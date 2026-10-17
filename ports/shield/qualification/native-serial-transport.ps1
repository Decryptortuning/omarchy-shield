param(
  [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{32}$')][string]$SerialToken,
  [ValidateRange(45,660)][int]$DurationSeconds=660
)
# Transport only. MAC keys stay in the WSL controller. Opening this port or
# receiving a line never establishes authentication, readiness or write scope.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
Set-StrictMode -Version Latest

Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.IO.Ports;
using System.Text;
using System.Threading;
using System.Diagnostics;

// This independent thread owns the current process handle. No PID lookup or
// device string selects a target. It also bounds a blocked SerialPort.Close.
public sealed class ShieldNativeBridgeDeadline : IDisposable {
  readonly ManualResetEvent done = new ManualResetEvent(false);
  readonly Thread thread;
  public ShieldNativeBridgeDeadline(int seconds) {
    if (seconds < 45 || seconds > 660) throw new ArgumentOutOfRangeException();
    thread = new Thread(() => {
      if (!done.WaitOne(seconds * 1000)) {
        using (var owned = Process.GetCurrentProcess()) { owned.Kill(); }
      }
    });
    thread.IsBackground = true;
    thread.Start();
  }
  public void Dispose() {
    done.Set();
    if (thread.Join(1000)) done.Dispose();
    // Unknown thread completion never becomes permission to keep running.
    else { using (var owned = Process.GetCurrentProcess()) { owned.Kill(); } }
  }
}

public sealed class ShieldNativeBridgeWake : IDisposable {
  readonly AutoResetEvent data = new AutoResetEvent(false);
  readonly AutoResetEvent input = new AutoResetEvent(false);
  readonly ConcurrentQueue<string> lines = new ConcurrentQueue<string>();
  readonly SerialPort port;
  volatile bool disposed;
  volatile bool ended;
  volatile string error;
  public bool Ended { get { return ended; } }
  public string Error { get { return error; } }
  void Signal(AutoResetEvent handle) {
    try { handle.Set(); } catch (ObjectDisposedException) { }
  }
  void Data(object sender, SerialDataReceivedEventArgs args) { Signal(data); }
  void ErrorReceived(object sender, SerialErrorReceivedEventArgs args) { Signal(data); }
  public ShieldNativeBridgeWake(SerialPort serial) {
    port = serial;
    port.DataReceived += Data;
    port.ErrorReceived += ErrorReceived;
    // Console.In.ReadLineAsync can have a synchronous implementation. Keep
    // bounded input parsing on one background thread, never on the port loop.
    var thread = new Thread(ReadInput);
    thread.IsBackground = true;
    thread.Start();
  }
  void ReadInput() {
    var line = new StringBuilder();
    bool cr = false;
    try {
      while (!disposed) {
        int value = Console.In.Read();
        if (value < 0) {
          if (line.Length != 0 || cr) error = "partial-input";
          break;
        }
        if (value == 10) {
          if (lines.Count >= 8) { error = "input-queue-limit"; break; }
          lines.Enqueue(line.ToString()); line.Clear(); cr = false;
          Signal(input); continue;
        }
        if (cr || (value != 13 && (value < 32 || value > 126))) {
          error = "non-ascii-input"; break;
        }
        if (value == 13) { cr = true; continue; }
        if (line.Length >= 65536) { error = "input-line-limit"; break; }
        line.Append((char)value);
      }
    } catch { error = "input-read-failed"; }
    finally { ended = true; Signal(input); }
  }
  public string TakeLine() {
    string line;
    return lines.TryDequeue(out line) ? line : null;
  }
  public void Wait(int milliseconds) {
    WaitHandle.WaitAny(new WaitHandle[] { data, input }, milliseconds);
  }
  public void Dispose() {
    disposed = true;
    port.DataReceived -= Data;
    port.ErrorReceived -= ErrorReceived;
    data.Dispose(); input.Dispose();
    // The sole input thread is background-only. Do not synchronously close a
    // TextReader whose blocking Read owns its lock. Process exit closes it.
  }
}
'@

$expectedParent='^USB\\VID_0525&PID_A4A7\\OMARCHY-A04-'+$SerialToken.ToUpperInvariant()+'$'
function Find-NativePort {
  $ports=@()
  foreach ($candidate in @(Get-CimInstance Win32_SerialPort)) {
    if ($candidate.PNPDeviceID -notmatch '^USB\\VID_0525&PID_A4A7&MI_[0-9A-F]+\\' -or $candidate.DeviceID -notmatch '^COM[0-9]+$') { continue }
    $parent=[string]$candidate.PNPDeviceID
    for ($depth=0;$depth -lt 8;$depth++) {
      if ($parent.ToUpperInvariant() -match $expectedParent) { $ports+=([string]$candidate.DeviceID);break }
      $property=Get-PnpDeviceProperty -InstanceId $parent -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue
      if ($null -eq $property -or [string]::IsNullOrEmpty([string]$property.Data)) { break }
      $parent=[string]$property.Data
    }
  }
  if ($ports.Count -gt 1) { throw 'Multiple matching native ports.' }
  return $ports
}

$stdout=[Console]::OpenStandardOutput()
$stderr=[Console]::OpenStandardError()
function Emit-BridgeMarker([string]$marker) {
  $bytes=[Text.Encoding]::ASCII.GetBytes('SHIELD_NATIVE_BRIDGE_'+$marker+"`n")
  # Device bytes have their own stdout pipe. A device-supplied line must never
  # be interpreted as a local process/port lifecycle observation by the caller.
  $stderr.Write($bytes,0,$bytes.Length);$stderr.Flush()
}
$arrival='ShieldNativeArrival_'+[Guid]::NewGuid().ToString('N')
$registered=$false;$serial=$null;$wake=$null;$status=1
$hardDeadline=[ShieldNativeBridgeDeadline]::new($DurationSeconds)
$clock=[Diagnostics.Stopwatch]::StartNew()
try {
  # Creating this object does not open a port. Input cancellation is available
  # while waiting for arrival; PortName is assigned only after exact discovery.
  $serial=[IO.Ports.SerialPort]::new()
  $wake=[ShieldNativeBridgeWake]::new($serial)
  if (@(Find-NativePort).Count -ne 0) { throw 'Existing matching port; never replay an attempt.' }
  Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_SerialPort'" -SourceIdentifier $arrival | Out-Null
  $registered=$true
  Emit-BridgeMarker ('ARMED '+$PID)
  $ports=@(Find-NativePort)
  $stopped=$false
  while ($ports.Count -eq 0 -and $clock.Elapsed.TotalSeconds -lt $DurationSeconds -and -not $stopped) {
    if ($null -ne $wake.Error) { throw 'Invalid bridge input.' }
    $line=$wake.TakeLine()
    if ($null -ne $line) {
      if ($line -ceq 'STOP') { $stopped=$true;break }
      throw 'Frames cannot be sent before exact port discovery.'
    }
    if ($wake.Ended) { throw 'Controller input closed without STOP.' }
    $event=Wait-Event -SourceIdentifier $arrival -Timeout 1
    if ($null -ne $event) { Remove-Event -EventIdentifier $event.EventIdentifier;$ports=@(Find-NativePort) }
  }
  if (-not $stopped) {
    if ($ports.Count -ne 1) { throw 'Native port arrival deadline.' }
    $serial.PortName=$ports[0]
    $serial.BaudRate=115200;$serial.Parity=[IO.Ports.Parity]::None
    $serial.DataBits=8;$serial.StopBits=[IO.Ports.StopBits]::One
    $serial.Handshake=[IO.Ports.Handshake]::None
    $serial.DtrEnable=$true;$serial.RtsEnable=$false
    $serial.ReadTimeout=500;$serial.WriteTimeout=500
    $serial.Encoding=[Text.Encoding]::ASCII
    $serial.Open()
    Emit-BridgeMarker 'CONNECTED'
    $buffer=[byte[]]::new(8192)
    [long]$receivedBytes=0;[long]$sentBytes=0
    while ($clock.Elapsed.TotalSeconds -lt $DurationSeconds -and -not $stopped) {
      if ($null -ne $wake.Error) { throw 'Invalid bridge input.' }
      while ($true) {
        $line=$wake.TakeLine()
        if ($null -eq $line) { break }
        if ($line -ceq 'STOP') { $stopped=$true;break }
        if ($line.Length -ge 65536 -or $line -cnotmatch '^SNCP1 [A-Za-z0-9+/]+={0,2} [0-9a-f]{64}$') { throw 'Invalid frame transport syntax.' }
        $sentBytes+=$line.Length+1
        if ($sentBytes -gt 33554432 -or $clock.Elapsed.TotalSeconds -ge $DurationSeconds) { throw 'Input transport budget.' }
        # Syntax only. The native peer, not this bridge, checks the MAC and schema.
        $serial.Write($line+"`n")
      }
      if ($stopped) { break }
      if ($wake.Ended) { throw 'Controller input closed without STOP.' }
      while ($serial.BytesToRead -gt 0) {
        if ($clock.Elapsed.TotalSeconds -ge $DurationSeconds) { throw 'Output transport deadline.' }
        $count=$serial.Read($buffer,0,[Math]::Min($buffer.Length,$serial.BytesToRead))
        if ($count -le 0) { throw 'Empty native read.' }
        $receivedBytes+=$count
        if ($receivedBytes -gt 33554432) { throw 'Output transport byte budget.' }
        $stdout.Write($buffer,0,$count);$stdout.Flush()
      }
      $remaining=[Math]::Ceiling(($DurationSeconds-$clock.Elapsed.TotalSeconds)*1000)
      if ($remaining -le 0) { break }
      # Events drive input/data. The bounded wake also observes a silent USB
      # disconnect (SerialPort does not guarantee an unplug event) and deadline.
      $wake.Wait([int][Math]::Min(1000,$remaining))
    }
    if (-not $stopped) { throw 'Bridge deadline without controller STOP.' }
  }
  $status=0
} catch {
  # Never print keys, frames, exception paths or arbitrary device strings.
  Emit-BridgeMarker 'FAILED'
} finally {
  if ($null -ne $wake) { $wake.Dispose() }
  if ($null -ne $serial) { if ($serial.IsOpen) { $serial.Close() };$serial.Dispose() }
  if ($registered) { Unregister-Event -SourceIdentifier $arrival;Get-Event -SourceIdentifier $arrival -ErrorAction SilentlyContinue | Remove-Event }
  if ($status -eq 0) { Emit-BridgeMarker 'STOPPED' }
  $hardDeadline.Dispose()
}
exit $status
