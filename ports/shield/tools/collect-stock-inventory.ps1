param(
  [string]$OutputDirectory,
  [ValidateRange(1, 90)][int]$TimeoutSeconds = 75
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-InventoryLine {
  param([System.IO.Stream]$Stream, [System.Diagnostics.Stopwatch]$Clock, [int]$Seconds)
  $line = [System.Text.StringBuilder]::new()
  while ($Clock.Elapsed.TotalSeconds -lt $Seconds) {
    try { $value = $Stream.ReadByte() } catch {
      if ($_.Exception -is [System.TimeoutException] -or $_.Exception.InnerException -is [System.TimeoutException]) { continue }
      throw
    }
    if ($value -lt 0) { throw 'Inventory stream ended early' }
    if ($value -eq 10) { return $line.ToString().TrimEnd([char]13) }
    if ($line.Length -ge 4096) { throw 'Inventory preface line exceeds limit' }
    [void]$line.Append([char]$value)
  }
  throw 'Inventory stream timed out'
}

function Receive-InventoryArchive {
  param([System.IO.Stream]$Stream, [string]$Begin, [string]$End, [string]$Path, [int]$Seconds)
  $clock = [System.Diagnostics.Stopwatch]::StartNew()
  $size = 0L
  for ($i = 0; $i -lt 64; $i++) {
    $line = Read-InventoryLine $Stream $clock $Seconds
    if ($line -match ('^' + [regex]::Escape($Begin) + ' ([0-9]+)$')) {
      $size = [long]$Matches[1]
      break
    }
  }
  if ($size -lt 1024 -or $size -gt 134217728 -or $size % 512 -ne 0) { throw 'Invalid inventory archive size' }
  $file = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
  try {
    $buffer = [byte[]]::new(65536)
    $remaining = $size
    while ($remaining -gt 0) {
      if ($clock.Elapsed.TotalSeconds -ge $Seconds) { throw 'Inventory transfer timed out' }
      try { $read = $Stream.Read($buffer, 0, [int][Math]::Min($buffer.Length, $remaining)) } catch {
        if ($_.Exception -is [System.TimeoutException] -or $_.Exception.InnerException -is [System.TimeoutException]) { continue }
        throw
      }
      if ($read -le 0) { throw 'Truncated inventory archive' }
      $file.Write($buffer, 0, $read)
      $remaining -= $read
    }
    do { $line = Read-InventoryLine $Stream $clock $Seconds } while ($line -eq '')
    if ($line -ne $End) { throw 'Inventory end marker mismatch' }
  } finally { $file.Dispose() }
  return $size
}

function Get-StockInventoryPort {
  $ports = @(Get-PnpDevice -Class Ports -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match 'VID_1D6B&PID_0104' })
  foreach ($device in $ports) {
    $instance = [string]$device.InstanceId
    $owned = $false
    for ($depth = 0; $depth -lt 4; $depth++) {
      if ($instance -match '^USB\\VID_1D6B&PID_0104\\shield-stock-inventory$') { $owned = $true; break }
      $property = Get-PnpDeviceProperty -InstanceId $instance -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue
      if (-not $property) { break }
      $instance = [string]$property.Data
    }
    $match = [regex]::Match([string]$device.FriendlyName, '\((COM[0-9]+)\)')
    if ($owned -and $match.Success) { $match.Groups[1].Value }
  }
}

# Dot sourcing exposes only the parser for synthetic-stream tests.
if ($MyInvocation.InvocationName -eq '.') { return }
if (-not $OutputDirectory -or (Test-Path -LiteralPath $OutputDirectory)) { throw 'Supply a new private output directory' }
[void][System.IO.Directory]::CreateDirectory($OutputDirectory)
$clock = [System.Diagnostics.Stopwatch]::StartNew()
$portName = $null
while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
  $ports = @(Get-StockInventoryPort)
  if ($ports.Count -gt 1) { throw 'More than one stock inventory gadget is present' }
  if ($ports.Count -eq 1) { $portName = $ports[0]; break }
  Start-Sleep -Milliseconds 200
}
if (-not $portName) { throw 'No matching stock inventory USB serial gadget appeared' }
$serial = [System.IO.Ports.SerialPort]::new($portName, 115200)
$serial.ReadTimeout = 500
$serial.WriteTimeout = 2000
$serial.DtrEnable = $true
$serial.RtsEnable = $true
$nonce = [guid]::NewGuid().ToString('N').ToUpperInvariant()
$begin = 'OMARCHY_STOCK_BEGIN_' + $nonce
$end = 'OMARCHY_STOCK_END_' + $nonce
# Fixed command: read RAM evidence into a RAM tar, then transfer binary bytes.
$template = 'tar -C /run/shield-stock -cf /run/stock-inventory.tar .; printf ''\n{BEGIN} %s\n'' "$(stat -c %s /run/stock-inventory.tar)"; cat /run/stock-inventory.tar; printf ''\n{END}\n'''
$command = $template.Replace('{BEGIN}', $begin).Replace('{END}', $end) + "`n"
$partial = Join-Path $OutputDirectory 'inventory.tar.part'
try {
  $serial.Open()
  Start-Sleep -Milliseconds 300
  $bytes = [System.Text.Encoding]::ASCII.GetBytes($command)
  $serial.BaseStream.Write($bytes, 0, $bytes.Length)
  $length = Receive-InventoryArchive $serial.BaseStream $begin $end $partial $TimeoutSeconds
} finally { if ($serial.IsOpen) { $serial.Close() }; $serial.Dispose() }
$archive = Join-Path $OutputDirectory 'inventory.tar'
[System.IO.File]::Move($partial, $archive)
$receipt = [ordered]@{ bytes = $length; sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant(); archive_extracted = $false; persistent_device_write_requested = $false; kexec_requested = $false }
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'receipt.json') -Encoding UTF8
Write-Output 'Saved private inventory.tar and receipt.json. The archive was not extracted or published.'
