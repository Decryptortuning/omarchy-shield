# Read-only stock-device/bootloader inventory. No reboot, unlock or flash steps.
param(
  [string]$PlatformTools = "$env:LOCALAPPDATA\Android\Sdk\platform-tools",
  [ValidatePattern('^[A-Za-z0-9._:-]*$')][string]$Serial = '',
  [string]$OutputPath = ''
)
$ErrorActionPreference = 'Stop'
if (-not $OutputPath) {
  $OutputPath = Join-Path $PSScriptRoot 'build\hardware-report-stock.json'
}

function Read-Native([string]$Executable, [string[]]$NativeArguments) {
  # Every argument is a fixed token or the validated serial, never shell text.
  foreach ($token in $NativeArguments) {
    if ($token -match '[\s"\x00]') { throw 'Unexpected process argument' }
  }
  $start = New-Object Diagnostics.ProcessStartInfo
  $start.FileName = $Executable
  $start.Arguments = [string]::Join(' ', $NativeArguments)
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $process = New-Object Diagnostics.Process
  $process.StartInfo = $start
  try {
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(10000)) {
      $process.Kill()
      $process.WaitForExit()
      return [ordered]@{ exit_code = $null; timed_out = $true; stdout = ''; stderr = 'Read timed out' }
    }
    return [ordered]@{
      exit_code = $process.ExitCode
      timed_out = $false
      stdout = $stdout.Result.Trim()
      stderr = $stderr.Result.Trim()
    }
  } finally {
    $process.Dispose()
  }
}

$adb = Join-Path $PlatformTools 'adb.exe'
$fastboot = Join-Path $PlatformTools 'fastboot.exe'
if (-not (Test-Path -LiteralPath $adb -PathType Leaf) -or
    -not (Test-Path -LiteralPath $fastboot -PathType Leaf)) {
  throw "Install Android platform-tools first: $PlatformTools"
}
$report = [ordered]@{
  captured_at_utc = [DateTime]::UtcNow.ToString('o')
  state = 'no-device'
  identity_confirmed = $false
  adb_devices = Read-Native $adb @('devices', '-l')
  fastboot_devices = Read-Native $fastboot @('devices')
  device_mutations = @()
}
$adbSelector = @('-d')
if ($Serial) { $adbSelector = @('-s', $Serial) }
$state = Read-Native $adb ($adbSelector + @('get-state'))
if ($state.exit_code -eq 0 -and $state.stdout -eq 'device') {
  $identity = Read-Native $adb ($adbSelector + @('shell', 'getprop', 'ro.product.device'))
  $report.identity = $identity
  $manufacturer = Read-Native $adb ($adbSelector + @('shell', 'getprop', 'ro.product.manufacturer'))
  $model = Read-Native $adb ($adbSelector + @('shell', 'getprop', 'ro.product.model'))
  $chip = Read-Native $adb ($adbSelector + @('shell', 'cat', '/sys/module/tegra_fuse/parameters/tegra_chip_id'))
  $major = Read-Native $adb ($adbSelector + @('shell', 'cat', '/sys/module/tegra_fuse/parameters/tegra_chip_major_rev'))
  $report.soc_identity = [ordered]@{ manufacturer = $manufacturer; model = $model; chip_id = $chip; major_revision = $major }
  $family = ''
  if ($manufacturer.stdout -eq 'NVIDIA' -and $model.stdout -match '^SHIELD' -and
      $identity.stdout -in @('darcy', 'mdarcy') -and
      $chip.exit_code -eq 0 -and $chip.stdout -eq '33' -and $major.exit_code -eq 0) {
    if ($major.stdout -eq '1' -and $identity.stdout -eq 'darcy') { $family = 'darcy-t210' }
    if ($major.stdout -eq '2') { $family = 'mdarcy-t210b01' }
  }
  if ($family) {
    $report.state = 'stock-adb'
    $report.identity_confirmed = $true
    $report.board_family = $family
    # Android identity/fuses do not identify an A04/A08/B00 revision.
    $report.board_variant = $null
    $report.board_sku_confirmed = $false
    $report.boot_image_compatibility_confirmed = $false
    $report.properties = [ordered]@{}
    foreach ($name in @('ro.product.device', 'ro.product.model', 'ro.board.platform',
      'ro.bootloader', 'ro.boot.hardware.sku', 'ro.boot.boardid', 'ro.boot.sku',
      'ro.boot.boardrev', 'ro.boot.flash.locked', 'ro.boot.verifiedbootstate',
      'ro.build.fingerprint', 'ro.build.version.incremental', 'ro.build.version.security_patch')) {
      $report.properties[$name] = Read-Native $adb ($adbSelector + @('shell', 'getprop', $name))
    }
    $report.files = [ordered]@{}
    foreach ($path in @('/proc/cmdline', '/proc/meminfo', '/proc/partitions',
      '/proc/device-tree/model', '/proc/device-tree/compatible')) {
      $report.files[$path] = Read-Native $adb ($adbSelector + @('shell', 'cat', $path))
    }
    $report.partition_names = Read-Native $adb ($adbSelector + @('shell', 'ls', '-l', '/dev/block/by-name'))
    $report.firmware_names = Read-Native $adb ($adbSelector + @('shell', 'find', '/vendor/firmware', '/vendor/etc/firmware', '/system/etc/firmware', '-maxdepth', '3', '-type', 'f'))
  } else {
    $report.state = 'other-adb-device-refused'
  }
} else {
  $report.adb_state = $state
  $devices = @($report.fastboot_devices.stdout -split '\r?\n' | Where-Object { $_ -match '\s+fastboot$' })
  if ($Serial -or $devices.Count -eq 1) {
    $fastbootSelector = @()
    if ($Serial) { $fastbootSelector = @('-s', $Serial) }
    if ($devices.Count -gt 0) {
      $report.state = 'fastboot-identity-needs-review'
      $report.bootloader_variables = [ordered]@{}
      foreach ($name in @('product', 'variant', 'version-bootloader', 'secure', 'unlocked',
        'hw-revision', 'partition-type:boot', 'partition-size:boot', 'partition-size:recovery', 'has-slot:boot')) {
        $value = Read-Native $fastboot ($fastbootSelector + @('getvar', $name))
        $value.available = $value.exit_code -eq 0 -and -not $value.timed_out -and
          ($value.stdout + $value.stderr) -notmatch 'Unknown var!|No partition present|FAILED'
        $report.bootloader_variables[$name] = $value
      }
    }
  } elseif ($devices.Count -gt 1) {
    $report.state = 'multiple-fastboot-devices-select-serial'
  }
}
$report.limitations = @(
  'Android product names and fastboot t210ref alone do not establish the Tegra generation or board SKU.',
  'Original Tegra210 and Tegra210B01 require separate matching device trees and firmware; never infer one from darcy alone.',
  'This inventory does not back up partitions or validate firmware payload compatibility.',
  'Review generated reports before publication; they can contain device identifiers.'
)
$fullPath = [IO.Path]::GetFullPath($OutputPath)
[void][IO.Directory]::CreateDirectory((Split-Path -Parent $fullPath))
[IO.File]::WriteAllText($fullPath, ($report | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
Write-Output "Read-only USB inventory: $($report.state); report: $fullPath"
