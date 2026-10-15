param([Parameter(Mandatory)][string]$Collector, [Parameter(Mandatory)][string]$WorkDirectory)
$ErrorActionPreference = 'Stop'
. $Collector
[void][System.IO.Directory]::CreateDirectory($WorkDirectory)
$body = [byte[]]::new(1536)
for ($i = 0; $i -lt $body.Length; $i++) { $body[$i] = [byte]($i % 256) }
$start = [System.Text.Encoding]::ASCII.GetBytes("banner`nBEGIN 1536`n")
$end = [System.Text.Encoding]::ASCII.GetBytes("`nEND`n")
$bytes = [byte[]]($start + $body + $end)
$stream = [System.IO.MemoryStream]::new($bytes, $false)
$output = Join-Path $WorkDirectory 'valid.bin'
try { $length = Receive-InventoryArchive $stream 'BEGIN' 'END' $output 5 } finally { $stream.Dispose() }
if ($length -ne 1536 -or (Get-FileHash $output).Hash -ne ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($body)).Replace('-', ''))) { throw 'Binary framing altered bytes' }
$bad = [System.Text.Encoding]::ASCII.GetBytes("BEGIN 999999999`n")
$stream = [System.IO.MemoryStream]::new($bad, $false)
$rejected = $false
try { Receive-InventoryArchive $stream 'BEGIN' 'END' (Join-Path $WorkDirectory 'bad.bin') 5 } catch { $rejected = $true } finally { $stream.Dispose() }
if (-not $rejected -or (Test-Path (Join-Path $WorkDirectory 'bad.bin'))) { throw 'Oversized frame was accepted' }
$stream = [System.IO.MemoryStream]::new([byte[]]($start + $body[0..100]), $false)
$rejected = $false
try { Receive-InventoryArchive $stream 'BEGIN' 'END' (Join-Path $WorkDirectory 'truncated.bin') 5 } catch { $rejected = $true } finally { $stream.Dispose() }
if (-not $rejected) { throw 'Truncated frame was accepted' }
Write-Output 'PASS: binary bytes preserved; oversized and truncated frames rejected; no device opened'
