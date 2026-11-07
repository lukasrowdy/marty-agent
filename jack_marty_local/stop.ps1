$ErrorActionPreference = 'Stop'
$pidFile = Join-Path $PSScriptRoot 'runtime\server.pid'
if (-not (Test-Path -LiteralPath $pidFile)) { Write-Output 'No recorded Jack/Marty process.'; exit 0 }
$taskProcessId = [int](Get-Content -LiteralPath $pidFile)
$taskProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$taskProcessId"
$expectedScript = Join-Path $PSScriptRoot 'local_console.py'
if ($taskProcess -and $taskProcess.CommandLine.Contains($expectedScript)) {
    $session = Invoke-RestMethod 'http://127.0.0.1:8766/api/session'
    Invoke-RestMethod 'http://127.0.0.1:8766/api/shutdown' -Method Post -ContentType 'application/json' -Headers @{'X-Local-Token'=$session.token} -Body '{"action":"stop-console"}' | Out-Null
    Wait-Process -Id $taskProcessId -Timeout 10 -ErrorAction SilentlyContinue
    if (Get-Process -Id $taskProcessId -ErrorAction SilentlyContinue) { throw 'Console has not stopped; its process was left intact.' }
    Write-Output 'Stopped the isolated Jack/Marty console.'
} elseif ($taskProcess) { throw 'PID is now owned by a different program; refusing to stop it.' }
Remove-Item -LiteralPath $pidFile
