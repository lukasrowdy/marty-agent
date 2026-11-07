$ErrorActionPreference = 'Stop'
$taskRoot = $PSScriptRoot
$pythonCandidates = @(
    "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
    "$env:USERPROFILE\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
)
$taskPython = $pythonCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $taskPython) { throw 'Python 3.12 is required; no configured interpreter was found.' }
$existing = Get-NetTCPConnection -LocalPort 8766 -State Listen -ErrorAction SilentlyContinue
if ($existing) {
    $health = Invoke-RestMethod 'http://127.0.0.1:8766/health'
    if ($health.service -ne 'jack-marty-local') { throw 'Port 8766 belongs to another service.' }
    Write-Output 'Jack/Marty is already running at http://127.0.0.1:8766/'
    exit 0
}
$runtime = Join-Path $taskRoot 'runtime'
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
$scriptPath = Join-Path $taskRoot 'local_console.py'
$taskProcess = Start-Process -FilePath $taskPython -ArgumentList @('-u', ('"' + $scriptPath + '"')) -WorkingDirectory $taskRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtime 'server.log') -RedirectStandardError (Join-Path $runtime 'server-error.log')
$taskProcess.Id | Set-Content -LiteralPath (Join-Path $runtime 'server.pid')
Start-Sleep -Milliseconds 700
$health = Invoke-RestMethod 'http://127.0.0.1:8766/health'
Write-Output ('Jack/Marty is running at http://127.0.0.1:8766/ (PID ' + $taskProcess.Id + ')')
