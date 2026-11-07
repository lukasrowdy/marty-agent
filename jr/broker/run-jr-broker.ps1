# run-jr-broker.ps1 (new, helper item 4 "deploy", 2026-09-28). The Jr Broker supervisor.
#
# 2026-09-28 evening (fix helper, skeptic finding 1 and Marty's 6:22 PM update from item 1): the child
# command line now matches jr_broker_main.py's real parser (config is POSITIONAL, :627 read 6:23 PM;
# the old --config made argparse exit 2 on every launch and the supervisor looped on it), the
# supervisor passes --parent-pid $PID so the broker exits when Task Scheduler kills this script
# (TerminateProcess runs no finally block), exit 2 is "refused, do not restart" and exits quietly
# like 3, and exits 4 and 5 restart with backoff but write a FAULT line into the status JSON.
#
# Started by the "Jr Broker" scheduled task (Interactive, Limited, at logon plus every 5 min).
# One instance at a time (named mutex). Runs the broker as a child:
#     py -3.14 -B jr_broker_main.py <Config> --parent-pid <this pid>
# and applies these rules, copied from run-marty-services.ps1 with these deliberate changes:
#   * PINNED PYTHON. Only the 3.14 launcher lane is used (py -3.14), and the supervisor
#     proves it answers as 3.14 before the first start. The service runtime and the .deps
#     pywin32 312 binaries are cp314; a different Python would import nothing.
#   * KILLS ITS CHILD. The original supervisor detaches children and never forwards a stop.
#     Here the finally block taskkills the recorded child pid so a stopped task never leaves
#     a real broker alive next to a fake-VM broker during QA. WITHOUT /T (2026-09-28 late
#     evening, fix helper, skeptic item 9c): a tree kill would also take the heartbeat
#     watchdog (jr_broker_watchdog.py, spawned by the broker and meant to outlive it) and the
#     per-batch network watchdog child; both cut the cable on their own once the broker is
#     gone, which is the point of them. Because a Stop-ScheduledTask never reaches that
#     finally block, the broker also watches --parent-pid and exits on its own when this
#     supervisor is gone.
#   * BROKER EXIT CODES (jr_broker_main.py:96-100):
#       0  clean stop            -> restart with backoff (the task expects a running broker)
#       1  crash                 -> restart with backoff
#       2  refused (lock held, bad config, fake-mode refusal, dead parent) -> DO NOT restart:
#          log one line, status 'refused', exit 0 quietly; the 5-minute trigger tries again
#       3  VM not running        -> not a crash: one line, status 'idle', exit 0 quietly
#       4  cable cut unverified  -> restart with backoff, and a FAULT line in the status JSON
#       5  isolation failed      -> restart with backoff, and a FAULT line in the status JSON
#   * BACKOFF AND CAP. Restarts wait 30/60/120/240 s (capped at 300 s); more than
#     MaxStartsPer10Min starts inside 10 minutes puts the broker on a HoldMinutes hold.
#   * STATUS FILE. <LogDir>\jr-broker.status.json rewritten every 5 s while the child runs.
#     register_jr_broker_task.ps1 -Unregister reads child_pid from it to kill the broker.
#
# -WhatIf prints the exact child command line, the log paths and the policy, and exits
# without starting anything. There is no -Apply: the task runs this script for real by
# design; helpers only ever run it with -WhatIf.

param(
    [string]$Config = '',
    [string]$BrokerDir = '',
    [string]$BrokerScript = 'jr_broker_main.py',
    [string]$LogDir = '',
    [string]$PyLauncher = 'py',
    [string]$PyVersion = '3.14',
    [int]$MaxStartsPer10Min = 5,
    [int]$HoldMinutes = 5,
    [int]$MaxRuntimeSec = 0,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $BrokerDir) { $BrokerDir = $here }
if (-not $LogDir) { $LogDir = Join-Path $BrokerDir 'logs' }
$script = Join-Path $BrokerDir $BrokerScript
$logFile = Join-Path $LogDir 'jr-broker-supervisor.log'
$statusFile = Join-Path $LogDir 'jr-broker.status.json'
$childOut = Join-Path $LogDir 'jr-broker.out.log'
$childErr = Join-Path $LogDir 'jr-broker.err.log'
$mutexName = 'Global\JrBrokerSupervisor'
$backoffs = @(30, 60, 120, 240)
# jr_broker_main.py CLI (item 1, confirmed 2026-09-28 6:22 PM): CONFIG positional, then --parent-pid N.
$childArgs = @(('-' + $PyVersion), '-B', ('"' + $script + '"'), ('"' + $Config + '"'), '--parent-pid', [string]$PID)
$commandLine = $PyLauncher + ' ' + ($childArgs -join ' ')
$faultText = @{ 4 = 'FAULT: broker exit 4: the startup cable cut could not be verified (poweroff was attempted); look at the VM in VirtualBox before anything else';
                5 = 'FAULT: broker exit 5: isolation check failed after the cut; the cable is off but the VM is not in the expected state; inspect before anything else' }

if ($WhatIf) {
    Write-Output 'run-jr-broker: DRY RUN (-WhatIf). Nothing started.'
    Write-Output ("WOULD: take the mutex {0} (exit 0 quietly if another supervisor holds it)" -f $mutexName)
    Write-Output ("WOULD: prove the launcher answers as Python {0}: {1} -{0} -c ""import sys;print(sys.version_info[:2])""" -f $PyVersion, $PyLauncher)
    Write-Output ("WOULD: require the broker script to exist: {0}" -f $script)
    Write-Output ("WOULD: require -Config to be given and to exist: '{0}'" -f $Config)
    Write-Output ("WOULD: Start-Process (hidden, stdout/stderr redirected) with this exact command line (config positional, then --parent-pid <this supervisor's pid> so the broker exits when the supervisor is killed):")
    Write-Output ("       {0}" -f $commandLine)
    Write-Output ("WOULD: log to {0}; child output to {1} and {2}; status JSON to {3}" -f $logFile, $childOut, $childErr, $statusFile)
    Write-Output ("WOULD: on child exit code 3 (VM not running): log 'VM not running; exiting quietly' and exit 0 (the task trigger retries in 5 min)")
    Write-Output ("WOULD: on child exit code 2 (refused: lock held, bad config, fake-mode refusal, dead parent): log 'REFUSED', status 'refused' with the reason file, do NOT restart, exit 0 quietly (the task trigger retries in 5 min; a bad config stays refused until fixed)")
    Write-Output ("WOULD: on child exit code 4 (cable cut unverified) or exit code 5 (isolation failed): write a FAULT line into the status JSON, then restart with backoff like a crash")
    Write-Output ("WOULD: on any other exit (0, 1, unknown): restart after {0} s (capped 300), at most {1} starts per 10 minutes, then hold {2} minutes" -f ($backoffs -join '/'), $MaxStartsPer10Min, $HoldMinutes)
    Write-Output ("WOULD: finally: taskkill /F /PID <child> (no /T: the heartbeat watchdog and the network watchdog child must outlive the broker) if it is still alive when this supervisor stops (a Stop-ScheduledTask skips this; the broker's --parent-pid watch covers that case)")
    exit 0
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Write-Log($message) {
    $line = "{0} - {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $message
    try {
        if ((Test-Path $logFile) -and ((Get-Item $logFile).Length -gt 1MB)) { Move-Item -Force $logFile ($logFile + '.1') }
        Add-Content -Path $logFile -Value $line -Encoding UTF8
    } catch { }
}

function Write-Status($state, $detail, $childPid, $starts) {
    $doc = [ordered]@{ checked = (Get-Date).ToString('s'); supervisor_pid = $PID; state = $state; detail = $detail;
                       child_pid = $childPid; starts_last_10m = $starts; command = $commandLine }
    try {
        $tmp = $statusFile + '.tmp'
        [System.IO.File]::WriteAllText($tmp, ($doc | ConvertTo-Json -Depth 3), (New-Object System.Text.UTF8Encoding $false))
        Move-Item -Force $tmp $statusFile
    } catch { }
}

$mutex = New-Object System.Threading.Mutex($false, $mutexName)
if (-not $mutex.WaitOne(0)) { exit 0 }

Write-Log ("supervisor started (pid {0})" -f $PID)
$child = $null
$began = Get-Date
try {
    if (-not $Config -or -not (Test-Path -LiteralPath $Config -PathType Leaf)) {
        Write-Log ("REFUSED: -Config missing or not a file: '{0}'" -f $Config); Write-Status 'refused' 'config missing' $null 0; exit 2
    }
    if (-not (Test-Path -LiteralPath $script -PathType Leaf)) {
        Write-Log ("REFUSED: broker script missing: {0}" -f $script); Write-Status 'refused' 'broker script missing' $null 0; exit 2
    }
    # 2026-09-29 Gate 1 fix: no inner double quotes here. PowerShell 5.1 strips them when it hands the
    # argument to py.exe, so Python saw print(%d.%d % ...) and the supervisor refused a good 3.14 lane.
    $probe = & $PyLauncher ('-' + $PyVersion) -c 'import sys;print(sys.version_info[0],sys.version_info[1],sep=chr(46))' 2>&1
    if (($LASTEXITCODE -ne 0) -or (($probe | Out-String).Trim() -ne $PyVersion)) {
        Write-Log ("REFUSED: '{0} -{1}' did not answer as Python {1}: {2}" -f $PyLauncher, $PyVersion, (($probe | Out-String).Trim()))
        Write-Status 'refused' 'python launcher lane wrong' $null 0; exit 2
    }
    $starts = @()
    while ($true) {
        $now = Get-Date
        $starts = @($starts | Where-Object { ($now - $_).TotalMinutes -lt 10 })
        if ($starts.Count -ge $MaxStartsPer10Min) {
            Write-Log ("{0} starts in 10 minutes; holding {1} minutes" -f $starts.Count, $HoldMinutes)
            Write-Status 'held' ("crash loop; holding until {0:HH:mm:ss}" -f $now.AddMinutes($HoldMinutes)) $null $starts.Count
            Start-Sleep -Seconds ($HoldMinutes * 60)
            $starts = @()
            continue
        }
        if ($starts.Count -gt 0) {
            $wait = [Math]::Min(300, $backoffs[[Math]::Min($starts.Count - 1, $backoffs.Count - 1)])
            Write-Log ("restart backoff {0} s" -f $wait)
            Write-Status 'down' ("restart in {0} s" -f $wait) $null $starts.Count
            Start-Sleep -Seconds $wait
        }
        foreach ($f in @($childOut, $childErr)) {
            if ((Test-Path $f) -and ((Get-Item $f).Length -gt 0)) { try { Move-Item -Force -ErrorAction Stop $f ($f + '.1') } catch { } }
        }
        $starts += Get-Date
        $child = Start-Process -FilePath $PyLauncher -ArgumentList $childArgs -WorkingDirectory $BrokerDir -WindowStyle Hidden -PassThru `
                 -RedirectStandardOutput $childOut -RedirectStandardError $childErr
        $null = $child.Handle
        Write-Log ("started broker (pid {0}): {1}" -f $child.Id, $commandLine)
        while (-not $child.HasExited) {
            Write-Status 'running' '' $child.Id $starts.Count
            if ($MaxRuntimeSec -gt 0 -and ((Get-Date) - $began).TotalSeconds -ge $MaxRuntimeSec) { break }
            Start-Sleep -Seconds 5
        }
        if (-not $child.HasExited) { Write-Log 'max runtime reached; stopping'; break }
        $code = $child.ExitCode
        if ($code -eq 3) {
            Write-Log 'broker exit 3: VM not running; exiting quietly (the task trigger retries in 5 min)'
            Write-Status 'idle' 'VM not running' $null $starts.Count
            $child = $null
            exit 0
        }
        if ($code -eq 2) {
            Write-Log ("broker exit 2: REFUSED (lock held, bad config, fake-mode refusal or dead parent); not restarting; read {0}" -f $childErr)
            Write-Status 'refused' ("broker refused to start (exit 2); see " + $childErr) $null $starts.Count
            $child = $null
            exit 0
        }
        if ($faultText.ContainsKey([int]$code)) {
            Write-Log $faultText[[int]$code]
            Write-Status 'down' $faultText[[int]$code] $null $starts.Count
            Start-Sleep -Seconds 1
        } else {
            Write-Log ("broker exited with code {0}; will restart" -f $code)
            Write-Status 'down' ("exit code {0}" -f $code) $null $starts.Count
        }
        $child = $null
    }
} finally {
    if ($child -and -not $child.HasExited) {
        Write-Log ("stopping broker child pid {0} (taskkill /F, no /T: the watchdogs outlive it)" -f $child.Id)
        $out = & taskkill.exe /F /PID $child.Id 2>&1
        if ($LASTEXITCODE -ne 0) { Write-Log ("could not stop child: {0}" -f (($out | Out-String).Trim())) }
    }
    Write-Log ("supervisor stopping (pid {0})" -f $PID)
    try { $mutex.ReleaseMutex() } catch { }
}
