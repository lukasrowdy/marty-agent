# Marty Services supervisor.
#
# Keeps every long-running Marty service listening, and is safe to relaunch at
# any time. Replaced run-dashboard.ps1 on 2026-09-21 after the dashboard sat
# dead for ten minutes: the old wrapper ran server.py as a blocking child on its
# own console, so one console-close event (0xC000013A) took both, and the task's
# logon-only trigger never re-fired.
#
# Hardened 2026-09-23 (audit finding 11: "a listening port is treated as service
# health"). A port can be held by a hung server or by something that is not ours
# at all, and the old check passed both. Now, every pass:
#   * IDENTITY. The process that owns the port is looked up. If its command line
#     is not the one this supervisor launches, the port is reported as held by a
#     foreign process and left strictly alone: never killed, never fought over.
#   * READINESS. An owned service is probed over HTTP with a bounded timeout. Any
#     HTTP answer counts as alive (the dashboard answers 401 without a login).
#     No answer for HUNG_AFTER passes in a row means hung: that process, and only
#     that one because it is ours, is stopped and restarted.
#   * RESTART LIMITS. Starts are spaced out (30, 60, 120, 240 s) and more than
#     MAX_RESTARTS in 10 minutes puts the service on a 5-minute hold, so a crash
#     loop cannot spin.
#   * A STATUS FILE, logs/marty-services.status.json, rewritten every pass: per
#     service its state (healthy / starting / unresponsive / hung / foreign /
#     down / held), owning pid, HTTP code and recent starts. Ollama is
#     watched and reported but NOT restarted here: it has its own launcher.
#     Since 2026-09-24 Creator Hub is restarted here; the face and the voice line were retired 2026-10-07.
#     Jobs are not tracked yet (no job manager exists).
#   * The supervisor logs why it stops, when it can. A "supervisor started" line
#     with no "supervisor stopping" before it means it was killed from outside;
#     it relaunched six times between 9/22 18:44 and 9/23 04:29 with no reason
#     recorded anywhere, which is why this exists.
#
# Tightened 2026-09-29 (skeptic finding: "contains the script name" adopts any
# process whose command line merely mentions it, e.g. any other server.py on
# the same port). Each supervised service's .py script argument is resolved to
# its full path once, at table build time, and the child is launched with that
# full path instead of the bare name, so our own children always carry it.
# "Ours" now requires BOTH the owning process's exe (Win32_Process.ExecutablePath)
# to match the service's interpreter, AND its command line to contain that full
# script path (or, for module-launched/unsupervised entries, the old Expect
# string). A process hand-launched with a relative script name from its own
# folder (start-dashboard.bat, ai-visualizer\run.bat, start-channel.ps1) no
# longer matches; it is logged "foreign" and left alone rather than adopted.
#
# Round 2 (2026-09-29, skeptic review): the full-path arg is now quoted when it
# contains a space (a bare space-containing path passed to -ArgumentList gets
# split at the space and the child exits immediately); and the "ours" exe check
# resolves a venv's actual interpreter (its pyvenv.cfg "home =" line) instead of
# comparing against the venv's Scripts\python.exe redirector, which never shows
# up as ExecutablePath on the running process.
#
# Children get their own consoles (Start-Process -WindowStyle Hidden), so a
# console event on the supervisor cannot reach them. One instance at a time, by a
# named mutex as well as the task's IgnoreNew policy. The scheduled task "Marty
# Services" launches this at logon and on a 5-minute repeating trigger.
#
# Test mode: -ServicesFile <json> runs against a throwaway service list, with no
# mutex, a separate log and status file, and optional short timings.

param(
    [string]$ServicesFile = "",
    [string]$StatusFile   = "",
    [string]$LogFile      = "",
    [int]$PollSec     = 15,
    [int]$GraceSec    = 40,     # a fresh start gets this long to bind and answer
    [int]$ProbeSec    = 10,     # one HTTP readiness probe may take this long
    [int]$HungAfter   = 3,      # unanswered probes in a row before an owned child counts as hung
    [int]$MaxRestarts = 5,      # starts per service per 10 minutes before a 5-minute hold
    [int]$DurationSec = 0       # tests: stop after this long (0 = run forever)
)

$ErrorActionPreference = "Continue"
$root      = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)   # my-agent
$logDir    = Join-Path $root "logs"
if (-not $LogFile)    { $LogFile    = Join-Path $logDir "marty-services.log" }
if (-not $StatusFile) { $StatusFile = Join-Path $logDir "marty-services.status.json" }
$pythonExe = "C:\Users\{{WIN_USER}}\AppData\Local\Programs\Python\Python312\python.exe"
$testMode  = [bool]$ServicesFile

# Test-mode hygiene (2026-09-29 round 2): running the staged copy from its own
# subfolder makes $root resolve one level too shallow (the staged folder's
# parent, not my-agent), so this used to create a stray empty "logs" folder
# under dashboard on every test run. Test mode always supplies its own
# -LogFile/-StatusFile and its own out/err paths (Start-Service-Child below),
# so $logDir is never actually read from in test mode; skip creating it.
if (-not $testMode) {
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
}

function Write-Log($message) {
    $line = "{0} - {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $message
    try {
        if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 1MB)) {
            Move-Item -Force $LogFile ($LogFile + ".1")
        }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch { }
}

# Single instance (not in test mode, so a test can run beside the live supervisor).
if (-not $testMode) {
    $mutex = New-Object System.Threading.Mutex($false, "Global\MartyServicesSupervisor")
    if (-not $mutex.WaitOne(0)) {
        exit 0   # another supervisor is alive; the task's IgnoreNew should have caught this too
    }
}

if ($testMode) {
    # PowerShell 5.1 hands a JSON array down the pipeline as ONE object, so iterate it explicitly
    $raw = Get-Content -Raw -Path $ServicesFile | ConvertFrom-Json
    $services = @(foreach ($x in $raw) {
        @{ Name = $x.Name; Port = [int]$x.Port; Dir = $x.Dir; Args = @($x.Args); Expect = [string]$x.Expect;
           Probe = [string]$x.Probe; Supervised = [bool]$x.Supervised; Exe = [string]$x.Exe;
           Console = [bool]$x.Console; Grace = [int]$x.Grace; Pipe = [string]$x.Pipe; Heartbeat = [string]$x.Heartbeat }
    })
} else {
    $services = @(
        @{ Name = "dashboard"; Port = 8765;  Dir = (Join-Path $root "dashboard"); Exe = (Join-Path $root "dashboard\.venv\Scripts\python.exe"); Args = @("-u", "server.py");
           Expect = "-u server.py"; Probe = "http://127.0.0.1:8765/"; Supervised = $true },
        # Added 2026-09-24 on Lukas's yes ("Make it permanent", "Add them"): Creator Hub now comes back after
        # a reboot or a crash, instead of waiting for start.bat by hand.
        @{ Name = "creator-hub"; Port = 8792; Dir = "C:\Users\{{WIN_USER}}\Projects\13 - UGC Automation\creator-hub\server";
           Args = @("-u", "hub_server.py"); Expect = "hub_server.py"; Probe = "http://127.0.0.1:8792/api/state"; Supervised = $true },
        # "face" (ai-visualizer, 8790) and "voice" (backtalk, 8791) retired 2026-10-07 on Lukas's yes ("Yes
        # please."): Jarvis is the voice chat now. backtalk's folder and venv stay (Whisper for Talk, the
        # recorder and tools/media.py). Backup: run-marty-services.ps1.pre-voice-retire-20261007-0906.
        # Added 2026-09-28 (self-audit finding: "Channel under the supervisor"). Channel died
        # on 2026-09-27 because start-channel.ps1 was launched by hand from a chat session, so
        # it ran as that session's child and died with it. It needs Python 3.12 specifically
        # (the default `py` is 3.14, which lacks the `cryptography` package channel imports),
        # hence the explicit Exe below, matching start-channel.ps1. It serves HTTPS on a
        # self-signed cert (cert.pem/key.pem in its own folder), so — like "voice" above — no
        # plain-HTTP Probe is given: a failed TLS handshake must never read as "hung" and get
        # the process killed. It is restarted only when nothing listens on 8767.
        @{ Name = "channel"; Port = 8767; Dir = "C:\Users\{{WIN_USER}}\code\channel";
           Exe = "C:\Users\{{WIN_USER}}\AppData\Local\Programs\Python\Python312\python.exe"; Args = @("server.py");
           Expect = "server.py"; Probe = ""; Supervised = $true },
        # Added 2026-10-04 on Lukas's "Go on both": the Marty Jarvis dashboard (tailnet :10443 proxies to it).
        # It was hand-started, so the 10/3 8:34 PM reboot left :10443 on 502 for about 15 hours.
        @{ Name = "jarvis"; Port = 4719; Dir = "C:\Users\{{WIN_USER}}\Projects\Marty Jarvis\app";
           Exe = "C:\Users\{{WIN_USER}}\AppData\Local\Programs\Python\Python312\python.exe"; Args = @("server.py");
           Expect = "server.py"; Probe = "http://127.0.0.1:4719/health"; Supervised = $true },
        # Full Marty worker (Stage B, 2026-09-30): no TCP port; health = its own authenticated pipe probe.
        # Its venv's Scripts\python.exe is a redirector, so the running worker's ExecutablePath is the venv's
        # "home" Python312 (Resolve-Expected-Exe), and its command line carries the full script path.
        @{ Name = "full-marty"; Port = 0; Pipe = "marty-fullmarty";
           Dir = (Join-Path $root "dashboard\fullmarty");
           Exe = (Join-Path $root "dashboard\fullmarty\.venv\Scripts\python.exe");
           Args = @("-u", "full_marty_worker.py", "serve", "--profile", "production");
           Expect = "full_marty_worker.py"; Probe = ""; Supervised = $true; Grace = 60 },
        # mail-watch (2026-10-06, Lukas: "Yes, go ahead"): the school line on Marty's own Gmail. No port,
        # no pipe. Identity = Get-PipeOwner (exe + full script path + " serve"); health = Test-PipeProbe,
        # i.e. "mail_watch.py probe" (exit 0 = heartbeat under 180 s and loop tick under 15 min).
        # Python 3.14 explicitly: the default 3.12 lacks imapclient/google-auth. Heartbeat is a marker
        # field only; the branch below keys on it. the school line's cloud routine stays as backstop for a week.
        @{ Name = "mail-watch"; Port = 0; Heartbeat = "status\mail-watch\mail-watch.json";
           Dir = (Join-Path $root "tools\mail-watch");
           Exe = "C:\Users\{{WIN_USER}}\AppData\Local\Python\pythoncore-3.14-64\python.exe";
           Args = @("-u", "mail_watch.py", "serve");
           Expect = "mail_watch.py"; Probe = ""; Supervised = $true; Grace = 60 },
        # watched and reported only; it has its own launcher (the Startup-folder shortcut)
        @{ Name = "ollama"; Port = 11434; Expect = "ollama";   Probe = "http://127.0.0.1:11434/api/version"; Supervised = $false }
    )
}
function Resolve-Expected-Exe($s) {
    # Interpreter identity, tightened 2026-09-29 round 2 (skeptic finding: a venv's
    # Scripts\python.exe is only a redirector; the process that actually owns the
    # port reports ExecutablePath as the venv's "home" interpreter, e.g. dashboard
    # and voice both show Python312\python.exe, not their own .venv\Scripts copy).
    # Comparing ExecutablePath to $s.Exe directly would call our own children
    # foreign forever. Resolve once, here: if $s.Exe sits in a venv (a pyvenv.cfg
    # exists one level up from its folder), expect the "home = " interpreter from
    # that file instead. Face and channel run a plain interpreter with no venv, so
    # pyvenv.cfg is never found for them and they keep matching $s.Exe/$pythonExe
    # exactly, as before.
    if (-not $s.Exe) { return $pythonExe }
    $venvDir = Split-Path -Parent (Split-Path -Parent $s.Exe)
    $cfg = Join-Path $venvDir "pyvenv.cfg"
    if (Test-Path $cfg) {
        $homeLine = Get-Content -Path $cfg | Where-Object { $_ -match '^\s*home\s*=\s*(.+)$' } | Select-Object -First 1
        if ($homeLine -and ($homeLine -match '^\s*home\s*=\s*(.+)$')) {
            # NOTE: $HOME is a PowerShell automatic, read-only variable. A local
            # $home here silently fails to assign (non-terminating) and Join-Path
            # then reads the REAL $HOME (the user profile dir) instead, so this
            # must not be named $home. Caught by test-d in round 2.
            $venvHome = $Matches[1].Trim()
            return (Join-Path $venvHome "python.exe")
        }
    }
    return $s.Exe
}

foreach ($s in $services) {
    $s.Proc = $null; $s.StartedAt = $null; $s.Fails = 0; $s.Starts = @(); $s.HoldUntil = $null
    $s.State = "unknown"; $s.Detail = ""; $s.Owner = $null; $s.Http = $null; $s.LastLogged = ""

    # Ownership hardening (2026-09-29): resolve a .py script argument to its full path
    # once, here, and rewrite it in place so Start-Service-Child launches our own
    # children with the full path rather than a bare name relative to -WorkingDirectory.
    # A service launched by module (voice: -m backtalk.main) has no such argument and
    # keeps using its Expect string in the ownership check below.
    #
    # Round 2: Start-Process -ArgumentList joins elements with a single space and
    # does NOT quote one that contains a space (skeptic finding: creator-hub's dir
    # has "13 - UGC Automation" in it, so the bare full path reached python
    # truncated at that space and it exited, crash-looped, then held). Quote the
    # arg itself when it contains a space; keep ScriptFullPath unquoted, since
    # Contains() still finds the unquoted path as a substring of the quoted
    # command line either way.
    $s.ScriptFullPath = $null
    if ($s.Args -and $s.Dir) {
        for ($i = 0; $i -lt $s.Args.Count; $i++) {
            if ($s.Args[$i] -like "*.py") {
                $full = Join-Path $s.Dir $s.Args[$i]
                $s.ScriptFullPath = $full
                if ($full.Contains(" ")) { $s.Args[$i] = '"' + $full + '"' } else { $s.Args[$i] = $full }
                break
            }
        }
    }
    $s.ExpectedExe = Resolve-Expected-Exe $s
}

function Get-Owner($port) {
    $c = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $c) { return $null }
    $id = [int]$c.OwningProcess
    $w = Get-CimInstance Win32_Process -Filter "ProcessId=$id" -ErrorAction SilentlyContinue
    $name = "?"; $cmd = ""; $exePath = $null
    # ExecutablePath (2026-09-29): the interpreter that actually owns the port, used
    # by the "ours" check below. Access denied or a process CIM could not resolve
    # leaves this $null/empty, which the check treats as not ours.
    if ($w) { $name = [string]$w.Name; $cmd = [string]$w.CommandLine; $exePath = [string]$w.ExecutablePath }
    return @{ Pid = $id; Name = $name; Cmd = $cmd; ExecutablePath = $exePath }
}

function Test-Http($url) {
    # Any HTTP status, 401 included, proves the handler answered. Only no answer is a failure.
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec $ProbeSec -Method Get -ErrorAction Stop
        return [int]$r.StatusCode
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return 0
    } catch {
        return 0
    }
}

function Set-State($s, $state, $detail) {
    $s.State = $state; $s.Detail = $detail
    $line = "{0}: {1}" -f $s.Name, $state
    if ($detail) { $line = $line + " - " + $detail }
    if ($line -ne $s.LastLogged) { Write-Log $line; $s.LastLogged = $line }
}

function Start-Service-Child($s) {
    $out = Join-Path $logDir ("{0}.out.log" -f $s.Name)
    $err = Join-Path $logDir ("{0}.err.log" -f $s.Name)
    if ($testMode) {
        $out = Join-Path (Split-Path -Parent $LogFile) ("{0}.out.log" -f $s.Name)
        $err = Join-Path (Split-Path -Parent $LogFile) ("{0}.err.log" -f $s.Name)
    }
    # Keep the previous run's output. Start-Process truncates both files, and these used to
    # be kept only past 2 MB, so a restart wiped exactly the logs that explain why the service
    # went down (2026-09-23 8:23: a dashboard restart erased 20 dropped-reply tracebacks).
    foreach ($f in @($out, $err)) {
        if ((Test-Path $f) -and ((Get-Item $f).Length -gt 0)) {
            try { Move-Item -Force -ErrorAction Stop $f ($f + ".1") }
            catch { Write-Log ("could not keep the previous {0}: {1}" -f $f, $_.Exception.Message) }
        }
    }
    $exe = $pythonExe
    if ($s.Exe) { $exe = $s.Exe }
    try {
        if ($s.Console) {
            # its own visible, minimized console (typed input still works); the app writes its own log
            $p = Start-Process -FilePath $exe -ArgumentList $s.Args -WorkingDirectory $s.Dir -WindowStyle Minimized -PassThru
        } else {
            $p = Start-Process -FilePath $exe -ArgumentList $s.Args -WorkingDirectory $s.Dir `
                 -WindowStyle Hidden -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
        }
        $null = $p.Handle      # cache the handle now, or ExitCode reads back blank after the process exits
        $s.Proc = $p
        $s.StartedAt = Get-Date
        Write-Log ("started {0} (pid {1}) for port {2}" -f $s.Name, $p.Id, $s.Port)
    } catch {
        Write-Log ("FAILED to start {0}: {1}" -f $s.Name, $_.Exception.Message)
    }
}

function Stop-Owned($s, $ownerPid, $why, [bool]$tree = $false) {
    # Only ever called for a process this supervisor launched or whose command line it matched.
    # $tree (MJ Phase 2, 2026-09-25): taskkill /T, the pid and everything under it, for a pid this
    # supervisor launched, so nothing it started (a venv launcher's system-python child, a claude.exe
    # turn) outlives it.
    Write-Log ("{0}: {1}; stopping pid {2}" -f $s.Name, $why, $ownerPid)
    if ($tree) {
        $out = & taskkill.exe /T /F /PID $ownerPid 2>&1
        if ($LASTEXITCODE -ne 0) { Write-Log ("{0}: could not stop the tree of pid {1}: {2}" -f $s.Name, $ownerPid, (($out | Out-String).Trim())) }
    } else {
        try { Stop-Process -Id $ownerPid -Force -ErrorAction Stop }
        catch { Write-Log ("{0}: could not stop pid {1}: {2}" -f $s.Name, $ownerPid, $_.Exception.Message) }
    }
    for ($i = 0; $i -lt 20 -and ($s.Port -and (Get-Owner $s.Port)); $i++) { Start-Sleep -Milliseconds 500 }
}

function Start-Supervised($s, $why) {
    $now = Get-Date
    $s.Starts = @($s.Starts | Where-Object { ($now - $_).TotalMinutes -lt 10 })
    if ($s.HoldUntil -and $now -lt $s.HoldUntil) {
        Set-State $s "held" ("crash loop; next attempt at {0:HH:mm:ss}" -f $s.HoldUntil); return
    }
    if ($s.Starts.Count -ge $MaxRestarts) {
        $s.HoldUntil = $now.AddMinutes(5)
        Set-State $s "held" ("{0} starts in 10 minutes; holding until {1:HH:mm:ss}" -f $s.Starts.Count, $s.HoldUntil); return
    }
    if ($s.Starts.Count -gt 0) {
        $wait = [Math]::Min(300, 30 * [Math]::Pow(2, $s.Starts.Count - 1))
        $next = $s.Starts[-1].AddSeconds($wait)
        if ($now -lt $next) {
            # a fixed time, not a countdown, so the line is logged once rather than every pass
            Set-State $s "down" ("{0}; next start at {1:HH:mm:ss}" -f $why, $next); return
        }
    }
    $s.Starts += $now
    $s.Fails = 0
    Set-State $s "starting" $why
    Start-Service-Child $s
}

function Write-Status {
    $now = Get-Date
    $rows = @(foreach ($s in $services) {
        $ownerPid = $null
        if ($s.Owner) { $ownerPid = $s.Owner.Pid }
        $held = $null
        if ($s.HoldUntil -and $now -lt $s.HoldUntil) { $held = $s.HoldUntil.ToString("s") }
        [ordered]@{ name = $s.Name; port = $s.Port; supervised = [bool]$s.Supervised; state = $s.State;
                    detail = $s.Detail; owner_pid = $ownerPid; http = $s.Http;
                    starts_last_10m = @($s.Starts | Where-Object { ($now - $_).TotalMinutes -lt 10 }).Count;
                    held_until = $held }
    })
    $doc = [ordered]@{ checked = $now.ToString("s"); supervisor_pid = $PID; services = $rows;
                       jobs = "not tracked: the dashboard has no job manager yet" }
    try {
        $tmp = $StatusFile + ".tmp"
        [System.IO.File]::WriteAllText($tmp, ($doc | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding $false))
        Move-Item -Force $tmp $StatusFile
    } catch { }
}

function Get-PipeOwner($s) {
    # Identity (REBASE onto the 2026-09-29 ownership rules): a python.exe whose ExecutablePath is the
    # service's resolved interpreter AND whose command line carries the full worker script path and
    # " serve". The venv redirector parent (a different ExecutablePath), a probe (" probe"), a staged or
    # test worker (another script path) and anything else are never adopted.
    if (-not $s.ScriptFullPath) { return $null }
    $want = $s.ScriptFullPath.ToLower()
    $exe = $s.ExpectedExe.ToLower()
    $w = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
         Where-Object { $_.CommandLine -and $_.ExecutablePath -and ([string]$_.ExecutablePath).ToLower() -eq $exe -and
                        ([string]$_.CommandLine).ToLower().Contains($want) -and ([string]$_.CommandLine).Contains(" serve") } |
         Select-Object -First 1
    if ($null -eq $w) { return $null }
    return @{ Pid = [int]$w.ProcessId; Name = [string]$w.Name; Cmd = [string]$w.CommandLine; ExecutablePath = [string]$w.ExecutablePath }
}

function Test-PipeProbe($s) {
    # The worker's own probe: it opens the pipe, does the key handshake, sends ping. Exit 0 = healthy.
    # REBASE: the probe's arguments are the service's own with "serve" swapped for "probe", so the full
    # script path and any test overrides (--pipe, --key-file) carry over.
    $probeArgs = @($s.Args | ForEach-Object { if ($_ -eq "serve") { "probe" } else { $_ } })
    $exe = $pythonExe
    if ($s.Exe) { $exe = $s.Exe }
    try {
        $p = Start-Process -FilePath $exe -ArgumentList $probeArgs -WorkingDirectory $s.Dir -WindowStyle Hidden -PassThru
        $null = $p.Handle      # cache the handle, or ExitCode reads back blank
    } catch { return 0 }
    if (-not $p.WaitForExit($ProbeSec * 1000)) { try { & taskkill.exe /T /F /PID $p.Id 2>&1 | Out-Null } catch { }; return 0 }
    if ($p.ExitCode -eq 0) { return 200 } else { return 0 }
}

function Invoke-Pass {
    foreach ($s in $services) {
        if ($s.Pipe -or $s.Heartbeat) {
            # Port-less workers (Full Marty pipe, mail-watch heartbeat): no port. Identity = Get-PipeOwner; health = the worker's own probe.
            $owner = Get-PipeOwner $s
            $s.Owner = $owner; $s.Http = $null
            $grace = $GraceSec
            if ($s.Grace) { $grace = $s.Grace }
            $starting = $s.StartedAt -and ((Get-Date) - $s.StartedAt).TotalSeconds -lt $grace
            if ($owner) {
                $code = Test-PipeProbe $s
                $s.Http = $code
                if ($code -gt 0) { $s.Fails = 0; $s.StartedAt = $null; Set-State $s "healthy" ""; continue }
                if ($starting) { Set-State $s "starting" "running, probe not answering yet"; continue }
                $s.Fails++
                if ($s.Fails -lt $HungAfter) { Set-State $s "unresponsive" ("probe failed, {0} of {1}" -f $s.Fails, $HungAfter); continue }
                # TREE stop: taskkill /T takes the worker and every claude.exe it started (their Job
                # Objects die with it too: KILL_ON_JOB_CLOSE).
                Stop-Owned $s $owner.Pid ("hung: no pipe answer for {0} checks" -f $s.Fails) $true
                $s.Owner = $null
                Start-Supervised $s "was hung"
                continue
            }
            # no worker process (REBASE: mirrors the port branch below)
            if ($starting) {
                if ($s.Proc -and $s.Proc.HasExited) {
                    Write-Log ("{0} exited during startup (code {1})" -f $s.Name, $s.Proc.ExitCode)
                    $s.StartedAt = $null
                } else {
                    Set-State $s "starting" ""; continue
                }
            } elseif ($s.Proc -and -not $s.Proc.HasExited) {
                Stop-Owned $s $s.Proc.Id ("running but no worker process after {0} s" -f $grace) $true
            }
            Start-Supervised $s "worker not running"
            continue
        }
        $owner = Get-Owner $s.Port
        $s.Owner = $owner
        $s.Http = $null
        $grace = $GraceSec
        if ($s.Grace) { $grace = $s.Grace }
        $starting = $s.StartedAt -and ((Get-Date) - $s.StartedAt).TotalSeconds -lt $grace
        if ($owner) {
            # Ownership check, tightened 2026-09-29. Both must hold for a service we
            # actually launch ourselves (Supervised): the owning process's exe matches
            # the interpreter we would use, AND its command line carries the full
            # script path (or, when no .py argument exists, the Expect string, as
            # before). Ollama is unsupervised and is not python at all, so it keeps the
            # original Expect-only check; we never claim an interpreter path for it.
            $cmdMatches = $true
            if ($s.ScriptFullPath) {
                $cmdMatches = $owner.Cmd.ToLower().Contains($s.ScriptFullPath.ToLower())
            } elseif ($s.Expect) {
                $cmdMatches = $owner.Cmd.ToLower().Contains($s.Expect.ToLower())
            }
            $exeMatches = $true
            if ($s.Supervised) {
                if ([string]::IsNullOrEmpty($owner.ExecutablePath)) {
                    $exeMatches = $false   # access denied or unresolved: treat as not ours
                } else {
                    $exeMatches = ($owner.ExecutablePath.ToLower() -eq $s.ExpectedExe.ToLower())
                }
            }
            $ours = $exeMatches -and $cmdMatches
            if (-not $ours) {
                Set-State $s "foreign" ("port {0} is held by {1} (pid {2}), not {3}; leaving it alone" -f $s.Port, $owner.Name, $owner.Pid, $s.Name)
                continue
            }
            if (-not $s.Probe) { $s.Fails = 0; Set-State $s "listening" ""; continue }
            $code = Test-Http $s.Probe
            $s.Http = $code
            if ($code -gt 0) { $s.Fails = 0; $s.StartedAt = $null; Set-State $s "healthy" ""; continue }
            if ($starting) { Set-State $s "starting" "listening, not answering yet"; continue }
            $s.Fails++
            if (-not $s.Supervised) { Set-State $s "unresponsive" ("listening but no HTTP answer, {0} checks in a row" -f $s.Fails); continue }
            if ($s.Fails -lt $HungAfter) { Set-State $s "unresponsive" ("no HTTP answer, {0} of {1}" -f $s.Fails, $HungAfter); continue }
            Stop-Owned $s $owner.Pid ("hung: listening but no HTTP answer for {0} checks" -f $s.Fails)
            $s.Owner = $null
            Start-Supervised $s "was hung"
            continue
        }
        # nothing is listening on the port
        if (-not $s.Supervised) {
            # Ollama kick, added 2026-10-04 (Lukas: it died at 14:19 and stayed down, which broke the local
            # and vision lanes). Still not owned or killed by us: when nothing listens on 11434 we start it,
            # at most once per 5 minutes. The tray app if it is not running, else the server alone.
            if ($s.Name -eq "ollama" -and -not $testMode) {
                $now = Get-Date
                if (-not $s.OllamaKick -or ($now - $s.OllamaKick).TotalSeconds -ge 300) {
                    $s.OllamaKick = $now
                    $dir = Join-Path $env:LOCALAPPDATA "Programs\Ollama"
                    try {
                        if (-not (Get-Process -Name "ollama app" -ErrorAction SilentlyContinue)) {
                            Start-Process -FilePath (Join-Path $dir "ollama app.exe") -WindowStyle Hidden
                            Write-Log "ollama not listening; started ollama app.exe (next try in 5 min)"
                        } else {
                            Start-Process -FilePath (Join-Path $dir "ollama.exe") -ArgumentList "serve" -WindowStyle Hidden
                            Write-Log "ollama not listening, tray app running; started ollama.exe serve (next try in 5 min)"
                        }
                    } catch { Write-Log ("could not start ollama: {0}" -f $_.Exception.Message) }
                }
            }
            $why = "not listening (not restarted by this supervisor)"
            if ($s.Name -eq "ollama") { $why = "not listening (started again at most every 5 min)" }
            Set-State $s "down" $why; continue
        }
        if ($starting) {
            if ($s.Proc -and $s.Proc.HasExited) {
                Write-Log ("{0} exited during startup (code {1})" -f $s.Name, $s.Proc.ExitCode)
                $s.StartedAt = $null
            } else {
                Set-State $s "starting" ""; continue
            }
        } elseif ($s.Proc -and -not $s.Proc.HasExited) {
            Stop-Owned $s $s.Proc.Id ("running but port {0} is not listening after {1} s" -f $s.Port, $grace) $true
        }
        Start-Supervised $s ("port {0} not listening" -f $s.Port)
    }
    Write-Status
}

$testNote = ""
if ($testMode) { $testNote = ", TEST" }
Write-Log ("supervisor started (pid {0}{1})" -f $PID, $testNote)
$began = Get-Date
try {
    while ($true) {
        try { Invoke-Pass } catch { Write-Log ("pass failed: {0}" -f $_.Exception.Message) }
        if ($DurationSec -gt 0 -and ((Get-Date) - $began).TotalSeconds -ge $DurationSec) { break }
        Start-Sleep -Seconds $PollSec
    }
} finally {
    Write-Log ("supervisor stopping (pid {0})" -f $PID)
}
