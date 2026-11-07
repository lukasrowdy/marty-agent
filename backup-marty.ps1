$ErrorActionPreference = "Stop"
$dest = "\\{{NAS_MODEL}}\home\Marty Backup"

# Log locally FIRST, so a failure is visible even when the NAS is not.
# (Changed 2026-09-20: the original logged only to the NAS, which hid a
# three-day failure caused by a missing stored credential.)
$localLogDir = "C:\Users\{{WIN_USER}}\my-agent\logs"
if (-not (Test-Path $localLogDir)) { New-Item -ItemType Directory -Path $localLogDir | Out-Null }
$localLog = Join-Path $localLogDir "backup-marty.log"

function Log($msg) {
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $msg" | Out-File -Append -Encoding utf8 $localLog
}

# Run a restore drill, retrying up to twice, 60 s apart (added 2026-09-27, Lukas's yes). On
# 2026-09-27 the 3 AM private drill failed on a Wi-Fi re-auth (Errno 22) while the archive was
# good (re-drill passed 1,390 files), which skipped the prune and Jr's history. The drill is
# read-only, so a retry is safe. Returns the output of the passing try; throws after the third.
function Invoke-Drill($label, [scriptblock]$run) {
    for ($try = 1; $try -le 3; $try++) {
        $text = (& $run) -join ' '
        if ($LASTEXITCODE -eq 0) {
            if ($try -gt 1) { Log "$label drill passed on try $try" }
            return $text
        }
        Log "$label drill failed on try ${try}: $($text.Substring(0, [Math]::Min(300, $text.Length)))"
        if ($try -lt 3) { Start-Sleep -Seconds 60 }
    }
    throw "$label RESTORE DRILL FAILED after 3 tries: $($text.Substring(0, [Math]::Min(700, $text.Length)))"
}

# Mirror one working folder to the NAS (added 2026-09-29, Lukas's yes, step 1 of the working-folder
# extension). Plain files, no drill: these are live working copies, restored the same way the vault
# mirror above is. /XJ skips reparse points (junctions) so a linked folder is never walked twice.
# A source that does not exist yet is skipped and logged rather than treated as a failure.
function Backup-WorkingFolder($Label, $Src, $Dst, [string[]]$ExcludeDirs, [string[]]$ExcludeFiles) {
    # Guard added 2026-09-29 (skeptic fix 1): refuse to /MIR anywhere but under the real
    # NAS destination. A bad call (bad $Dst, or $Dst equal to the share root itself) would
    # otherwise mirror-delete the whole share instead of one working folder.
    if ($Dst -notlike "$dest\?*") { throw "refusing /MIR to $Dst" }
    if (-not (Test-Path -LiteralPath $Src)) {
        Log "$Label skipped: $Src does not exist"
        return
    }
    $roboArgs = @($Src, $Dst, "/MIR", "/XJ", "/R:5", "/W:30", "/NFL", "/NDL", "/NP")
    if ($ExcludeDirs -and $ExcludeDirs.Count -gt 0) { $roboArgs += "/XD"; $roboArgs += $ExcludeDirs }
    if ($ExcludeFiles -and $ExcludeFiles.Count -gt 0) { $roboArgs += "/XF"; $roboArgs += $ExcludeFiles }
    robocopy @roboArgs | Out-Null
    $rc = $LASTEXITCODE
    # robocopy: 0-7 are success codes (files copied, extras removed, etc.); 8 and up mean failures.
    if ($rc -ge 8) { throw "robocopy ($Label) failed with exit code $rc" }
    Log "$Label mirrored (robocopy code $rc)"
}

Log "Starting Marty backup"
try {
    # Why this is not a bare Test-Path (changed 2026-09-21): Test-Path returns
    # $false identically for a NAS that is switched off and for one that rejected
    # the password, and the old message blamed reachability either way. That cost
    # an hour on 2026-09-21, when a stale stored credential was misread as an
    # unreachable share. Probe the port first, then the share, and say which failed.
    try {
        Get-ChildItem -LiteralPath $dest -ErrorAction Stop | Out-Null
    }
    catch {
        $accessError = $_.Exception.Message
        $portOpen = $false
        try {
            $portOpen = (Test-NetConnection -ComputerName '{{NAS_MODEL}}' -Port 445 -WarningAction SilentlyContinue).TcpTestSucceeded
        } catch { }
        if (-not $portOpen) {
            throw "NAS is not answering on the network: {{NAS_MODEL}} port 445 is closed or the unit is off. ($accessError)"
        }
        throw "NAS is up and serving SMB, but refused access to $dest. This is almost always a credential problem, not a network one. Check: Credential Manager has entries for BOTH '{{NAS_MODEL}}' and '{{NAS_IP}}' (Windows matches them literally by the name used), and DSM > Control Panel > Security > Account > Account Protection is not holding the account. Windows said: $accessError"
    }

    robocopy "C:\Users\{{WIN_USER}}\marty-vault" "$dest\vault" /MIR /R:2 /W:5 /NFL /NDL /NP | Out-Null
    $rc = $LASTEXITCODE
    # robocopy: 0-7 are success codes (files copied, extras removed, etc.); 8 and up mean failures.
    if ($rc -ge 8) { throw "robocopy failed with exit code $rc" }
    Log "Vault mirrored (robocopy code $rc)"

    # Handoff vault, ciphertext only (added 2026-09-21, C3 of the security plan).
    # .vault holds salt, verifier and KDF parameters, never a key. media/*.enc are
    # the encrypted objects. The plaintext inbox/outbox packs are deliberately NOT
    # mirrored: this share is readable on the LAN.
    robocopy "C:\Users\{{WIN_USER}}\marty-handoff\.vault" "$dest\handoff\.vault" /MIR /R:2 /W:5 /NFL /NDL /NP | Out-Null
    $rc = $LASTEXITCODE
    if ($rc -ge 8) { throw "robocopy (handoff .vault) failed with exit code $rc" }
    robocopy "C:\Users\{{WIN_USER}}\marty-handoff\media" "$dest\handoff\media" *.enc /MIR /R:2 /W:5 /NFL /NDL /NP | Out-Null
    $rc2 = $LASTEXITCODE
    if ($rc2 -ge 8) { throw "robocopy (handoff media) failed with exit code $rc2" }
    Log "Handoff vault mirrored, ciphertext only (robocopy codes $rc / $rc2)"

    # Mirror the working folders (added 2026-09-29, Lukas's yes). private\ is excluded from the
    # my-agent copy because it is already archived encrypted further below; facefusion is a
    # re-downloadable install, not data worth mirroring.
    # Additional /XD and /XF entries added 2026-09-29 (skeptic fix 2): these honour
    # tools\recovery_bundle.py lines 23-30, which say this same private data (uploads, any
    # dashboard chat store, private/, logs, device-token and secret files) must not sit on
    # this LAN-readable share in plaintext.
    $stepStart = Get-Date
    $workingExcludeDirs = @(
        "private", "facefusion", ".venv", "venv", "node_modules", "__pycache__", ".wrangler",
        ".rollback-*", ".staged-*", "_bundle-*",
        "C:\Users\{{WIN_USER}}\my-agent\uploads",
        "C:\Users\{{WIN_USER}}\my-agent\dashboard\chats",
        "C:\Users\{{WIN_USER}}\my-agent\dashboard\outbox",
        "C:\Users\{{WIN_USER}}\my-agent\logs",
        "C:\Users\{{WIN_USER}}\my-agent\status",
        "C:\Users\{{WIN_USER}}\my-agent\proposals",
        "C:\Users\{{WIN_USER}}\my-agent\jr\history",
        "C:\Users\{{WIN_USER}}\my-agent\jr\drafts",
        "C:\Users\{{WIN_USER}}\my-agent\jr\computer",
        "C:\Users\{{WIN_USER}}\my-agent\jr\library",
        "test-chats", "*.bak-*",
        "logs", "tmp", ".newcode-*"
    )
    $workingExcludeFiles = @(
        "*.mpb", "*.jsonl", "*.key", "*.dpapi", "*.env", ".env",
        "keyinfo.json", "grant.json", "passkeys-user.json", "private_names.json", "broker-config.json",
        "*.log"
    )

    # Non-fatal working folders (skeptic fix 3): one folder's robocopy failure must not skip
    # the private archive or Jr's history further below. Each call is caught and recorded in
    # $wf; the run still fails at the end (see the throw after Jr's history) but every later
    # step gets to run first.
    # Desktop exclude (skeptic fix 4): "Secure Folder" is a Samsung Secure Folder export, 21.7 GB
    # of private media, and must not land on this LAN-readable share. node_modules is excluded
    # from both Projects and Desktop as re-buildable bulk, not data worth mirroring.
    $projectsExcludeDirs = @("node_modules")
    $desktopExcludeDirs = @("node_modules", "C:\Users\{{WIN_USER}}\OneDrive\Desktop\Secure Folder")

    $wf = @()
    try { Backup-WorkingFolder "Projects" "C:\Users\{{WIN_USER}}\Projects" "$dest\projects" $projectsExcludeDirs }
    catch { $wf += $_.Exception.Message; Log "WORKING FOLDER FAILED: $($_.Exception.Message)" }
    try { Backup-WorkingFolder "Desktop" "C:\Users\{{WIN_USER}}\OneDrive\Desktop" "$dest\desktop" $desktopExcludeDirs }
    catch { $wf += $_.Exception.Message; Log "WORKING FOLDER FAILED: $($_.Exception.Message)" }
    try { Backup-WorkingFolder "Documents" "C:\Users\{{WIN_USER}}\OneDrive\Documents" "$dest\documents" }
    catch { $wf += $_.Exception.Message; Log "WORKING FOLDER FAILED: $($_.Exception.Message)" }
    try { Backup-WorkingFolder "Pictures" "C:\Users\{{WIN_USER}}\OneDrive\Pictures" "$dest\pictures" }
    catch { $wf += $_.Exception.Message; Log "WORKING FOLDER FAILED: $($_.Exception.Message)" }
    try { Backup-WorkingFolder "my-agent" "C:\Users\{{WIN_USER}}\my-agent" "$dest\my-agent" $workingExcludeDirs $workingExcludeFiles }
    catch { $wf += $_.Exception.Message; Log "WORKING FOLDER FAILED: $($_.Exception.Message)" }

    $stepElapsed = [Math]::Round(((Get-Date) - $stepStart).TotalSeconds, 1)
    Log "Working folders mirrored in $stepElapsed s"

    Copy-Item "C:\Users\{{WIN_USER}}\my-agent\CLAUDE.md" "$dest\config\CLAUDE.md" -Force
    Copy-Item "C:\Users\{{WIN_USER}}\my-agent\backtalk\backtalk.json" "$dest\config\backtalk.json" -Force -ErrorAction SilentlyContinue
    Copy-Item "C:\Users\{{WIN_USER}}\my-agent\ai-visualizer\ai-visualizer.json" "$dest\config\ai-visualizer.json" -Force -ErrorAction SilentlyContinue
    Log "Configs copied"

    # Versioned recovery bundle plus a restore drill (added 2026-09-23, audit finding 12).
    # The mirrors above keep no history (/MIR copies deletions too) and never held the custom
    # code, AGENTS.md, the tool scope, the Modelfiles or a dependency record. This adds a dated
    # zip of all of that plus the vault to versions\, keeps the newest 8, and restores the NAS
    # copy into a temp folder to prove it (every file checksummed, the restored selftests run).
    # Private data (uploads\, dashboard\chats\, private\, logs, device tokens) is deliberately
    # NOT in it: this share is readable on the LAN. See tools\recovery_bundle.py.
    # Native output is captured without 2>&1: under ErrorActionPreference Stop, PowerShell 5.1
    # turns any stderr line from a redirected native command into a terminating error.
    $py = "C:\Users\{{WIN_USER}}\AppData\Local\Programs\Python\Python312\python.exe"
    $rb = "C:\Users\{{WIN_USER}}\my-agent\tools\recovery_bundle.py"
    $name = "marty-recovery-{0}.zip" -f (Get-Date -Format "yyyy-MM-dd-HHmm")
    $local = Join-Path $env:TEMP $name
    $out = & $py $rb build --out $local
    if ($LASTEXITCODE -ne 0) { throw "recovery bundle build failed (exit $LASTEXITCODE): $($out -join ' ')" }
    Log "Recovery bundle built: $($out -join ' ')"
    New-Item -ItemType Directory -Force -Path "$dest\versions" | Out-Null
    Copy-Item $local "$dest\versions\$name" -Force
    if ((Get-FileHash $local).Hash -ne (Get-FileHash "$dest\versions\$name").Hash) {
        throw "the recovery bundle copied to the NAS does not match the local build"
    }
    Remove-Item $local -Force
    $pruned = & $py $rb prune "$dest\versions" --keep 8
    Log "Stored $name in versions (newest 8 kept): $($pruned -join ' ')"
    $drill = Invoke-Drill "Recovery bundle ($name)" { & $py $rb drill "$dest\versions\$name" }
    Log "Restore drill passed for $name (every file verified, restored selftests passed)"

    # Encrypted copy of private\ (weekly from 2026-09-27; Lukas's yes on the Punch List, 2026-09-25
    # 5:58 AM: "it joins the Sunday backup, keeping the last 4 on the NAS"). Ciphertext only: the key
    # stays in Credential Manager ("marty/private-backup-key"), which this task can read because it
    # runs as {{WIN_USER}}, logged on. Built straight onto the NAS, drilled (every file decrypted and
    # checksummed in memory, no plaintext on disk), and pruned to the newest 4 only after the drill
    # passes. business\ is never in it. See tools\private_backup.py.
    $pb = "C:\Users\{{WIN_USER}}\my-agent\tools\private_backup.py"
    $pname = "private-{0}.mpb" -f (Get-Date -Format "yyyy-MM-dd-HHmm")
    New-Item -ItemType Directory -Force -Path "$dest\private" | Out-Null
    $out = & $py $pb build --out "$dest\private\$pname"
    if ($LASTEXITCODE -ne 0) { throw "private backup build failed (exit $LASTEXITCODE): $($out -join ' ')" }
    Log "Private backup built: $($out -join ' ')"
    $pdrill = Invoke-Drill "PRIVATE ($pname)" { & $py $pb drill "$dest\private\$pname" }
    Log "Private restore drill passed for $pname"
    $ppruned = & $py $pb prune "$dest\private" --keep 4
    Log "Private backups pruned to the newest 4: $($ppruned -join ' ')"

    # Marty Jr.'s history, ciphertext only (Lukas, 2026-09-25: "Jr's encrypted history should join
    # the weekly backup"). It is already AES-256-GCM under a key only Lukas types, so it is copied
    # as-is into a dated folder, every file hash-checked against the source, newest 4 kept.
    # Skipped (and logged) until Jr's first unlock creates the folder.
    $jrSrc = "C:\Users\{{WIN_USER}}\my-agent\jr\history"
    if (Test-Path -LiteralPath $jrSrc) {
        $jrDest = "$dest\jr-history\jr-history-{0}" -f (Get-Date -Format "yyyy-MM-dd-HHmm")
        robocopy $jrSrc $jrDest /E /R:2 /W:5 /NFL /NDL /NP | Out-Null
        $rc = $LASTEXITCODE
        if ($rc -ge 8) { throw "robocopy (Jr history) failed with exit code $rc" }
        $jrFiles = @(Get-ChildItem -LiteralPath $jrSrc -Recurse -File)
        foreach ($f in $jrFiles) {
            $rel = $f.FullName.Substring($jrSrc.Length).TrimStart('\')
            $copy = Join-Path $jrDest $rel
            if (-not (Test-Path -LiteralPath $copy) -or
                (Get-FileHash -LiteralPath $f.FullName).Hash -ne (Get-FileHash -LiteralPath $copy).Hash) {
                throw "Jr history copy check FAILED for $rel"
            }
        }
        Get-ChildItem -LiteralPath "$dest\jr-history" -Directory | Where-Object Name -like "jr-history-*" |
            Sort-Object Name -Descending | Select-Object -Skip 4 |
            ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }
        Log "Jr history copied, ciphertext only ($($jrFiles.Count) files hash-checked, newest 4 kept)"
    } else {
        Log "Jr history skipped: $jrSrc does not exist yet (Jr's first unlock creates it)"
    }

    # Skeptic fix 3: fail the run if any working folder failed, but only after every later
    # step (private archive, Jr history) has already run.
    if ($wf.Count) { throw "working folders failed: $($wf -join '; ')" }

    Log "Marty backup finished OK"
    # Second copy of the log on the NAS, for reading from another machine.
    Copy-Item $localLog (Join-Path $dest "backup-log.txt") -Force -ErrorAction SilentlyContinue
    exit 0
}
catch {
    Log "FAILED: $($_.Exception.Message)"
    exit 1
}
