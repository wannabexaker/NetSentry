# NetSentry PC agent
#
# This script is the ONLY thing the NetSentry key may run on this PC. The key is
# pinned to it in authorized_keys with
#   restrict,port-forwarding,permitopen="127.0.0.1:1234",from="<netsentry host>",
#   command="powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\NetSentry\pc-agent.ps1"
# so whatever the caller asks for arrives here as text in SSH_ORIGINAL_COMMAND and
# is only ever compared, whole, against the fixed list below. Nothing from it is
# executed, interpolated or passed on. To remove NetSentry's access: delete that
# key's line from authorized_keys (see README.md next to this file).
#
# Keep this file ASCII-only: Windows PowerShell 5.1 reads a script without a BOM
# in the system code page.

# ======================= installation-specific settings =======================
#
# $Core: a PowerShell module that starts and stops your AI services, so that this
#   agent, a tray app and a dashboard all agree on what runs. It must export
#     Start-Agent -Id <id>       -> $true when started
#     Stop-Agent -Id <id>        -> $true when stopped
#     Get-ServiceStatus -Id <id> -> object with .Name and .Running
#   and may export (each one is optional):
#     Get-ServiceRam -Id <id>    -> bytes      Get-AgentModel -Id <id> -> model name
#     Get-LoadedModels           -> names      Get-GameRunning         -> $true/$false
#     Stop-AllFree               -> frees GPU memory (stops what can be stopped)
#   Leave it pointing at a file that does not exist and the agent still works:
#   status reports the machine, start/stop/free-vram answer "not available".
#
# $Services: the service ids NetSentry may start and stop. They must match the
#   `services` list in NetSentry's workstation config, and each id must be lower
#   case letters, digits, "-" or "_".
#
# $NeedsLogin: services that only run inside a logged-on Windows session (they
#   start from a scheduled task "at log on", use the desktop, ...). Starting one
#   with nobody logged in is refused with a clear reason instead of failing.

$Core = 'C:\Path\To\YourLauncher\src\YourLauncher.Core.psm1'
$Services = @('lmstudio', 'hermes', 'openclaw')
$NeedsLogin = @('hermes', 'openclaw')

# ==============================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$Log = Join-Path $PSScriptRoot 'agent.log'
$Allowed = @('status', 'summary', 'sleep', 'hibernate', 'shutdown', 'restart', 'cancel', 'free-vram') +
           ($Services | ForEach-Object { "start $_"; "stop $_" })
$HaveCore = Test-Path -LiteralPath $Core -PathType Leaf

function Write-Log([string]$text) {
    try {
        if ((Test-Path $Log) -and (Get-Item $Log).Length -gt 512KB) { Move-Item $Log "$Log.1" -Force }
        Add-Content -Path $Log -Value ("{0:yyyy-MM-dd HH:mm:ss}  {1}" -f (Get-Date), $text) -Encoding UTF8
    } catch { }
}

function Out-Json($value) { $value | ConvertTo-Json -Depth 6 -Compress }

function Import-Core {
    if (-not $HaveCore) { return $false }
    Import-Module $Core -Force 3>$null
    return $true
}

function Test-Command([string]$name) { [bool](Get-Command $name -ErrorAction SilentlyContinue) }

function Test-LoggedOn {
    try { return [bool](@(quser 2>$null) | Select-Object -Skip 1 | Where-Object { $_ -match 'Active' }) } catch { return $false }
}

function Get-Gpu {
    # NVIDIA only (nvidia-smi ships with the driver). Anything else: null.
    try {
        $line = & nvidia-smi --query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw --format=csv,noheader,nounits 2>$null | Select-Object -First 1
        if (-not $line) { return $null }
        $f = $line -split '\s*,\s*'
        return [ordered]@{ name = $f[0]; temp_c = [int]$f[1]; load_pct = [int]$f[2]; vram_used_mb = [int]$f[3]; vram_total_mb = [int]$f[4]; power_w = [int][double]$f[5] }
    } catch { return $null }
}

function Get-Status {
    $os = Get-CimInstance Win32_OperatingSystem
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $status = [ordered]@{
        host = $env:COMPUTERNAME
        time = (Get-Date).ToString('s')
        uptime_s = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
        logged_on = Test-LoggedOn
        ram_used_mb = [int](($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1KB)
        ram_total_mb = [int]($os.TotalVisibleMemorySize / 1KB)
        disk_c_free_gb = [int]($disk.FreeSpace / 1GB)
        disk_c_total_gb = [int]($disk.Size / 1GB)
        gpu = Get-Gpu
        game_running = $null
        models_loaded = @()
        services = @()
    }
    if (-not $HaveCore) {
        $status.error = 'the service launcher module is not installed'
        return $status
    }
    try {
        Import-Core | Out-Null
        if (Test-Command 'Get-GameRunning') { try { $status.game_running = [bool](Get-GameRunning) } catch { } }
        if (Test-Command 'Get-LoadedModels') {
            try { $status.models_loaded = @(Get-LoadedModels | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_.Name) { [string]$_.Name } elseif ($_.identifier) { [string]$_.identifier } else { [string]$_ } }) } catch { }
        }
        $status.services = @(foreach ($id in $Services) {
            $s = Get-ServiceStatus -Id $id
            $ram = $null; if (Test-Command 'Get-ServiceRam') { try { $ram = [int]((Get-ServiceRam -Id $id) / 1MB) } catch { } }
            $model = $null; if (Test-Command 'Get-AgentModel') { try { $m = Get-AgentModel -Id $id; if ($m) { $model = [string]$m } } catch { } }
            [ordered]@{ id = $id; name = [string]$s.Name; running = [bool]$s.Running; ram_mb = $ram; model = $model }
        })
    } catch { $status.error = 'the service launcher module could not be read' }
    return $status
}

function Invoke-Service([string]$verb, [string]$id) {
    if (-not (Import-Core)) {
        return [ordered]@{ ok = $false; id = $id; running = $false; reported = $false; reason = 'not available on this PC' }
    }
    if ($verb -eq 'start') {
        if (($NeedsLogin -contains $id) -and -not (Test-LoggedOn)) {
            return [ordered]@{ ok = $false; id = $id; running = $false; reported = $false; reason = 'nobody is logged in on the PC' }
        }
        $ok = [bool](Start-Agent -Id $id)
    } else {
        $ok = [bool](Stop-Agent -Id $id)
    }
    $running = [bool](Get-ServiceStatus -Id $id).Running
    return [ordered]@{ ok = ($running -eq ($verb -eq 'start')); id = $id; running = $running; reported = $ok }
}

function Invoke-FreeVram {
    if (-not (Import-Core) -or -not (Test-Command 'Stop-AllFree')) {
        return [ordered]@{ ok = $false; reason = 'not available on this PC'; gpu = Get-Gpu }
    }
    Stop-AllFree | Out-Null
    return [ordered]@{ ok = $true; gpu = Get-Gpu }
}

# A page's share switch: 'share <page> on|off'. <page> is the page id from AI Mission
# Control's own list, lower-cased with every run of other characters turned into '-'
# (e.g. 'hermes/Dashboard' -> 'hermes-dashboard'). The caller's text is only compared
# against that list; the id handed on comes from the list, never from the caller.
function Get-PageSlug([string]$id) { return (($id.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')) }
function Find-SharePage([string]$slug) {
    Import-Module $Core -Force 3>$null
    foreach ($pd in @(Get-WebPages -SkipFirewall)) {
        if ((Get-PageSlug ([string]$pd.Id)) -ceq $slug) { return [string]$pd.Id }
    }
    return $null
}

# AI Mission Control actions (the /aicontrol screen). Every name the caller gives is only
# compared against a list AI Mission Control itself produces; what is handed on comes from
# that list. Each one runs through Invoke-TrackedAction (Source = netsentry), so the
# dashboard's "last action" and history show it, and answers with the summary after it.
#   mc svc <service> start|stop|restart     a service AI Mission Control shows
#   mc all start|stop                       start all / stop all and free the GPU
#   mc load <model key>  |  mc unload       load one LM Studio model / unload
#   mc use <service> <model key>            switch an agent to another model
#   mc game on|off                          game mode (free the GPU when a game starts)
#   mc open <service>                       start it (its page comes up with it) and share its pages
#   mc close <service>                      stop it and stop sharing its pages
#   mc models                               read-only: installed models + what each agent may use
#
# Anything that starts a process runs OUTSIDE this SSH session (WMI Win32_Process.Create):
# Windows ends every process of an SSH session when it closes, which took a page helper
# such as Hermes' dashboard down with it right after NetSentry had started it.
function Find-McService([string]$id) {
    foreach ($s in @(Get-ShownServices)) { if (([string]$s.Id) -ceq $id -and -not $s.Remote) { return [string]$s.Id } }
    return $null
}
function Get-McPageIds([string]$serviceId) {
    return @(Get-WebPages -SkipFirewall | Where-Object { ([string]$_.ServiceId) -ceq $serviceId } | ForEach-Object { [string]$_.Id })
}
# Runs one tracked action in a process of its own, outside this SSH session, and waits for
# its record to finish (ok / failed) or for the time limit. Target and value come from AI
# Mission Control's own lists, never from the caller.
function Invoke-McDetached([string]$kind, [string]$target, [string]$value, [int]$limitSec) {
    $q = { param($s) "'" + (([string]$s) -replace "'", "''") + "'" }
    $id = ([guid]::NewGuid().ToString('N')).Substring(0, 12)
    $cmd = "Import-Module $(& $q $Core) -Force 3>`$null; Invoke-TrackedAction -Kind $(& $q $kind) -Target $(& $q $target) -Value $(& $q $value) -Source 'netsentry' -ActionId '$id' | Out-Null"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
        CommandLine = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $enc" }
    if ($r.ReturnValue -ne 0) { throw "could not start the action process ($($r.ReturnValue))" }
    $until = (Get-Date).AddSeconds($limitSec)
    while ((Get-Date) -lt $until) {
        Start-Sleep -Milliseconds 700
        $rec = @(Get-ActionHistory) | Where-Object { ([string]$_.Id) -eq $id } | Select-Object -First 1
        if ($rec -and ([string]$rec.State) -in 'ok', 'failed') { return }
    }
}

function Find-McModel([string]$key) {
    foreach ($m in @(Get-ModelCatalogCached)) { if (([string]$m.Key) -ceq $key) { return [string]$m.Key } }
    return $null
}

$action = ("$env:SSH_ORIGINAL_COMMAND").Trim()
$SharePage = $null
$Mc = $null
if ($action -cmatch '^share ([a-z0-9-]{1,40}) (on|off)$') {
    try { $SharePage = Find-SharePage $Matches[1] } catch { $SharePage = $null }
    if ($SharePage) { $Allowed += $action }
} elseif ($action -cmatch '^mc ') {
    try {
        Import-Module $Core -Force 3>$null
        if ($action -cmatch '^mc svc ([a-z0-9_-]{1,32}) (start|stop|restart)$') {
            $id = Find-McService $Matches[1]
            if ($id) { $Mc = @{ Kind = (Get-Culture).TextInfo.ToTitleCase($Matches[2]); Target = $id; Value = '' } }
        } elseif ($action -cmatch '^mc all (start|stop)$') {
            $Mc = @{ Kind = $(if ($Matches[1] -eq 'start') { 'StartAll' } else { 'StopAll' }); Target = ''; Value = '' }
        } elseif ($action -cmatch '^mc load ([a-z0-9._-]{1,80})$') {
            $key = Find-McModel $Matches[1]
            if ($key) { $Mc = @{ Kind = 'Load'; Target = $key; Value = '' } }
        } elseif ($action -ceq 'mc unload') {
            $Mc = @{ Kind = 'Unload'; Target = ''; Value = '' }
        } elseif ($action -cmatch '^mc use ([a-z0-9_-]{1,32}) ([a-z0-9._-]{1,80})$') {
            $id = Find-McService $Matches[1]; $key = Find-McModel $Matches[2]
            if ($id -and $key -and $id -ne 'lmstudio') { $Mc = @{ Kind = 'SwitchModel'; Target = $id; Value = $key } }
        } elseif ($action -cmatch '^mc game (on|off)$') {
            $Mc = @{ Kind = 'Game'; Target = ''; Value = $Matches[1] }
        } elseif ($action -cmatch '^mc (open|close) ([a-z0-9_-]{1,32})$') {
            $id = Find-McService $Matches[2]
            if ($id -and $id -ne 'lmstudio') { $Mc = @{ Kind = $(if ($Matches[1] -eq 'open') { 'Open' } else { 'Close' }); Target = $id; Value = '' } }
        } elseif ($action -ceq 'mc models') {
            $Mc = @{ Kind = 'Models'; Target = ''; Value = '' }
        }
    } catch { $Mc = $null }
    if ($Mc) { $Allowed += $action }
}
if ($Allowed -cnotcontains $action) {
    # Only the length is logged: the text itself came from outside.
    Write-Log "REFUSED (not on the list), $($action.Length) characters"
    [Console]::Error.WriteLine('netsentry-pc-agent: that action is not on the list')
    exit 64
}

try {
    switch -Regex ($action) {
        '^status$'    { Out-Json (Get-Status) }
        '^share [a-z0-9-]+ (on|off)$' {
            $on = ($Matches[1] -eq 'on')
            Invoke-TrackedAction -Kind PageShare -Target $SharePage -Value $(if ($on) { 'true' } else { 'false' }) -Source 'netsentry' | Out-Null
            Write-Log "share $SharePage -> $on"
            Get-MissionControlSummary | ConvertTo-Json -Depth 5 -Compress
        }
        '^mc ' {
            if ($Mc.Kind -eq 'Models') {
                $agents = [ordered]@{}
                foreach ($s in @(Get-ShownServices)) {
                    if ($s.Remote -or ([string]$s.Id) -eq 'lmstudio') { continue }
                    try { $agents[[string]$s.Id] = @(Get-AvailableModels | ForEach-Object { [string]$_ }) } catch { }
                }
                $models = @(Get-ModelCatalogCached | ForEach-Object { [ordered]@{ Key = [string]$_.Key; SizeMB = [int]([double]$_.SizeBytes / 1MB) } })
                ([ordered]@{ Models = $models; Agents = $agents; GameAutoFree = [bool](Get-GameAutoFree) }) | ConvertTo-Json -Depth 5 -Compress
            } else {
                $limits = @{ Start = 120; Restart = 150; StartAll = 180; Load = 150; SwitchModel = 150 }
                if ($Mc.Kind -eq 'Game') {
                    Set-GameAutoFree -Enabled ($Mc.Value -eq 'on') | Out-Null
                } elseif ($Mc.Kind -eq 'Open') {
                    Invoke-McDetached 'Start' $Mc.Target '' 120
                    foreach ($pid_ in (Get-McPageIds $Mc.Target)) {
                        Invoke-TrackedAction -Kind PageShare -Target $pid_ -Value 'true' -Source 'netsentry' | Out-Null
                    }
                } elseif ($Mc.Kind -eq 'Close') {
                    foreach ($pid_ in (Get-McPageIds $Mc.Target)) {
                        Invoke-TrackedAction -Kind PageShare -Target $pid_ -Value 'false' -Source 'netsentry' | Out-Null
                    }
                    Invoke-TrackedAction -Kind Stop -Target $Mc.Target -Source 'netsentry' | Out-Null
                } elseif ($limits.ContainsKey($Mc.Kind)) {
                    Invoke-McDetached $Mc.Kind $Mc.Target $Mc.Value $limits[$Mc.Kind]
                } else {
                    Invoke-TrackedAction -Kind $Mc.Kind -Target $Mc.Target -Value $Mc.Value -Source 'netsentry' | Out-Null
                }
                Write-Log "$action"
                Get-MissionControlSummary | ConvertTo-Json -Depth 5 -Compress
            }
        }
        '^summary$'   { Import-Module $Core -Force 3>$null; Get-MissionControlSummary | ConvertTo-Json -Depth 5 -Compress }   # read-only, AI Mission Control 0.5.0+
        '^(start|stop) ([a-z0-9_-]+)$' { $r = Invoke-Service $Matches[1] $Matches[2]; Write-Log "$action -> running=$($r.running)"; Out-Json $r }
        '^free-vram$' { Write-Log $action; Out-Json (Invoke-FreeVram) }
        '^shutdown$'  { Write-Log $action; shutdown.exe /s /t 15 /c "Shut down by NetSentry" | Out-Null; Out-Json ([ordered]@{ ok = $true; in_seconds = 15 }) }
        '^restart$'   { Write-Log $action; shutdown.exe /r /t 15 /c "Restarted by NetSentry" | Out-Null; Out-Json ([ordered]@{ ok = $true; in_seconds = 15 }) }
        '^cancel$'    { Write-Log $action; shutdown.exe /a 2>$null | Out-Null; Out-Json ([ordered]@{ ok = $true }) }
        '^hibernate$' { Write-Log $action; Out-Json ([ordered]@{ ok = $true }); [Console]::Out.Flush(); shutdown.exe /h | Out-Null }
        '^sleep$' {
            # Answer first: the connection goes down with the PC.
            Write-Log $action
            Out-Json ([ordered]@{ ok = $true }); [Console]::Out.Flush()
            Add-Type -AssemblyName System.Windows.Forms
            [void][System.Windows.Forms.Application]::SetSuspendState('Suspend', $false, $false)
        }
    }
} catch {
    Write-Log "$action FAILED: $($_.Exception.Message)"
    [Console]::Error.WriteLine("netsentry-pc-agent: $action failed")
    exit 1
}
