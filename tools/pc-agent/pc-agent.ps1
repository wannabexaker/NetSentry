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

$action = ("$env:SSH_ORIGINAL_COMMAND").Trim()
if ($Allowed -cnotcontains $action) {
    # Only the length is logged: the text itself came from outside.
    Write-Log "REFUSED (not on the list), $($action.Length) characters"
    [Console]::Error.WriteLine('netsentry-pc-agent: that action is not on the list')
    exit 64
}

try {
    switch -Regex ($action) {
        '^status$'    { Out-Json (Get-Status) }
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
