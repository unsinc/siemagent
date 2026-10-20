<#
.SYNOPSIS
UNS SIEM Agent deployment tool

.DESCRIPTION
This script first evaluates the UNS SIEM Agent (same checks, output and NinjaOne property as siem-evaluation.ps1).
If the agent is missing, broken, unreadable or outdated it runs the deployment once, waits, evaluates once more to
confirm, and reports NEEDS_REVIEW if the agent is still not compliant. Use -InstallOnly to skip the evaluation and
run only the deployment below.

Deployment scrip will perform following tasks:
1. Uninstall Sysmon 32 bit from the system.
2. Install Sysmon 64bit on the system.
3. Uninstall Perch collector is its installed.
4. Install and enforce proprietary Sysmon64 config file.
5. Deploy UNS SIEM Agent.
If you need help with switches, please repeat this command with -Full

.NOTES
File Name       : elastic-agent-installer.ps1
Author          : nkolev@unsinc.com
Prerequisite    : PowerShell >= V4,V5
Copyright       : 2024, UNS Inc
Version         : 2026.10.07.15

.EXAMPLE
You can smply load the script and let it do it's magic.
.\elastic-agent-installer.ps1

.EXAMPLE
You can provide both enrollment url and token on the console. If none is provided, you will be prompted during the deployment process.
.\elastic-agent-installer.ps1 -token <elastic enrollment token> -fleetURL <url> -Verbose

.EXAMPLE
If you want to deploy from local files, make sure script in positioned where files are. Execute with -local. In addition you can specify
.\elastic-agent-installer.ps1 -token <elastic enrollment token> -fleetURL <url> -Verbose -local

.EXAMPLE
If you'd like to choose custom destination file path, please select -datapath. Ex. -datapath C:\temp
.\elastic-agent-installer.ps1 -datapath C:\temp

.EXAMPLE
If you'd like to tag the agent at enrollment, provide one or more comma-separated tags with -tag.
.\elastic-agent-installer.ps1 -token <elastic enrollment token> -fleetURL <url> -tag "prod,workstation"

.LINK
https://github.com/unsinc/siemagent/blob/main/README.md

.PARAMETER token
Use this switch to provide an enrollment token, enabling the registration of new UNS nodes to a specific UNS SIEM instance.

.PARAMETER fleetURL
Use this switch to assign a specific UNS Fleet URL to a particular UNS SIEM instance. Format is: https://750258aff4014f51a3fvc4a9d68bf5f.fleet.us-east-1.aws.elastic-cloud.com

.PARAMETER datapath
Use this switch to indicate where deployment files are. If this switch is used, installer will not download files, but instead grab them from the indicated folder.

.PARAMETER local
To be used with $datapth. When passed, script will look for files stored under datapath. If no datapath is specified while passing local, datapath will default to current script location.

.PARAMETER insecure
To be used with self signed fleet certificates 

.PARAMETER tag
Use this switch to assign one or more comma-separated tags to the agent at enrollment, e.g. -tag "prod,workstation". If omitted, no --tag switch is passed to the installer.

.PARAMETER InstallOnly
Skips the evaluation and the post-deployment check and only runs the deployment. The evaluation step starts the deployment with this switch, so it should not normally be used directly.

.PARAMETER UninstallOnly
Removes the UNS SIEM Agent (and Elastic Endpoint, if present) and installs nothing: no evaluation, no download, no Sysmon or Perch changes. Uses the uninstall token passed with -uninstallToken, or the one for this machine's policy (elasticUninstallToken<Role> variables), which an agent with Agent Tamper Protection needs. NinjaOne variable: elasticUninstallOnly.

.PARAMETER uninstallToken
Use this switch to provide the Elastic Agent uninstall token, required to remove an existing agent whose policy has Agent Tamper Protection enabled (Elastic Defend integration). Without it, removal of a tamper-protected agent/Endpoint installation will fail.

.PARAMETER policy
Selects which of the role's agent policies to enrol in. Auto (default) uses the machine's role: Windows Server 2012 gets its no-Defend server policy, and a workstation gets Workstations - No Defend only when a third-party antivirus is detected. NoDefend forces the no-Defend policy of the role. Defend stops a workstation from being switched to No Defend by the detection. Other uses the one extra policy for machines that fit none of the roles. Tokens come from the per-role variables at the top of the script.

#>
[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false, ValueFromPipeline=$true)]
    [ValidatePattern("^[a-zA-Z0-9+/]+={0,2}$")]
	[string[]]$token,

    [Parameter(Mandatory = $false, ValueFromPipeline=$true)]
    [ValidatePattern("^https:\/\/.*")]
	[string[]]$fleetURL,

    [Parameter(Mandatory = $false, ValueFromPipeline=$true)]
	[string[]]$datapath,

    [Parameter(Mandatory = $false)]
    [switch]$local,

    [Parameter(Mandatory = $false)]
    [switch]$insecure,

    # No ValidatePattern here: attributes on a script parameter stay attached to the variable, so a
    # later hard-coded "$tag = ..." (e.g. injected by NinjaOne) would be re-validated and silently
    # fail. Tags are normalized and validated below instead.
    [Parameter(Mandatory = $false, ValueFromPipeline=$true)]
	[string[]]$tag,

    [Parameter(Mandatory = $false, ValueFromPipeline=$true)]
	[string[]]$uninstallToken,

    # Auto, NoDefend, Defend or Other - checked in the script body (see "-policy" below), not with ValidateSet,
    # for the same reason as -tag above.
    [Parameter(Mandatory = $false)]
	[string]$policy,

    [Parameter(Mandatory = $false)]
    [switch]$InstallOnly,

    [Parameter(Mandatory = $false)]
    [switch]$UninstallOnly,

    # Set by the evaluation step when it starts the deployment, so both use the same agent version. Not meant to be given by hand.
    [Parameter(Mandatory = $false)]
    [string]$TargetVersion,

    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

# Script version: increase the last number by one (2026.10.07.12, ...; a new day starts with the date and .1) EVERY time this script is changed, and add a line
# to the change log below. It is printed first in the output, so the log of a run shows which copy of
# the script (e.g. the one stored in NinjaOne) actually ran.
$ScriptVersion = "2026.10.07.15"
# Change log:
#   2026.10.07.15  The role evidence in the log also shows the AD DS (NTDS) service state; the role itself is decided as before.
#   2026.10.07.14  Failure exits reach the evaluation process as non-zero (Stop-Deployment; exit 4 used to become 0); the old-Endpoint
#                  cleanup after install only removes a stray Endpoint under a ...NoDefend policy and never an Endpoint a Defend policy
#                  takes over; dead exit-3 branch removed; downloads have time limits and reject empty files; Perch exit codes 3010/1641/1605
#                  are success; Sysmon config is re-applied when it changed; the agent is found by service name; the version is decided once
#                  (-TargetVersion); one deployment at a time (named mutex).
#   2026.10.07.13  -UninstallOnly no longer runs the Sysmon file copy (it failed and never reached the uninstall); the Sysmon
#                  copy retry catches System.IO.FileNotFoundException (the short name was not a valid type) and no longer rethrows.
#   2026.10.07.12  Missing token/URL is reported as exit code 2 (no wait or re-check); uninstall tries every known policy token.
#   2026.10.07.11  Elastic Endpoint is removed with its own uninstaller (elastic-endpoint.exe uninstall --uninstall-token <token>),
#                  trying every known policy token; recovery never uninstalls the freshly installed agent; tokens are masked in output.
#   2026.10.07.10  Version before this change log started.
Write-Output "UNS SIEM Agent installer script version $ScriptVersion"

######## Evaluation / deployment settings ##########
# Offline fallback for the required agent version. The real source is agent-version on GitHub; this
# is only used when GitHub can't be reached.
$defaultVersion = [version]"9.5.5"

# Seconds to wait between the end of the deployment and the confirmation check.
$recheckDelaySeconds = 15

# Longest the deployment may run before it is stopped (a hung deployment would otherwise block
# the confirmation check and the status report forever).
$deployTimeoutMinutes = 15

# Elastic Agent listens on 127.0.0.1:<agent.grpc.port> for its own components. The default is 6789,
# which other software (e.g. the UniFi Network Application) also uses. If it is taken or not bindable,
# the agent service dies right after it starts and the installer fails with "elastic-agent-system pipe
# not found". The deployment then picks another port and writes it into elastic-agent.yml.
$defaultAgentGrpcPort = 6789
####################################################

######## Uncomment if you want to have hard-coded fleeturl and token variables ##########
#$fleetURL = ""
#$token = ""
#$datapath = (Get-Location)
#$local = $true
#$tag = "prod,workstation"
# Uninstall token for removing an existing tamper-protected agent/Endpoint install - this is
# NOT the enrollment token above, it's the per-agent token from Kibana > Fleet > Agents > this
# host > Uninstall command, only needed when Agent Tamper Protection is enabled on the policy.
#$uninstallToken = ""

# --- Per-role tokens and tags, applied automatically (nothing else to uncomment) ---
# Lets one task deploy every kind of endpoint: the script detects the machine's role and uses that
# policy's tokens below (a role can have a normal and a no-Defend policy), and adds the role's tags (Windows + Workstation / Server / HyperV / Active
# Directory) after the client tag above. A token you set or pass yourself ($token / -token,
# $uninstallToken / -uninstallToken) always wins. Leave a role's value empty ("") if it has none.
#$disableRoleTags = $true   # uncomment to add no role tags
#
# Enrollment tokens: Kibana > Fleet > Enrollment tokens (one per agent policy).
#$tokenWorkstation  = ""   # Policy: Workstations
#$tokenWorkstationNoDefend = ""   # Policy: Workstations - No Defend (used with -policy NoDefend)
#$tokenServer       = ""   # Policy: Servers (standalone / member server, no Hyper-V)
#$tokenServerNoDefend   = ""   # Policy: Servers - No Defend (Windows Server 2012, or any server that cannot run Defend)
#$tokenHyperV       = ""   # Policy: Hyper-V hosts
#$tokenHyperVNoDefend   = ""   # Policy: Hyper-V hosts - No Defend
#$tokenDC           = ""   # Policy: Domain Controllers
#$tokenDCNoDefend       = ""   # Policy: Domain Controllers - No Defend
#$tokenOther        = ""   # Policy: Other - one extra policy for machines that fit none of the above (used with -policy Other)
#
# Uninstall tokens: Kibana > Fleet > Uninstall tokens (one per agent policy, so each role's
# uninstall token belongs to the same policy as its enrollment token above).
#$uninstallTokenWorkstation = ""   # Policy: Workstations
#$uninstallTokenWorkstationNoDefend = ""   # Policy: Workstations - No Defend
#$uninstallTokenServer      = ""   # Policy: Servers
#$uninstallTokenServerNoDefend  = ""   # Policy: Servers - No Defend
#$uninstallTokenHyperV      = ""   # Policy: Hyper-V hosts
#$uninstallTokenHyperVNoDefend  = ""   # Policy: Hyper-V hosts - No Defend
#$uninstallTokenDC          = ""   # Policy: Domain Controllers
#$uninstallTokenDCNoDefend      = ""   # Policy: Domain Controllers - No Defend
#$uninstallTokenOther       = ""   # Policy: Other - one extra policy for machines that fit none of the above
#
# Services that mean a third-party antivirus / EDR is installed (wildcards allowed). A workstation
# with one of these running is enrolled in Workstations - No Defend. Add the products your clients use.
$thirdPartyAvServices = @(
    "CSFalconService", "SentinelAgent", "CylanceSvc", "CbDefense", "cyserver",
    "SAVService", "Sophos Endpoint Defense Service", "SepMasterService", "ccSvcHst", "SmcService",
    "McShield", "mfemms", "mfevtp", "ntrtscan", "TmListen", "ekrn", "AVP*", "EPSecurityService",
    "WRSVC", "MBAMService", "AvastSvc", "avast! Antivirus", "AVGSvc", "SBAMSvc", "PandaAetherAgent"
)
#
# Choosing between a role's two policies: Windows Server 2012 is detected automatically. For
# workstations the no-Defend policy is chosen automatically when a third-party antivirus is found;
# -policy NoDefend forces it (also for a server that can't run Defend but isn't 2012), -policy Defend
# stops the automatic switch, and -policy Other picks the extra policy. Default is Auto.
#$policy = "NoDefend"
###########################################################################################

######## Settings from NinjaOne script variables (environment variables) ##########
# NinjaOne hands script variables to the script as environment variables, so one script can serve every
# client: create the variable in the task, leave the script alone. The environment name is the script
# variable name with an "elastic" prefix and a capital first letter, so it cannot collide with
# unrelated machine variables: $token -> elasticToken, $fleetURL -> elasticFleetURL,
# $tokenServer -> elasticTokenServer, $uninstallTokenDC -> elasticUninstallTokenDC. For each setting the
# first of these that has a value wins:
#   1. a parameter given on the command line (-token, -fleetURL, ...)
#   2. the environment variable (elastic...)
#   3. the value hard-coded in the section above
# Settings read: token, fleetURL, datapath, tag, uninstallToken, policy, the switches local / insecure /
# disableRoleTags (true/1/yes/on turn them on, anything else off), and the per-role tokens
# (tokenServer, tokenDC, uninstallTokenServer, ... see the list above). An empty variable, or the
# text "null" that NinjaOne sends for one, counts as not set. Values are never printed, only where
# each setting came from.
function Get-EnvSettingName {
    param ([string]$Name)
    return ('elastic' + $Name.Substring(0, 1).ToUpper() + $Name.Substring(1))
}
function Get-EnvSetting {
    param ([string]$Name)
    $value = [Environment]::GetEnvironmentVariable((Get-EnvSettingName $Name))
    if ([string]::IsNullOrWhiteSpace($value)) { return $null }
    $value = $value.Trim()
    if ($value -like 'null') { return $null }
    return $value
}
$script:SettingSources = New-Object System.Collections.Generic.List[string]

foreach ($settingName in 'token', 'fleetURL', 'datapath', 'tag', 'uninstallToken', 'policy') {
    if ($PSBoundParameters.ContainsKey($settingName)) {
        # puts the parameter back in case a hard-coded line above replaced it
        Set-Variable -Name $settingName -Value $PSBoundParameters[$settingName]
        $script:SettingSources.Add("$settingName=parameter")
        continue
    }
    $envValue = Get-EnvSetting $settingName
    if ($null -ne $envValue) {
        try {
            Set-Variable -Name $settingName -Value $envValue -ErrorAction Stop
            $script:SettingSources.Add("$settingName=environment($(Get-EnvSettingName $settingName))")
        } catch {
            Write-Output "[-] The '$(Get-EnvSettingName $settingName)' variable from the environment is not valid: $($_.Exception.Message)"
            throw
        }
    } elseif (Get-Variable -Name $settingName -ValueOnly -ErrorAction SilentlyContinue) {
        $script:SettingSources.Add("$settingName=script")
    }
}

foreach ($switchName in 'local', 'insecure', 'disableRoleTags', 'uninstallOnly') {
    if ($PSBoundParameters.ContainsKey($switchName)) { $script:SettingSources.Add("$switchName=parameter"); continue }
    $envValue = Get-EnvSetting $switchName
    if ($null -ne $envValue) {
        $switchOn = [bool]($envValue -match '^(true|1|yes|y|on)$')
        Set-Variable -Name $switchName -Value $switchOn
        $script:SettingSources.Add("$switchName=environment($(Get-EnvSettingName $switchName)=$switchOn)")
    }
}

foreach ($roleName in 'Workstation', 'WorkstationNoDefend', 'Server', 'ServerNoDefend', 'HyperV', 'HyperVNoDefend', 'DC', 'DCNoDefend', 'Other') {
    foreach ($prefix in 'token', 'uninstallToken') {
        $roleVariable = "$prefix$roleName"
        $envValue = Get-EnvSetting $roleVariable
        if ($null -ne $envValue) {
            Set-Variable -Name $roleVariable -Value $envValue -Scope Script
            $script:SettingSources.Add("$roleVariable=environment($(Get-EnvSettingName $roleVariable))")
        } elseif (Get-Variable -Name $roleVariable -Scope Script -ValueOnly -ErrorAction SilentlyContinue) {
            $script:SettingSources.Add("$roleVariable=script")
        }
    }
}

# Removes every elastic... setting from this process's environment, and the token variables from memory,
# so nothing the task passed in is left for a later step or child process. Call it after the work is done
# (the deployment process the evaluation starts reads the environment itself, so not before). The
# environment of a process disappears with the process anyway; this is for anything launched later and
# for the log: if a value turns out to be stored permanently (User or Machine scope), that is reported,
# not deleted, because this script did not put it there.
function Clear-ElasticEnvSettings {
    $settingNames = @('token', 'fleetURL', 'datapath', 'tag', 'uninstallToken', 'policy', 'local', 'insecure', 'disableRoleTags', 'uninstallOnly')
    foreach ($role in 'Workstation', 'WorkstationNoDefend', 'Server', 'ServerNoDefend', 'HyperV', 'HyperVNoDefend', 'DC', 'DCNoDefend', 'Other') {
        $settingNames += "token$role"
        $settingNames += "uninstallToken$role"
    }
    $cleared = 0
    $persisted = @()
    foreach ($settingName in $settingNames) {
        $envName = Get-EnvSettingName $settingName
        if ([Environment]::GetEnvironmentVariable($envName, 'Process')) { $cleared++ }
        [Environment]::SetEnvironmentVariable($envName, [NullString]::Value, 'Process')   # a plain $null leaves an empty variable behind in PowerShell 7
        foreach ($scope in 'User', 'Machine') {
            try { if ([Environment]::GetEnvironmentVariable($envName, $scope)) { $persisted += "$envName ($scope)" } } catch { }
        }
    }
    foreach ($secretName in $settingNames | Where-Object { $_ -match 'oken' }) {
        Remove-Variable -Name $secretName -Scope Script -ErrorAction SilentlyContinue
    }
    Write-Output "Cleared $cleared elastic... setting(s) from the environment"
    if ($persisted.Count -gt 0) {
        Write-Output "WARNING: these are stored permanently on this machine and were NOT removed: $($persisted -join ', ')"
    }
}
###########################################################################################

# ======================================================================================
# Diagnostics helpers (used by the deployment and by the final NEEDS_REVIEW report)
# ======================================================================================

# elastic-agent install redraws a spinner on every tick, which floods the NinjaOne output (and gets
# it cut off before the real error appears). This reads the captured output and prints it without
# the spinner: each install stage once, and JSON log lines as "[level] message".
function Format-ElasticInstallOutput {
    param ([string]$Path, [int]$MaxLines = 60)

    if (-not (Test-Path $Path)) { return }
    $text = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($text)) { return }

    $out = New-Object System.Collections.Generic.List[string]
    $lastStage = $null
    foreach ($raw in ($text -split "[\r\n]+")) {
        $line = $raw.Trim()
        if (-not $line) { continue }
        # spinner frame, e.g. "[  ==] Waiting For Enroll...  [5s]" or "... [1m9s]"
        if ($line -match '^\[[ =]{4}\]\s*(.*?)\s*\[[0-9hms]+\]\s*(.*)$') {
            $stage = $Matches[1]
            $line = $Matches[2].Trim()
            if ($stage -and ($stage -ne $lastStage)) { $out.Add("    $stage"); $lastStage = $stage }
            if (-not $line) { continue }
        }
        # on failure the installer dumps its whole debug log; the useful part is above it
        if ($line -match '^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+(DEBUG|TRACE)\b') { continue }
        if ($line.StartsWith('{')) {
            try {
                $entry = $line | ConvertFrom-Json -ErrorAction Stop
                if ($entry.message) { $out.Add(("    [{0}] {1}" -f $entry.'log.level', $entry.message)); continue }
            } catch { }
        }
        if ($line.Length -gt 400) { $line = $line.Substring(0, 400) + '...' }
        $out.Add("    $line")
    }

    if ($out.Count -le $MaxLines) { $out } else {
        $out | Select-Object -First $MaxLines
        Write-Output "    ... $($out.Count - $MaxLines) more lines omitted"
    }
}

# Lists the processes that are listening on a TCP port (any address, IPv4 or IPv6), one readable string
# each. Parses netstat so it works on every Windows version the script supports. Never throws.
function Get-PortListener {
    param ([int]$Port)
    $found = @()
    try {
        foreach ($line in (netstat.exe -ano 2>$null)) {
            if ($line -match "^\s*TCP\s+(\S+):${Port}\s+\S+\s+LISTENING\s+(\d+)\s*$") {
                $address = $Matches[1]
                $listenerPid = [int]$Matches[2]
                $proc = Get-WmiObject -Class Win32_Process -Filter "ProcessId=$listenerPid" -ErrorAction SilentlyContinue
                $found += "PID $listenerPid $($proc.Name) [$($proc.ExecutablePath)] on ${address}:${Port}"
            }
        }
    } catch { }
    return $found
}

# True when 127.0.0.1:<Port> can actually be bound right now. This is the same operation the agent
# performs, so it also catches ports Windows refuses without a visible listener (excluded port ranges
# reserved by Hyper-V/WinNAT, exclusive binds by another process).
function Test-PortBindable {
    param ([int]$Port)
    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        if ($listener) { try { $listener.Stop() } catch { } }
    }
}

# Returns the first usable port for the agent's local gRPC listener: the default when it is free,
# otherwise the first free one in 6790-6890. Ports in -Exclude (already tried) are skipped.
# Returns $null when nothing is usable.
function Find-FreeAgentGrpcPort {
    param ([int[]]$Exclude = @())
    foreach ($candidate in (@($defaultAgentGrpcPort) + (6790..6890))) {
        if ($Exclude -contains $candidate) { continue }
        if (@(Get-PortListener -Port $candidate).Count -gt 0) { continue }
        if (-not (Test-PortBindable -Port $candidate)) { continue }
        return $candidate
    }
    return $null
}

# Prints what is known about a failed deployment: service state, whether the Fleet server answers,
# Windows service-start errors and the agent's own recent errors. Read-only, and never throws.
function Write-SiemDiagnostics {
    Write-Output "---- UNS SIEM Agent diagnostics ----"

    try {
        $services = @(Get-Service -Name "Elastic Agent", "ElasticEndpoint" -ErrorAction SilentlyContinue)
        if ($services.Count -eq 0) { Write-Output "Services: none installed (the failed install was rolled back or never started)" }
        foreach ($service in $services) { Write-Output "Service '$($service.Name)': $($service.Status)" }
    } catch { Write-Output "Services: could not be read ($($_.Exception.Message))" }

    try {
        $listeners = @(Get-PortListener -Port $defaultAgentGrpcPort)
        if ($listeners.Count -gt 0) {
            foreach ($listener in $listeners) {
                # the agent itself listens on this port when it runs normally, which is not a conflict
                if ($listener -match 'elastic-agent') { Write-Output "Port ${defaultAgentGrpcPort} (agent default) is held by the installed agent itself (normal): $listener" }
                else { Write-Output "Port ${defaultAgentGrpcPort} (agent default) is in use by another program: $listener" }
            }
        } elseif (-not (Test-PortBindable -Port $defaultAgentGrpcPort)) {
            Write-Output "Port ${defaultAgentGrpcPort} (agent default) has no listener but cannot be bound (Windows excluded port range or a security product)"
        }
    } catch { }

    try {
        if (-not (($fleetURL -join '').Trim())) { throw "no fleet URL is set (normal for -UninstallOnly)" }
        $fleetUri = [uri](($fleetURL -join '').Trim())
        $port = if ($fleetUri.Port -gt 0) { $fleetUri.Port } else { 443 }
        $client = New-Object System.Net.Sockets.TcpClient
        $connect = $client.BeginConnect($fleetUri.Host, $port, $null, $null)
        if ($connect.AsyncWaitHandle.WaitOne(5000) -and $client.Connected) {
            Write-Output "Fleet server $($fleetUri.Host):$port is reachable"
        } else {
            Write-Output "Fleet server $($fleetUri.Host):$port is NOT reachable (blocked by firewall/proxy, or DNS problem)"
        }
        $client.Close()
    } catch { Write-Output "Fleet server: reachability check failed ($($_.Exception.Message))" }

    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = (Get-Date).AddMinutes(-30) } -ErrorAction Stop |
            Where-Object { $_.Message -match 'Elastic|UNS SIEM' } | Select-Object -First 5)
        foreach ($event in $events) {
            $message = ($event.Message -replace '\s+', ' ')
            if ($message.Length -gt 300) { $message = $message.Substring(0, 300) }
            Write-Output "Windows service log $($event.TimeCreated.ToString('HH:mm:ss')): $message"
        }
    } catch { }

    try {
        $crashes = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error'; StartTime = (Get-Date).AddMinutes(-30) } -ErrorAction Stop |
            Where-Object { $_.Message -match 'elastic|endpoint-security' } | Select-Object -First 3)
        foreach ($crash in $crashes) {
            $message = ($crash.Message -replace '\s+', ' ')
            if ($message.Length -gt 300) { $message = $message.Substring(0, 300) }
            Write-Output "Application crash $($crash.TimeCreated.ToString('HH:mm:ss')): $message"
        }
    } catch { }

    try {
        $blocks = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117, 1121, 1122; StartTime = (Get-Date).AddMinutes(-30) } -ErrorAction Stop |
            Where-Object { $_.Message -match 'elastic|Elastic' } | Select-Object -First 3)
        foreach ($block in $blocks) {
            $message = ($block.Message -replace '\s+', ' ')
            if ($message.Length -gt 300) { $message = $message.Substring(0, 300) }
            Write-Output "Windows Defender $($block.TimeCreated.ToString('HH:mm:ss')): $message"
        }
    } catch { }

    try {
        # the live log, or the copy the deployment saved before the installer's rollback deleted it
        $logFile = Get-ChildItem -Path "$env:ProgramFiles\Elastic\Agent\data\*\logs\*.ndjson", (Join-Path $env:TEMP "UNSAgent-failure-logs\*.ndjson") -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($logFile) {
            $errors = @(Get-Content -Path $logFile.FullName -Tail 300 -ErrorAction SilentlyContinue | Where-Object { $_ -match '"log.level":"error"' } | Select-Object -Last 6)
            foreach ($errorLine in $errors) {
                try { Write-Output ("Agent log error: " + ($errorLine | ConvertFrom-Json -ErrorAction Stop).message) } catch { Write-Output "Agent log error: $errorLine" }
            }
        }
    } catch { }

    Write-Output "------------------------------------"
}

# ======================================================================================
# Evaluate -> deploy -> re-check
# Without -InstallOnly this script first evaluates the UNS SIEM Agent (same checks, output and
# NinjaOne property as siem-evaluation.ps1). Only when that reports ACTION_REQUIRED does it run the
# deployment portion below - once - in a child PowerShell process (the deployment code calls
# "exit" in many places, which would otherwise end this script before the re-check). After the
# deployment it waits, evaluates one final time and, if the agent is still not compliant, reports
# NEEDS_REVIEW. The child is started with -InstallOnly, which skips this whole block, so the
# deployment can never start another deployment and a run can never loop.
# ======================================================================================
if (-not $InstallOnly) {

    # One deployment at a time: two overlapping runs would share the download folder and fight over the
    # uninstall. A named mutex is held by this process until it exits (a run that was killed releases it too).
    $script:DeploymentMutex = $null
    $lockAcquired = $true
    try {
        $script:DeploymentMutex = New-Object System.Threading.Mutex($false, 'Global\UNS-SIEM-Agent-Deployment')
        try { $lockAcquired = $script:DeploymentMutex.WaitOne(0) }
        catch [System.Threading.AbandonedMutexException] { $lockAcquired = $true }
    } catch {
        Write-Output "WARNING: could not create the deployment lock ($($_.Exception.Message)); continuing without it"
    }
    if (-not $lockAcquired) {
        Write-Output "Another UNS SIEM Agent deployment is already running on this machine; this run does nothing."
        Write-Output "SIEM_AGENT_STATUS: DEPLOYMENT_IN_PROGRESS"
        Clear-ElasticEnvSettings
        exit
    }

    # $defaultVersion (the offline fallback) is set in the settings block at the top of the script.
    try {
        $remoteVersion = (Invoke-RestMethod `
            -Uri "https://raw.githubusercontent.com/unsinc/siemagent/refs/heads/main/agent-version" `
            -UseBasicParsing `
            -ErrorAction Stop).Trim()

        $defaultVersion = [version]$remoteVersion
        Write-Output "Fetched current SIEM Agent version: $defaultVersion"
    }
    catch {
        Write-Output "Failed to fetch current SIEM Agent version - using fallback $defaultVersion"
    }

    # The only source of the required version is the agent-version file on GitHub (the same file the
    # deployment installs), with the hard-coded value above as the offline fallback.
    $requiredVersion = $defaultVersion
    #####################################

    # Fixed, ASCII-only markers for NinjaOne to key its next-task condition on (output contains).
    # Kept separate from the human-readable Write-Output lines below so rewording those later
    # doesn't silently break the automation gate, and to avoid non-ASCII characters, which a
    # no-BOM UTF-8 script can have mangled by Windows PowerShell 5.1's ANSI-codepage file reading.
    $StatusActionRequired = "SIEM_AGENT_STATUS: ACTION_REQUIRED"
    $StatusNeedsReview = "SIEM_AGENT_STATUS: NEEDS_REVIEW"
    $StatusCompliant = "SIEM_AGENT_STATUS: COMPLIANT"

    $agentBinaryPath = "$env:ProgramFiles\Elastic\Agent\elastic-agent.exe"

    # Reports an evaluation outcome: sets the NinjaOne property and prints the status marker, and
    # records the outcome in $script:SiemEvalResult (COMPLIANT or ACTION_REQUIRED) for the caller.
    # On the confirmation check ($Recheck) a failing outcome is recorded silently, so the only
    # failing status the run ever prints after a deployment is the final NEEDS_REVIEW.
    function Set-SiemEvaluationOutcome {
        param ($Property, $Marker, $Result, [switch]$Recheck)
        $script:SiemEvalResult = $Result
        if ($Recheck -and ($Result -ne "COMPLIANT")) { return }
        Ninja-Property-Set siemAgent $Property
        Write-Output $Marker
    }

    # Same checks and console output as siem-evaluation.ps1, except that a broken install or an
    # unreadable version now report ACTION_REQUIRED (they get redeployed) instead of NEEDS_REVIEW.
    function Invoke-SiemEvaluation {
        param ([switch]$Recheck)

        $script:SiemEvalResult = "ACTION_REQUIRED"

        # by the stable service name; the display name "UNS SIEM Agent" is only branding and can be reset
        $siemAgentService = Get-Service -Name 'Elastic Agent' -ErrorAction SilentlyContinue

        if (-not $siemAgentService) {
            Write-Output "UNS SIEM Agent is not installed"
            Set-SiemEvaluationOutcome "Not Installed" $StatusActionRequired "ACTION_REQUIRED" -Recheck:$Recheck
            return
        }

        if (-not (Test-Path $agentBinaryPath)) {
            Write-Output "UNS SIEM Agent service exists but binary is missing"
            Set-SiemEvaluationOutcome "Broken Install" $StatusActionRequired "ACTION_REQUIRED" -Recheck:$Recheck
            return
        }

        # Always query binary version only (daemon may be dead)
        # joined into one string: -notmatch on an array of lines filters it instead of returning a yes/no
        $versionOutput = (@(& $agentBinaryPath version --binary-only 2>$null) -join "`n")

        if ($versionOutput -notmatch 'Binary:\s+([0-9]+\.[0-9]+\.[0-9]+)') {
            Write-Output "UNS SIEM Agent installed, but version could not be parsed"
            Set-SiemEvaluationOutcome "Installed (Version Unknown)" $StatusActionRequired "ACTION_REQUIRED" -Recheck:$Recheck
            return
        }

        $installedVersion = [version]$matches[1]

        # Check daemon health separately (optional but useful)
        $daemonHealthy = $versionOutput -notmatch 'Daemon:\s+<failed'

        # A service that is installed but not running is not compliant. Give it one chance to start.
        $siemAgentService.Refresh()
        if ($siemAgentService.Status -ne 'Running') {
            Write-Output "UNS SIEM Agent service is $($siemAgentService.Status), trying to start it"
            try { Start-Service -InputObject $siemAgentService -ErrorAction Stop } catch { }
            Start-Sleep -Seconds 15
            $siemAgentService.Refresh()
            if ($siemAgentService.Status -ne 'Running') {
                Write-Output "UNS SIEM Agent service is not running"
                Set-SiemEvaluationOutcome "Not Running" $StatusActionRequired "ACTION_REQUIRED" -Recheck:$Recheck
                return
            }
        }

        # Version enforcement
        if ($installedVersion -lt $requiredVersion) {
            Write-Output "UNS SIEM Agent $installedVersion detected - update required"
            Set-SiemEvaluationOutcome "Outdated ($installedVersion)" $StatusActionRequired "ACTION_REQUIRED" -Recheck:$Recheck
        }
        else {
            Write-Output "UNS SIEM Agent is compliant"
            Set-SiemEvaluationOutcome "$installedVersion" $StatusCompliant "COMPLIANT" -Recheck:$Recheck
        }

        # Optional health signal (non-blocking)
        if (-not $daemonHealthy) {
            Write-Output "WARNING: Elastic Agent daemon is not responding"
        }
    }

    function Set-SiemNeedsReview {
        param ($Reason)
        Write-Output $Reason
        Ninja-Property-Set siemAgent "Needs Review"
        Write-Output $StatusNeedsReview
    }

    # 1. Evaluate. Nothing to do unless the agent is missing, broken, unreadable or outdated.
    # -UninstallOnly skips the evaluation: whatever is installed is removed, compliant or not.
    if (-not $UninstallOnly) {
        Invoke-SiemEvaluation
        if ($script:SiemEvalResult -eq "COMPLIANT") { Clear-ElasticEnvSettings; exit }
    }

    # 2. Deploy, once. Forward whatever was passed on the command line to the deployment process.
    if (-not $PSCommandPath) {
        Set-SiemNeedsReview "Cannot start the deployment: script path is unknown (script was not run from a file)"
        Clear-ElasticEnvSettings
        exit 1
    }
    $installArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-InstallOnly')
    foreach ($name in 'token', 'fleetURL', 'datapath', 'tag', 'uninstallToken', 'policy') {
        if ($PSBoundParameters.ContainsKey($name)) { $installArgs += "-$name"; $installArgs += ($PSBoundParameters[$name] -join ',') }
    }
    foreach ($name in 'local', 'insecure', 'UninstallOnly', 'Verbose') {
        if ($PSBoundParameters.ContainsKey($name) -and $PSBoundParameters[$name]) { $installArgs += "-$name" }
    }
    $installArgs += '-TargetVersion'
    $installArgs += $requiredVersion.ToString()
    $powershellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $powershellExe)) { $powershellExe = 'powershell.exe' }

    # Start-Process takes one argument string, so quote every argument (a tag can contain spaces, and
    # a trailing backslash in a path must be doubled or it would escape the closing quote).
    $installArgString = ($installArgs | ForEach-Object {
        '"' + (($_ -replace '(\\+)$', '$1$1') -replace '"', '\"') + '"'
    }) -join ' '

    if ($UninstallOnly) {
        Write-Output "UNINSTALL ONLY: removing the UNS SIEM Agent and Elastic Endpoint, nothing will be installed ($deployTimeoutMinutes minute limit)"
    } else {
        Write-Output "Starting UNS SIEM Agent deployment (single attempt, $deployTimeoutMinutes minute limit)"
    }
    try {
        $deployProcess = Start-Process -FilePath $powershellExe -ArgumentList $installArgString -NoNewWindow -PassThru
        $deployHandle = $deployProcess.Handle  # Cache the process handle so ExitCode is readable after WaitForExit
        if ($deployProcess.WaitForExit([int]($deployTimeoutMinutes * 60 * 1000))) {
            $childExitCode = $deployProcess.ExitCode
            Write-Output "UNS SIEM Agent deployment finished (exit code $childExitCode)"
        }
        else {
            Write-Output "UNS SIEM Agent deployment did not finish within $deployTimeoutMinutes minutes, stopping it"
            if (Get-Command taskkill.exe -ErrorAction SilentlyContinue) {
                & taskkill.exe /PID $deployProcess.Id /T /F *> $null
            } else {
                Stop-Process -Id $deployProcess.Id -Force -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Write-Output "UNS SIEM Agent deployment threw an error: $($_.Exception.Message)"
    }

    # 3a. -UninstallOnly: success means no agent or Endpoint service is left. No re-evaluation, and the
    # siemAgent property is left alone (setting it to "Not Installed" could trigger a reinstall task).
    if ($UninstallOnly) {
        $remaining = @(Get-Service -Name "Elastic Agent", "ElasticEndpoint" -ErrorAction SilentlyContinue)
        if (($remaining.Count -eq 0) -and ($childExitCode -eq 0)) {
            Write-Output "UNS SIEM Agent and Elastic Endpoint are removed from this machine"
            Write-Output "SIEM_AGENT_STATUS: UNINSTALLED"
            Clear-ElasticEnvSettings
            exit
        }
        if ($remaining.Count -gt 0) { Write-Output "Still installed after the uninstall: $(($remaining | ForEach-Object { $_.Name }) -join ', ')" }
        else { Write-Output "No agent service is left, but the uninstall process did not complete cleanly (exit code: $(if ($null -eq $childExitCode) { 'none, timed out' } else { $childExitCode }))" }
        Write-SiemDiagnostics
        Set-SiemNeedsReview "UNS SIEM Agent could not be removed - manual review required (an agent with Tamper Protection needs its uninstall token)"
        Clear-ElasticEnvSettings
        exit 1
    }

    # 3. Confirm, once.
    # The deployment process reports its outcome as an exit code (see Stop-Deployment):
    #   0 finished (the re-check below decides whether the machine is compliant)
    #   1 failed (the re-check below reports the state it left behind)
    #   2 configuration problem, nothing was changed: no point waiting and re-checking
    #   4 new agent installed and running, but a stray old Endpoint could not be removed
    if ($childExitCode -eq 2) {
        Write-Output "UNS SIEM Agent deployment was not started because of a configuration problem (see the missing items above); the existing installation was left untouched"
        Set-SiemNeedsReview "Deployment configuration is incomplete - add the missing script variable(s) listed above and run again"
        Clear-ElasticEnvSettings
        exit 1
    }
    if ($childExitCode -eq 4) {
        Set-SiemNeedsReview "New UNS SIEM Agent installed and running, but a stray old Endpoint could not be removed even after a retry - manual review required"
        Clear-ElasticEnvSettings
        exit 1
    }

    Write-Output "Waiting $recheckDelaySeconds seconds before confirming the deployment"
    Start-Sleep -Seconds $recheckDelaySeconds
    Invoke-SiemEvaluation -Recheck
    if ($script:SiemEvalResult -ne "COMPLIANT") {
        Write-SiemDiagnostics
        Set-SiemNeedsReview "UNS SIEM Agent is still not compliant after deployment - manual review required"
        Clear-ElasticEnvSettings
        exit 1   # non-zero so NinjaOne shows the action as failed, not SUCCESS
    }
    Clear-ElasticEnvSettings
    exit
}

#check if invalid parameter was passed on the console
if($invalid_parameter)
{
    Write-Output "[-] $($invalid_parameter) is not a valid switch. Please type Get-Help .\elastic-agent-installer.ps1"
    throw

}

# check if server is 2012 and apply different policy with no defend, until they update them. 
function check_2012 {
    (get_windows_os_info).Caption -match "2012"
}

# agenda
# 0 - Standalone Workstation
# 1 - Member Workstation
# 2 - Standalone Server
# 3 - Member Server
# 4 - Backup Domain Controller (BDC)
# 5 - Primary Domain Controller (PDC)

# Reads every signal that says whether this is a server or a workstation. DomainRole alone is not
# reliable enough: if the WMI query for it fails (it can on a busy or freshly booted VM) it comes
# back empty, which used to be read as "workstation". The OS's own product type is the authority,
# with the edition name and the registry InstallationType as backups.
function get_windows_os_info {

    if ($script:osInfo) { return $script:osInfo }
    $info = @{ ProductType = $null; InstallationType = $null; Caption = $null; DomainRole = $null }
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        if ($os.ProductType) { $info.ProductType = [int]$os.ProductType }   # 1 workstation, 2 domain controller, 3 server
        $info.Caption = $os.Caption
    } catch { }
    try {
        $version = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $info.InstallationType = $version.InstallationType   # Client, Server, Server Core
        if (-not $info.Caption) { $info.Caption = $version.ProductName }   # backup when the WMI query failed
    } catch { }
    try {
        $domainRole = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).DomainRole
        if ($null -ne $domainRole) { $info.DomainRole = [int]$domainRole }
    } catch { }
    $script:osInfo = $info
    return $info
}

# Works out what kind of machine this is, so the policy / tag functions below can share it.
# Returns: Workstation, Server, HyperV, DomainController or Unknown (no signal could be read at all).
# Server vs workstation is decided by the OS product type first, then the registry InstallationType,
# the edition name and DomainRole, so a server whose DomainRole could not be read is still a server.
# A DC always reports DomainController, even when it also has the Hyper-V role installed.
# The signals and the verdict are kept in $script:roleEvidence for the deployment log.
function get_windows_role_type {

    if ($script:roleType) { return $script:roleType }

    $info = get_windows_os_info
    $isServer = $null
    if ($info.ProductType)                  { $isServer = ($info.ProductType -ne 1) }
    elseif ($info.InstallationType)         { $isServer = ($info.InstallationType -match 'Server') }
    elseif ($info.Caption)                  { $isServer = ($info.Caption -match 'Server') }
    elseif ($null -ne $info.DomainRole)     { $isServer = ($info.DomainRole -ge 2) }

    if ($null -eq $isServer) {
        $type = "Unknown"
    }
    elseif (-not $isServer) {
        $type = "Workstation"
    }
    elseif (($info.ProductType -eq 2) -or ($info.DomainRole -eq 4) -or ($info.DomainRole -eq 5)) {
        $type = "DomainController"
    }
    else {
        # Get-WindowsFeature only exists on Windows Server (and needs ServerManager on 2008 R2),
        # so a failure here just means "not a Hyper-V host" rather than stopping the install.
        try {
            $hypervrole = (Get-WindowsFeature -Name Hyper-V -ErrorAction Stop).InstallState -eq "Installed"
        } catch {
            $hypervrole = $false
        }
        if ($hypervrole) { $type = "HyperV" } else { $type = "Server" }
    }

    $serverByRole = ($null -ne $info.DomainRole) -and ($info.DomainRole -ge 2)
    $note = ""
    if (($null -ne $isServer) -and ($null -ne $info.DomainRole) -and ($isServer -ne $serverByRole)) {
        $note = " - DomainRole disagrees with the OS, trusting the OS"
    }
    # The AD DS service (NTDS) is only present on a domain controller. It is not used to decide the role; it is
    # shown so a log answers "is this really a DC?" without a second visit. A running NTDS that Windows does not
    # report as a domain controller is called out because it should never happen.
    $ntdsService = Get-Service -Name 'NTDS' -ErrorAction SilentlyContinue
    $ntdsText = if ($ntdsService) { "NTDS=$($ntdsService.Status)" } else { 'NTDS=not present' }
    if (($type -ne 'DomainController') -and $ntdsService -and ($ntdsService.Status -eq 'Running')) {
        $note += " - WARNING: the AD DS service is running but Windows does not report a domain controller"
    }
    $script:roleEvidence = "ProductType=$($info.ProductType), InstallationType=$($info.InstallationType), DomainRole=$($info.DomainRole), $ntdsText, OS='$($info.Caption)'$note"
    $script:roleType = $type
    return $type
}

# -policy: Auto (default) picks the policy from the machine's role: servers running Windows Server
# 2012 get the 2012 (no Defend) policy, workstations get Workstations - No Defend only when a
# third-party antivirus is found (see get_thirdparty_av) and Workstations otherwise. NoDefend forces
# the no-Defend policy of the role whatever is detected. Defend stops a workstation from being moved to
# No Defend by the detection (use it if the detection is wrong); it changes nothing for servers.
# Other forces the one extra policy for machines that fit none of the roles. Anything else is rejected.
$policyChoice = ($policy -join '').Trim()
if (-not $policyChoice) { $policyChoice = "Auto" }
if ($policyChoice -notin "Auto", "NoDefend", "Defend", "Other") {
    Write-Output "[-] Invalid -policy value '$policyChoice'. Use Auto, NoDefend, Defend or Other."
    throw "Invalid policy value"
}

# Decides whether a workstation runs a third-party antivirus / EDR (anything other than Microsoft
# Defender), which is when the no-Defend workstation policy is needed. Three independent checks, any
# one of them is enough, so a failing query doesn't hide a product:
#   1. Windows Security Center (root\SecurityCenter2): products other than Defender that are switched on.
#      A registered but switched-off product is ignored, since Security Center keeps stale entries after
#      an uninstall.
#   2. Defender's own running mode: Passive / EDR Block means something else is the main antivirus.
#   3. Known antivirus services (list at the top) that are running.
# Elastic's own registration is excluded: Elastic Defend registers in Security Center and puts Defender
# in passive mode, so on a machine that already has Elastic Endpoint installed, a passive Defender is
# not evidence of a third-party product (and the Elastic entry is skipped), otherwise a re-run would
# flip a machine into the wrong policy. The evidence is kept in $script:avEvidence for the log.
function get_thirdparty_av {

    $found = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[string]
    $endpointInstalled = [bool](Get-Service -Name "ElasticEndpoint" -ErrorAction SilentlyContinue)

    $products = $null
    try {
        $products = @(Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction Stop)
    } catch {
        try {
            $products = @(Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop)
        } catch {
            $notes.Add("Security Center unavailable")
        }
    }
    foreach ($product in $products) {
        $name = [string]$product.displayName
        if ($name -match 'Windows Defender|Microsoft Defender|Elastic|Endgame') { continue }
        # productState bits 12-15: 1 = on, 2 = snoozed, 0 = off
        $state = 0
        try { $state = [int]$product.productState } catch { }
        if (($state -band 0xF000) -eq 0x1000) { $found.Add("Security Center: $name (on)") }
        else { $notes.Add("Security Center: $name registered but not on, ignored") }
    }

    try {
        $mode = [string](Get-MpComputerStatus -ErrorAction Stop).AMRunningMode
        if ($mode -match 'Passive|EDR Block') {
            if ($endpointInstalled) { $notes.Add("Defender is in '$mode' mode, but Elastic Endpoint is installed so that proves nothing") }
            else { $found.Add("Defender running mode: $mode") }
        }
    } catch {
        $notes.Add("Defender mode unavailable")
    }

    try {
        $running = @(Get-Service -Name $thirdPartyAvServices -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" })
        foreach ($service in $running) { $found.Add("AV service running: $($service.Name)") }
    } catch { }

    $script:avEvidence = (@($found) + @($notes)) -join "; "
    if (-not $script:avEvidence) { $script:avEvidence = "no third-party antivirus found" }
    return ($found.Count -gt 0)
}

# Returns the policy this machine belongs to as a name suffix, matching the per-role variables at
# the top ($token<name> / $uninstallToken<name>): Workstation, WorkstationNoDefend, Server,
# ServerNoDefend, HyperV, HyperVNoDefend, DC, DCNoDefend or Other.
function get_policy_name {

    if ($policyChoice -eq "Other") { return "Other" }
    $noDefend = ($policyChoice -eq "NoDefend")

    $type = get_windows_role_type
    if ($type -eq "Unknown") { return "Other" }
    if ($type -eq "Workstation") {
        if ($noDefend) { $script:avEvidence = "-policy NoDefend given"; return "WorkstationNoDefend" }
        if ($policyChoice -eq "Defend") { $script:avEvidence = "-policy Defend given, detection skipped"; return "Workstation" }
        if (get_thirdparty_av) { return "WorkstationNoDefend" }
        return "Workstation"
    }

    if ($type -eq "DomainController") { $name = "DC" } else { $name = $type }
    if ($noDefend -or (check_2012)) { return "${name}NoDefend" }
    return $name
}
$policyName = get_policy_name

# Reads the per-role variable for this machine's policy, e.g. "token" -> $tokenServerNoDefend. Returns
# $null when it is not set. It never falls back to another policy's value: a machine that must not
# get Elastic Defend would otherwise be enrolled in the Defend policy.
function get_policy_value {
    param ([string]$Prefix)
    Get-Variable -Name ($Prefix + $policyName) -ValueOnly -ErrorAction SilentlyContinue
}

# Applied automatically: when no -token / $token was given, use the enrollment token of this
# machine's policy set at the top. An empty value changes nothing.
if (-not $token) { $roleToken = get_policy_value "token"; if ($roleToken) { $token = $roleToken } }

# Returns the agent tags for this machine's role. Edit the tag lists below to change what each role gets.
function check_windows_role_tags {

    switch (get_windows_role_type) {
        "DomainController" { return "Windows, Server, Active Directory" }
        "HyperV"           { return "Windows, Server, HyperV" }
        "Server"           { return "Windows, Server" }
        "Unknown"          { return "Windows" }
        default { return "Windows, Workstation" }
    }
}
# Applied automatically: keeps the tag(s) you set above / passed with -tag and adds the role tags to
# them, e.g. $tag = "Client 1" on a DC becomes "Client 1,Windows,Server,Active Directory".
# Set $disableRoleTags = $true in the hard-coded section at the top to turn this off.
if (-not $disableRoleTags) { $tag = @($tag) + (check_windows_role_tags) }

# Applied automatically: only used when no uninstall token was set above / passed with -uninstallToken.
# It is the token of the policy the machine is enrolled in today, which is the same policy as the
# enrollment token above - so the same -policy applies here.
if (-not $uninstallToken) { $uninstallToken = get_policy_value "uninstallToken" }

# Normalize tags into the single comma-separated string elastic-agent expects for --tag.
# Accepts -tag "a,b", -tag a,b (array) or "a, b" (spaces after commas); tags may contain spaces.
if ($tag) {
    $seenTags = @{}   # hashtable keys are case-insensitive, so "windows" and "Windows" count as one tag
    $tagList = @(($tag -join ',') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $seenTags.ContainsKey($_) -and ($seenTags[$_] = $true) })
    $badTags = @($tagList | Where-Object { $_ -notmatch '^[a-zA-Z0-9_. -]+$' })
    if ($badTags.Count -gt 0) {
        Write-Output "[-] Invalid tag(s): $($badTags -join ', '). Tags may only contain letters, numbers, space, '_', '.' and '-'."
        throw "Invalid tag value"
    }
    $tag = $tagList -join ','
}


# Shows what this run resolved (set / not set only, never the values), so a run that ends up without
# a token can be diagnosed from the NinjaOne log alone.
if ($InstallOnly) {
    Write-Output "Deployment config: role=$(get_windows_role_type) [$script:roleEvidence], policy=$policyName (-policy $policyChoice$(if ($script:avEvidence) { ", AV: $script:avEvidence" })), enrollment token $(if ($token) { 'set' } else { 'NOT SET' }), fleet URL $(if ($fleetURL) { 'set' } else { 'NOT SET' }), uninstall token $(if ($uninstallToken) { 'set' } else { 'not set' }), tags: $(if ($tag) { $tag } else { '<none>' })"
    Write-Output "Settings source: $(if ($script:SettingSources.Count -gt 0) { $script:SettingSources -join ', ' } else { '<none set>' })"
    if ($UninstallOnly) {
        Write-Output "UNINSTALL ONLY mode: nothing will be downloaded or installed. Uninstall token for this machine (policy $policyName): $(if ($uninstallToken) { 'set' } else { 'NOT SET - an agent with Agent Tamper Protection cannot be removed without it' })"
    }
}

# Unattended deployment (started by the evaluation step, with no desktop to show the token form on):
# stop here, before anything on the machine is changed, if the enrollment token or fleet URL is
# missing. Otherwise the token form would wait forever for someone to fill it in. Run from an
# interactive console the form is still shown.
if ($InstallOnly -and (-not $UninstallOnly) -and (-not [Environment]::UserInteractive) -and (-not ($token -and $fleetURL))) {
    # Exit code 2 = configuration problem, nothing was changed. The evaluation step reads it and skips the
    # wait and the re-check, which could only report the same old state again.
    $missingSettings = @()
    if (-not $token)    { $missingSettings += "enrollment token for policy ${policyName}: set $(Get-EnvSettingName "token$policyName") (or $(Get-EnvSettingName 'token') for every role)" }
    if (-not $fleetURL) { $missingSettings += "fleet URL: set $(Get-EnvSettingName 'fleetURL')" }
    Write-Output "[-] Configuration error - the deployment was NOT started and nothing on this machine was changed (it is unattended, so it cannot ask for the missing value)."
    foreach ($missingSetting in $missingSettings) { Write-Output "    Missing $missingSetting" }
    Write-Output "    This machine was detected as role $(get_windows_role_type) and mapped to policy $policyName [$script:roleEvidence]. If that is not the policy it should use, set $(Get-EnvSettingName 'policy') (Auto, NoDefend, Defend or Other) or give the token of the right policy. A token is never borrowed from another policy."
    Clear-ElasticEnvSettings
    exit 2
}

if (($local) -and (-not $datapath)) {
    Write-Verbose "-local was provided without -datapath. dataPath will default to current script location."
    $datapath = (Get-Location)
}

# Check dotnet version installed.
$DotNetVersionKey = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -EA 0 -name Version | Where-Object { $_.PSChildName -match '^(?!Setup)[\d\.]+' } | Select-Object -Property PSChildName, Version | Sort-Object Version -Descending | Select-Object -First 1
$Version = New-Object Version($DotNetVersionKey.Version)
$RequiredVersion = New-Object Version("4.5")


# Masks a secret for logging: first 4 characters, then asterisks. $token is a [string[]], so it is
# flattened to a plain string first (otherwise .Length is the element count, not the character count).
function Get-MaskedSecret {
    param ($Value)
    $text = ($Value -join '')
    if ([string]::IsNullOrEmpty($text)) { return '<none>' }
    if ($text.Length -gt 4) { return $text.Substring(0, 4) + ('*' * ($text.Length - 4)) }
    return '*' * $text.Length
}

# Ends the deployment process with an exit code the parent can trust. A plain "exit <code>" inside the
# deployment's try block is replaced by the "exit $script:deployExitCode" in its finally block (so a failure
# used to reach the parent as 0), which is why the code is stored first. 1 = failed, 2 = configuration problem,
# 4 = new agent fine but a stray old Endpoint could not be removed.
function Stop-Deployment {
    param ([int]$Code = 1)
    $script:deployExitCode = $Code
    exit $Code
}

# Time function
function Get-FormattedDate {
    Get-Date -Format "yyyyMMdd_HHmmss"
    #Possible formats are:
    # "yyyyMMdd_HHmmss"
    # "dddd MM/dd/yyyy HH:mm K"
    # -UFormat "%A %m/%d/%Y %R %Z"
    # For more information see Get-Date - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-date?view=powershell-7.4
}

# Check if the script is running with elevated privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script with elevated privileges
    Write-Output "$(Get-FormattedDate) Administrator privileges required. Please restart as Administrator"
    Start-Sleep 5
    exit 1
}

## setttings ##
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# The agent version is decided once, by the evaluation step, and handed over with -TargetVersion so the version
# that is installed is the version that is checked afterwards. Only when this process is started by hand does it
# look it up itself, falling back to the single default at the top of the script.
$agentVersion = $defaultVersion.ToString()
if ($TargetVersion -match '^\d+\.\d+\.\d+$') {
    $agentVersion = $TargetVersion
} else {
    try {
        $remoteVersion = (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/unsinc/siemagent/refs/heads/main/agent-version" -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop).Content.Trim()
        if ($remoteVersion -match '^\d+\.\d+\.\d+$') {
            $agentVersion = $remoteVersion
        } else {
            Write-Verbose "$(Get-FormattedDate) Remote version format unexpected, using default: $agentVersion"
        }
    } catch {
        Write-Verbose "$(Get-FormattedDate) Could not fetch remote version, using default: $agentVersion"
    }
}
Write-Output "$(Get-FormattedDate) Using Elastic Agent version: $agentVersion"

# Detect processor architecture so the correct Elastic Agent package is downloaded
function Get-AgentArch {
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) {
        $arch = $env:PROCESSOR_ARCHITEW6432
    }
    $script:IsArm64Host = ($arch -eq "ARM64")
    if ($script:IsArm64Host) {
        return "windows-arm64.zip"
    } else {
        return "windows-x86_64.zip"
    }
}
$agentPkg = Get-AgentArch
Write-Output "$(Get-FormattedDate) Detected architecture, using package: $agentPkg"

# Sysmon ships a native ARM64 binary (Sysmon64a.exe); the x64 driver (Sysmon64.exe) cannot
# load on ARM64 Windows since kernel-mode drivers are not covered by WOW64/x64 emulation.
$sysmonExe = if ($IsArm64Host) { "Sysmon64a.exe" } else { "Sysmon64.exe" }
Write-Output "$(Get-FormattedDate) Using Sysmon binary: $sysmonExe"
# Service name the Sysmon binary registers under (Sysmon64.exe -> "Sysmon64", Sysmon64a.exe -> "Sysmon64a").
# Compared by exact name so a stale wrong-architecture "Sysmon64" service is never mistaken for the native one.
$sysmonSvcName = [System.IO.Path]::GetFileNameWithoutExtension($sysmonExe)

# check if fleetURL was passed on the console
if ($fleetURL) {
Write-Verbose "$(Get-FormattedDate) URL is: $fleetURL"
}
# check if token was passed on the console
if ($token) {
Write-Verbose "$(Get-FormattedDate) token is: $(Get-MaskedSecret $token)"
}

# get current location so we can return to it after the deployment.
$currentLocation = Get-Location
$InitialLocation = $currentLocation
Write-Verbose "$(Get-FormattedDate) Initial location is: $($InitialLocation)"

#Perform spelling check and create logpath folder for all further actions.
#Perform spelling check and create logpath folder for all further actions.
[String]$datapath = $datapath -replace '\\\\+', '\'
[String]$datapath = $datapath -replace '\\+$', '\'


if ($datapath) {
    [String]$unsfiles = "UNSFiles\"
    if ($datapath -notlike "*$unsfiles") {
        if ($datapath -like "*\") {
            [String]$datapath = $datapath.Trim(), $unsfiles -join ''
        } else {
            [String]$datapath = $datapath.Trim(), "\", $unsfiles -join ''
        }
    }
    Write-Verbose "$(Get-FormattedDate) Custom data path selected. Log path will be $datapath"
    Write-Output "$(Get-FormattedDate) Custom data path selected. Log path will be $datapath"
    if (Test-Path $datapath) {
        Write-Verbose "$(Get-FormattedDate) $datapath directory exist."
    } else {
        try {
            New-Item -Path $datapath -ItemType Directory -Force -ErrorAction Stop
        }
        catch [System.IO.PathTooLongException] {
            $errorMessage = "File Path too long. Maximum allowed characters 256."
            Write-Error $errorMessage -ErrorAction Stop
            Start-Sleep 5
            Stop-Deployment
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Error "$(Get-FormattedDate) $datapath folder creation failed because of: $errorMessage"
            Start-Sleep 5
            Stop-Deployment
        }
    }
} else {
    [String]$datapath = $env:temp.Trim(), "\UNSFiles\" -join ''
    Write-Verbose -Message "$(Get-FormattedDate) Default LogPath is: $datapath"
    if (Test-Path $datapath) {
        Write-Verbose "$(Get-FormattedDate) $datapath directory exist."
    } else {
        try {
            New-Item -Path $datapath -ItemType Directory -Force -ErrorAction Stop
        }
        catch [System.IO.PathTooLongException] {
            $errorMessage = "Data path too long. Maximum allowed characters 256."
            Write-Error $errorMessage -ErrorAction Stop
            Start-Sleep 5
            Stop-Deployment
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Error "$(Get-FormattedDate) $datapath folder creation failed because of: $errorMessage"
            Start-Sleep 5
            Stop-Deployment
        }
    }
}

#start transcript logging.

$transcriptFilePath = Join-Path -Path $datapath -ChildPath "UNSAgent_Installer_Transcript_$(Get-FormattedDate).txt"
Start-Transcript -Path $transcriptFilePath

# Download folder in case files are being downloaded from internet.
$downloadFolder = $datapath
Write-Verbose -Message "$(Get-FormattedDate) Download Folder is: $downloadFolder"
Write-Output "$(Get-FormattedDate) Download Folder is: $downloadFolder"

#Default Install Directory
$InstallDIR = $env:programfiles + '\UNS SIEM Agent'
if ($UninstallOnly -or (Test-Path $InstallDIR)) {
    "Exist" | Out-Null   # -UninstallOnly must not create anything
} else {
    try {

        New-Item -Path $InstallDIR -ItemType Directory -Force
        Write-Output "Setting up Install DIR to $($InstallDIR)"
        Write-Verbose -Message "$(Get-FormattedDate) Default Installation Directory is: $InstallDIR"
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Output "Creating folders failed because: $errorMessage"
    }
}


# Remove leftovers from Elastic folder
function Remove-ElasticLeftovers {
    param (
        [string]$path
    )

    if (Test-Path -Path $path) {
        #Check what PS version we are using.
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            $items = Get-ChildItem $path -Exclude *.log -Recurse -Force
        } else {
            $items = Get-ChildItem $path -Exclude *.log -Depth 3 -Recurse -Force
        }
		foreach ($item in $items) {
			if (Test-Path $item -PathType Any) {
                Write-Debug "$(Get-FormattedDate) Removing $item." -ErrorAction SilentlyContinue
				Remove-Item -Path $item -Recurse -Force -ErrorAction SilentlyContinue -Exclude "*.log"
			}
		}
        Write-Verbose "$(Get-FormattedDate) Leftovers removed"
    }
}

# Current execution directory (useful to remove leftovers after deployment)
$currentLocation = Get-Location
Write-Verbose -Message "$(Get-FormattedDate) Current location is: $currentLocation"

# In case we want to download the files from google drive, below lines should be uncomment.
# Add your links here in same order.
$originalLinks = @(
    "https://download.sysinternals.com/files/Sysmon.zip"                                                    		## UNS Sysmon File
    "https://raw.githubusercontent.com/unsinc/siemagent/main/files/UNS-Sysmon.xml"                          		## UNS Sysmon Configuration File
    "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$agentVersion-$agentPkg"    	## Elastic elastic-agent
    "https://raw.githubusercontent.com/unsinc/siemagent/main/files/logo.ico"                                		## UNS Logo ico
    "https://raw.githubusercontent.com/unsinc/siemagent/main/files/logo.png"                                		## UNS Logo
)

# Function to modify google drive share links into downloadable format.
function Set-GoogleDriveLink {
    param([string]$originalLink)

    # Check if the link matches the expected pattern
    if ($originalLink -match "https://drive\.google\.com/file/d/(.*?)/view\?usp=drive_link") {
        # Extract the file ID from the link
        $fileId = $Matches[1]

        # Create the modified link
        $modifiedLink = "https://drive.google.com/uc?id=$fileId&export=download&confirm=1"

        return $modifiedLink
    } else {
        return $null
    }
}

$downloadUrls = @()

# Loop through each original URL, apply modification, and store in the new array
foreach ($url in $originalLinks) {
    $modifiedUrl = Set-GoogleDriveLink -originalLink $url
    if ($null -ne $modifiedUrl) {
        $downloadUrls += $modifiedUrl
    } else {
        $downloadUrls += $url
    }	
    Write-Debug "Modified URL: $downloadUrls" -ErrorAction SilentlyContinue
}

$agentFiles = @(
    "Sysmon.zip",
    "UNS-Sysmon.xml",
	"uns-agent.zip",
    "logo.ico",
    "logo.png"
)
$agentPaths = $agentFiles | ForEach-Object { Join-Path $datapath $_ }
foreach ($i in 0..($agentPaths.Length - 1)) {
    Write-Verbose "$(Get-FormattedDate) Agent Path $i : $($agentPaths[$i])" -ErrorAction SilentlyContinue
}

if (-not $UninstallOnly) { Write-Output "$(Get-FormattedDate) Downloading required deployment files, please be patient." }
# WebClient with a time limit: the stock WebClient waits forever on a stalled connection. Timeout covers
# connecting and the first response, ReadWriteTimeout a transfer that stops moving.
if (-not $UninstallOnly) {
    try {
        if (-not ('UnsWebClient' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Net;
public class UnsWebClient : WebClient {
    public int TimeoutMs = 60000;
    protected override WebRequest GetWebRequest(Uri address) {
        WebRequest request = base.GetWebRequest(address);
        request.Timeout = TimeoutMs;
        HttpWebRequest http = request as HttpWebRequest;
        if (http != null) { http.ReadWriteTimeout = TimeoutMs; }
        return request;
    }
}
"@
        }
    } catch {
        Write-Verbose "$(Get-FormattedDate) Could not create the time-limited download client, using the default one: $($_.Exception.Message)"
    }
}

# Function to download files from the internet. Up to 3 attempts; each uses the time-limited client and, if
# that fails, Invoke-WebRequest (also time-limited). An empty file counts as a failed download.
function Get-UNSFiles($downloadUrl, $installPath) {
    # A file left behind (or still locked) by an earlier run makes the download fail with
    # "being used by another process". Clear it first, and stop with a clear message if it is locked.
    if (Test-Path -LiteralPath $installPath) {
        for ($wait = 0; $wait -lt 5; $wait++) {
            try { Remove-Item -LiteralPath $installPath -Force -ErrorAction Stop; break }
            catch { Start-Sleep -Seconds 1 }
        }
        if (Test-Path -LiteralPath $installPath) {
            Write-Error "$(Get-FormattedDate) $installPath is locked by another process and cannot be replaced. Stop whatever holds it (a previous deployment, an antivirus scan) or delete it, then run again."
            exit 1
        }
    }

    $downloadSuccessful = $false
    for ($attempt = 1; ($attempt -le 3) -and (-not $downloadSuccessful); $attempt++) {
        $webClient = $null
        try {
            $webClient = if ('UnsWebClient' -as [type]) { New-Object UnsWebClient } else { New-Object System.Net.WebClient }
            $webClient.DownloadFile($downloadUrl, $installPath)
            $downloadSuccessful = $true
        }
        catch {
            Write-Output "$(Get-FormattedDate) Download attempt $attempt of 3 failed ($($_.Exception.Message)). Trying Invoke-WebRequest."
            try {
                Invoke-WebRequest -Uri $downloadUrl -OutFile $installPath -UseBasicParsing -TimeoutSec 300 -ErrorAction Stop
                $downloadSuccessful = $true
            }
            catch {
                Write-Output "$(Get-FormattedDate) Invoke-WebRequest failed too ($($_.Exception.Message))."
            }
        }
        finally {
            if ($webClient) { try { $webClient.Dispose() } catch { } }
        }

        if ($downloadSuccessful -and ((-not (Test-Path -LiteralPath $installPath)) -or ((Get-Item -LiteralPath $installPath).Length -eq 0))) {
            Write-Output "$(Get-FormattedDate) The download produced an empty file, treating it as failed."
            Remove-Item -LiteralPath $installPath -Force -ErrorAction SilentlyContinue
            $downloadSuccessful = $false
        }
        if ((-not $downloadSuccessful) -and ($attempt -lt 3)) { Start-Sleep -Seconds (5 * $attempt) }
    }

    if (-not $downloadSuccessful) {
        Write-Error "$(Get-FormattedDate) Failed to download $downloadUrl after 3 attempts"
        exit 1
    }
}

# verify if $local
if ($UninstallOnly) {
    Write-Verbose "$(Get-FormattedDate) -UninstallOnly: no files are downloaded"
}
elseif ($local) {
    Write-Verbose "$(Get-FormattedDate) `$local switch provided. Looking for files in $($datapath.TrimEnd('UNSFiles\'))"
    # Get all files in the directory
    $mfiles = Get-ChildItem -Path $($datapath.TrimEnd('UNSFiles\')) -File -ErrorAction SilentlyContinue
    foreach ($tfile in $mfiles) {Move-Item $tfile -Destination $datapath}
    Rename-Item -Path $datapath\$((Get-ChildItem $datapath -Filter *elastic*-agent*).Name) -NewName uns-agent.zip -Force -ErrorAction Stop
}
else {
# Download files in case $data source is not provided.
    for ($i=0; $i -lt $downloadUrls.Length; $i++) {
        Write-Verbose "$(Get-FormattedDate) Downloading $($agentPaths[$i])"
        Get-UNSFiles -downloadUrl $downloadUrls[$i] -installPath $agentPaths[$i]
    }
}

# Create necessary directories

try {
    $directories = if ($UninstallOnly) { @() } else { @("sysmon", "configs") }

    foreach ($dir in $directories) {
        $dirPath = Join-Path -Path $InstallDIR -ChildPath $dir
        if (-not (Test-Path $dirPath)) {
            Write-Output "$(Get-FormattedDate) Creating necessary folders .."
            New-Item -Path $dirPath -ItemType Directory -Force -ErrorAction Stop
            Write-Verbose "$(Get-FormattedDate) $dir folder created successfully."
        } else {
            Write-Verbose "$(Get-FormattedDate) $dir directory exists"
        }
    }
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Error "$(Get-FormattedDate) Folder creation error message: $errorMessage."
    Stop-Deployment
}

Write-Verbose "$(Get-FormattedDate) InstallDIR is $InstallDIR"
# Copy required files to the installation directory
function CopyFilesToDir {
    $retryCount = 0
    do {
        try {
            if (-not (Test-Path "$InstallDIR\sysmon\Sysmon.exe")) {
                Write-Output "$(Get-FormattedDate) $($dirPath) created."
                Write-Verbose "$(Get-FormattedDate) Unzipping $datapath\Sysmon.zip to $InstallDIR\sysmon"

                if ($Version -ge $RequiredVersion) {
                    # Execute the command for .NET Framework 4.5 and above
                    #Check what PS version we are using.
                    if ($PSVersionTable.PSVersion.Major -lt 5) {
                        Write-Verbose "$(Get-FormattedDate) This is PowerShell version less than 5, using .NET framework classes to unpack"
                        Add-Type -assembly "system.io.compression.filesystem"
                        [io.compression.zipfile]::ExtractToDirectory("$datapath\Sysmon.zip", "$InstallDIR\sysmon")
                    } else {
                        Write-Verbose "$(Get-FormattedDate) This is PowerShell version 5 unziping via Expand-Archive"
                        Expand-Archive -Path $datapath\Sysmon.zip -DestinationPath $InstallDIR\sysmon -ErrorAction Stop -Verbose
                    }
                } else {
                    Write-Verbose "$(Get-FormattedDate) DOTNET version is below 4.5 Using COM Shell Application to Expand"
                    # Execute the command for .NET Framework versions below 4.5
                    $shell = New-Object -ComObject Shell.Application
                    $zip = $shell.NameSpace("$datapath\Sysmon.zip")
                    $destination = $shell.NameSpace("$InstallDIR\sysmon")
                    $destination.CopyHere($zip.Items(), 0x10)
                }
                

                # Verify if files were extracted.
                if (Test-Path "$InstallDIR\sysmon\Sysmon.exe") {
                    Write-Verbose "$(Get-FormattedDate) Sysmon copied successfully."
                    Write-Verbose "$(Get-FormattedDate) $sysmonExe copied successfully."
                    $copySuccessful = $true
                } else {
                    Write-Error "$(Get-FormattedDate) Sysmon failed to copy to $($InstallDIR)"
                    $copySuccessful = $false
                    $retryCount++
                }
            } else {
                Write-Verbose "$(Get-FormattedDate) Sysmon files already exist"
                $copySuccessful = $true
            }

            try {
                Copy-Item "$datapath\UNS-Sysmon.xml" -Destination "$InstallDIR\configs\" -ErrorAction Stop
                $copySuccessful = $true
            }
            catch {
                Write-Error "Failed to copy UNS-Sysmon.xml"
                $errorMessage = $_.Exception.Message
                Write-Error "$(Get-FormattedDate) Error copying UNS-Sysmon.xml because: $errorMessage"
                $copySuccessful = $false
                $retryCount++
            }
        }
        catch [System.IO.FileNotFoundException] {
            Write-Output "$(Get-FormattedDate) File not found. Attempting to copy file  again."
            $copySuccessful = $false
            $retryCount++
            Start-Sleep -Seconds 2
        }
        catch {
            Write-Error "Sysmon files copy failed"
            $errorMessage = $_.Exception.Message
            Write-Error "$(Get-FormattedDate) Error copying sysmon files because: $errorMessage"
            $copySuccessful = $false
            $retryCount++
        }
        if (-not $copySuccessful) { Start-Sleep -Seconds 2 }
    } while (-not $copySuccessful -and $retryCount -lt 3)

    if (-not $copySuccessful) {
        Write-Error "$(Get-FormattedDate) Failed to copy Sysmon files after 3 attempts"
        Stop-Deployment
    }
}
# -UninstallOnly downloads nothing and installs nothing, so there is no Sysmon package or config to copy
# and the UNS install folder may not even exist.
if (-not $UninstallOnly) {
    CopyFilesToDir

    # Set current location to the installation directory
    Set-Location -Path $InstallDIR -ErrorAction Stop
    $currentLocation = Get-Location
    Write-Verbose -Message "$(Get-FormattedDate) Setting working location of $(Get-Location)"
}


function Uninstall-Sysmon32 {
    param ()
    Write-Output "$(Get-FormattedDate) Sysmon32 was found, uninstalling" 
    Write-Verbose "$(Get-FormattedDate) Sysmon32 was found, uninstalling"
    try {
        $process = Start-Process -FilePath "$InstallDIR\sysmon\Sysmon.exe" -ArgumentList "-u force"  -NoNewWindow -PassThru
        $handle = $process.Handle  # Cache the process handle
        $process.WaitForExit()
            # Check the exit code
            if ($process.ExitCode -ne 0) {
                throw "Installation failed with exit code $($process.ExitCode)"
            } else {
                Write-Output  "$(Get-FormattedDate) Uninstalling Sysmon32 completed" 
                Write-Verbose "$(Get-FormattedDate) Uninstalling Sysmon32 completed."
                Remove-Item -Path "$InstallDIR\sysmon\Sysmon.exe" -Force -ErrorAction SilentlyContinue
            }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Error "$(Get-FormattedDate) Error while uninstalling Sysmon32: $errorMessage"
        Stop-Deployment
    }
    #destroy the handle cache
    $null = $handle
}

# Returns $true when a wrong-architecture Sysmon64 (x64) registration exists on an ARM64 host:
# a service whose image path is Sysmon64.exe (checked via WMI and the registry, since a service
# marked for deletion can linger in either), or the leftover C:\Windows\Sysmon64.exe itself.
# Sysmon64a (native) never matches: the regex requires "Sysmon64.exe" exactly.
function Test-WrongArchSysmon64Present {
    if (-not $IsArm64Host) { return $false }
    $svc = Get-WmiObject -Class Win32_Service -Filter "Name='Sysmon64'" -ErrorAction SilentlyContinue
    if ($svc -and ($svc.PathName -match '(?i)Sysmon64\.exe')) { return $true }
    $reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64' -ErrorAction SilentlyContinue
    if ($reg -and ($reg.ImagePath -match '(?i)Sysmon64\.exe')) { return $true }
    return (Test-Path -LiteralPath "$env:SystemRoot\Sysmon64.exe")
}

# Last-resort removal of the stale x64 "Sysmon64" registration and binary when "Sysmon64.exe -u"
# fails (e.g. exit code 5 / access denied). Deliberately never touches the "SysmonDrv" driver
# service: the x64 and native builds share that name, so on a host where the native Sysmon is
# already running it belongs to the working install.
function Remove-StaleSysmon64Registration {
    param ()
    if (Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue) {
        & sc.exe stop Sysmon64 | Out-Null
        $null = & sc.exe delete Sysmon64
        if ($LASTEXITCODE -eq 1072) {
            Write-Output "$(Get-FormattedDate) Stale Sysmon64 service is marked for deletion; it will be removed after a reboot"
        } elseif ($LASTEXITCODE -ne 0) {
            Write-Output "$(Get-FormattedDate) sc.exe delete Sysmon64 failed with exit code $LASTEXITCODE"
        }
    }
    $staleExe = "$env:SystemRoot\Sysmon64.exe"
    if (Test-Path -LiteralPath $staleExe) {
        Remove-Item -LiteralPath $staleExe -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $staleExe) {
            Write-Output "$(Get-FormattedDate) Could not delete $staleExe (in use or protected)"
        }
    }
}

# Function to remove a wrong-architecture Sysmon64 (x64) driver left over on an ARM64 host,
# e.g. from before native ARM64 support was added, so it can be replaced with Sysmon64a.exe.
# Kernel-mode drivers cannot run under WOW64/x64 emulation, so an x64 Sysmon64 install on
# ARM64 is never actually functional. Exit code of "-u force" is not trusted on its own: the
# result is verified afterwards and a manual cleanup is attempted if anything is left behind.
# If the native Sysmon is already running, "-u force" is skipped entirely (it would also tear
# down the shared SysmonDrv driver) and only the stale registration is cleaned up.
# Errors here are logged but not fatal so the caller can continue.
function Uninstall-Sysmon64WrongArch {
    param ()
    Write-Output "$(Get-FormattedDate) Wrong-architecture Sysmon64 (x64) found on ARM64 host, removing it in favour of native $sysmonExe"
    Write-Verbose "$(Get-FormattedDate) Wrong-architecture Sysmon64 (x64) found on ARM64 host, removing it in favour of native $sysmonExe"

    $native = Get-Service -Name $sysmonSvcName -ErrorAction SilentlyContinue
    if ($native -and $native.Status -eq 'Running') {
        Write-Output "$(Get-FormattedDate) Native $sysmonSvcName is already running, cleaning up only the stale Sysmon64 registration (SysmonDrv left untouched)"
        Remove-StaleSysmon64Registration
    } else {
        try {
            $process = Start-Process -FilePath "$InstallDIR\sysmon\Sysmon64.exe" -ArgumentList "-u force" -NoNewWindow -PassThru
            $handle = $process.Handle  # Cache the process handle
            $process.WaitForExit()
            if ($process.ExitCode -ne 0) {
                throw "Uninstall failed with exit code $($process.ExitCode)"
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Output "$(Get-FormattedDate) Sysmon64 -u force reported a problem: $errorMessage. Attempting manual cleanup."
        }
        #destroy the handle cache
        $null = $handle

        if (Test-WrongArchSysmon64Present) {
            Remove-StaleSysmon64Registration
        }
    }

    if (Test-WrongArchSysmon64Present) {
        Write-Error "$(Get-FormattedDate) Wrong-architecture Sysmon64 could not be fully removed (service/file still present). A reboot and re-run may be required."
    } else {
        Write-Output "$(Get-FormattedDate) Wrong-architecture Sysmon64 removed"
        Write-Verbose "$(Get-FormattedDate) Wrong-architecture Sysmon64 removed."
    }
}

# Verifies the Sysmon service this script is supposed to leave behind is actually running.
# Waits briefly because the service may still be starting right after "-i". Sets $script:SysmonHealthy.
function Test-Sysmon64Health {
    param ()
    $running = $false
    for ($i = 0; $i -lt 10 -and -not $running; $i++) {
        $svc = Get-Service -Name $sysmonSvcName -ErrorAction SilentlyContinue
        $running = ($svc -and $svc.Status -eq 'Running')
        if (-not $running) { Start-Sleep -Seconds 1 }
    }
    $drv = Get-Service -Name 'SysmonDrv' -ErrorAction SilentlyContinue
    $drvRunning = ($drv -and $drv.Status -eq 'Running')

    if ($running -and $drvRunning) {
        Write-Output "$(Get-FormattedDate) Sysmon health check passed: $sysmonSvcName and SysmonDrv are running"
    } else {
        Write-Error "$(Get-FormattedDate) Sysmon health check failed: $sysmonSvcName running=$running, SysmonDrv running=$drvRunning"
    }
    if (Test-WrongArchSysmon64Present) {
        Write-Output "$(Get-FormattedDate) Warning: stale wrong-architecture Sysmon64 registration is still present on this host"
    }
    # Result goes in a script-scope flag, not the pipeline: the Write-Output lines above would pollute a return value.
    $script:SysmonHealthy = [bool]($running -and $drvRunning)
}

# Uninstall Perch
function Uninstall-Perch {
    param()
    $arguments = "/X {18B16389-F8F8-4E48-9E78-A043D5742B99} /qn"
        try {
            Write-Verbose "$(Get-FormattedDate) Uninstalling Perch agent"
            Write-Output "$(Get-FormattedDate) Uninstalling Perch agent"
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "$arguments" -NoNewWindow -PassThru
            $handle = $process.Handle  # Cache the process handle
            $process.WaitForExit()

            # Check the exit code
            # 0 = removed, 3010/1641 = removed and a reboot is pending, 1605 = it was not installed (all fine)
            if ($process.ExitCode -notin 0, 3010, 1641, 1605) {
                throw "Perch uninstall failed with exit code $($process.ExitCode)"
            } else {
                Write-Verbose "$(Get-FormattedDate) Perch uninstall completed (exit code $($process.ExitCode))."
            }

        } catch {
                $errorMessage = $_.Exception.Message
                Write-Error "$(Get-FormattedDate) Error while uninstalling Perch: $errorMessage"
                Stop-Deployment
            }
            #destroy the handle cache
            $null = $handle
}

# Function to install Sysmon64 and configure it
function Install-Sysmon64 {
    param ()
    Write-Output "$(Get-FormattedDate) Installing Sysmon64"
    try {
        $process = Start-Process -FilePath "$InstallDIR\sysmon\$sysmonExe" -ArgumentList "-accepteula -i" -NoNewWindow -PassThru
        $handle = $process.Handle  # Cache the process handle
        $process.WaitForExit()

        # Check the exit code
        if ($process.ExitCode -ne 0) {
            throw "Installation failed with exit code $($process.ExitCode)"
        } else {
            Write-Output "$(Get-FormattedDate) Installation of Sysmon64 is complete" 
            Write-Verbose "$(Get-FormattedDate) Installation of Sysmon64 is complete"
        }

    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Error "$(Get-FormattedDate) Error while installing Sysmon64: $errorMessage"
    }
    #destroy the handle cache
    $null = $handle

}

# Function to configure running Sysmon64
function Set-Sysmon64 {
    param ([string]$ExePath = "$InstallDIR\sysmon\$sysmonExe")
    # Exact name: the ARM64 driver (Sysmon64a.exe) registers as service "Sysmon64a", not "Sysmon64",
    # and a wildcard would also match a stale wrong-architecture "Sysmon64" service.
    $sysmon64 = Get-Service -Name $sysmonSvcName -ErrorAction SilentlyContinue
    if ($sysmon64) {
        try {
            Write-Output  "$(Get-FormattedDate) Setting the configuration for Sysmon64."
            $process = Start-Process -FilePath $ExePath -ArgumentList "-c `"$InstallDIR\configs\UNS-Sysmon.xml`"" -NoNewWindow -PassThru
            $handle = $process.Handle  # Cache the process handle
            $process.WaitForExit()

            # Check the exit code
            if ($process.ExitCode -ne 0) {
                throw "Installation failed with exit code $($process.ExitCode)"
            } else {
                Write-Output "$(Get-FormattedDate) Configuration of Sysmon64 is complete" 
                Write-Verbose "$(Get-FormattedDate) Configuration of Sysmon64 is complete"
                # remember which config was applied, so a later run can tell whether the downloaded one is new
                try {
                    (Get-FileHash -Algorithm SHA256 -LiteralPath "$InstallDIR\configs\UNS-Sysmon.xml" -ErrorAction Stop).Hash |
                        Set-Content -Path "$InstallDIR\configs\UNS-Sysmon.applied.sha256" -ErrorAction Stop
                } catch {
                    Write-Verbose "$(Get-FormattedDate) Could not record the applied Sysmon config hash: $($_.Exception.Message)"
                }
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Error "$(Get-FormattedDate) Error while setting Sysmon64 config: $errorMessage"
        }
        #destroy the handle cache
        $null = $handle 

    } else {
        Write-Error "$(Get-FormattedDate) Sysmon64 was not found on the system" 
        Write-Verbose "$(Get-FormattedDate) Sysmon64 was not found on the system"
        Stop-Deployment
    }
}

# Sysmon that is already installed keeps whatever configuration it has. This applies the UNS config again
# when the config downloaded in this run differs from the one this script last applied (or when this script
# never applied one), using the Sysmon binary the installed service runs from so versions always match.
function Update-Sysmon64ConfigIfChanged {
    $config = "$InstallDIR\configs\UNS-Sysmon.xml"
    $marker = "$InstallDIR\configs\UNS-Sysmon.applied.sha256"
    if (-not (Test-Path -LiteralPath $config)) { Write-Output "$(Get-FormattedDate) No Sysmon config file to apply"; return }
    $newHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $config).Hash
    $appliedHash = if (Test-Path -LiteralPath $marker) { ((Get-Content -Path $marker -Raw -ErrorAction SilentlyContinue) + '').Trim() } else { '' }
    if ($newHash -eq $appliedHash) {
        Write-Verbose "$(Get-FormattedDate) Sysmon config is unchanged since it was last applied"
        return
    }
    Write-Output "$(Get-FormattedDate) Sysmon is installed but the UNS config has changed (or was never applied by this script), applying it"
    $installedExe = Join-Path $env:SystemRoot $sysmonExe
    if (Test-Path -LiteralPath $installedExe) { Set-Sysmon64 -ExePath $installedExe } else { Set-Sysmon64 }
}

# Function to popup token form
function Show-TokenForm {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Create a form
    $form = New-Object Windows.Forms.Form
    $form.Text = 'UNS SIEM Agent'
    $form.Size = New-Object Drawing.Size @(350, 230)
    $form.StartPosition = 'CenterScreen'
    # Set FormBorderStyle to FixedDialog
    $form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedDialog

    # Set UNS form icon
    if (Test-Path $agentPaths[3]) {
        $icon = New-Object System.Drawing.Icon $agentPaths[3]
        $form.Icon = $icon
    }

    # Create a UNS logo
    $logoBox = New-Object Windows.Forms.PictureBox
    $logoBox.Image = [System.Drawing.Image]::FromFile($agentPaths[4])
    $logoBox.Location = New-Object Drawing.Point @(20, 35)
    $logoBox.Size = New-Object Drawing.Size @(80, 100)
    $form.Controls.Add($logoBox)

    if ($token) {
        Write-Verbose "$(Get-FormattedDate) Token already provided"
    } else {
    # Create a label for primary input
    $label = New-Object Windows.Forms.Label
    $label.Location = New-Object Drawing.Point @(120, 20)
    $label.Size = New-Object Drawing.Size @(200, 20)
    $label.Text = 'Please provide enrollment token'
    $form.Controls.Add($label)

    # Create a primary text box
    $textBox = New-Object Windows.Forms.TextBox
    $textBox.Location = New-Object Drawing.Point @(120, 50)
    $textBox.Size = New-Object Drawing.Size @(200, 20)
    $form.Controls.Add($textBox)
    }
    if ($fleetURL) {
        Write-Verbose "$(Get-FormattedDate) fLeetURL already provided"
    } else {
    # Create a label for secondary input
    $label2 = New-Object Windows.Forms.Label
    $label2.Location = New-Object Drawing.Point @(120, 80)
    $label2.Size = New-Object Drawing.Size @(200, 20)
    $label2.Text = 'Please provide Fleet URL'
    $form.Controls.Add($label2)

    # Create a secondary text box
    $textBox2 = New-Object Windows.Forms.TextBox
    $textBox2.Location = New-Object Drawing.Point @(120, 110)
    $textBox2.Size = New-Object Drawing.Size @(200, 20)
    $form.Controls.Add($textBox2)
    }

    # Create an OK button
    $okButton = New-Object Windows.Forms.Button
    $okButton.Location = New-Object Drawing.Point @(120, 140)
    $okButton.Size = New-Object Drawing.Size @(75, 23)
    $okButton.Text = 'OK'
    $okButton.DialogResult = [Windows.Forms.DialogResult]::OK
    $form.Controls.Add($okButton)

    # Create a Cancel button
    $cancelButton = New-Object Windows.Forms.Button
    $cancelButton.Location = New-Object Drawing.Point @(205, 140)
    $cancelButton.Size = New-Object Drawing.Size @(75, 23)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($cancelButton)

    # Show the form and return an array with both inputs
    $result = $form.ShowDialog()
    if ($result -eq [Windows.Forms.DialogResult]::OK) {
        if (($fleetURL) -and (-not $token)) {
            return $textBox.Text
        } elseif (($token) -and (-not $fleetURL)) {
            return $textBox2.Text
        } else {
            $inputs = @($textBox.Text, $textBox2.Text)
            return $inputs
        }
    }
    return $null
}

# Stops every process running from the Elastic install folder (the agent, Endpoint and the beats it
# spawns) and deletes the install folders. Their open files are what makes a half-removed install
# fail the next one. Only call this once the services are gone or being forced out.
function Remove-ElasticInstallFiles {
    $elasticRoot = Join-Path $env:ProgramFiles "Elastic"
    $leftoverProcs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -like "$elasticRoot\*" })
    foreach ($proc in $leftoverProcs) {
        Write-Verbose "$(Get-FormattedDate) Stopping leftover process $($proc.Name) (PID $($proc.Id))"
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
    if ($leftoverProcs.Count -gt 0) { Start-Sleep -Seconds 2 }
    foreach ($dir in @((Join-Path $elasticRoot "Agent"), (Join-Path $elasticRoot "Endpoint"))) {
        if (Test-Path -LiteralPath $dir) {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $dir) { Write-Output "$(Get-FormattedDate) Could not fully remove $dir (files still in use)" }
            else { Write-Verbose "$(Get-FormattedDate) Removed leftover $dir" }
        }
    }
}

# Runs elastic-agent uninstall with a time limit and prints its output without the progress spinner.
# Returns the exit code, or $null when it had to be stopped for running longer than the limit.
function Invoke-ElasticAgentUninstallProcess {
    param ([string]$ExePath, [string]$Arguments, [int]$TimeoutMinutes = 5, [string]$Label = "elastic-agent uninstall", [switch]$Quiet)

    $outFile = Join-Path $env:TEMP "uns-elastic-uninstall-out.txt"
    $errFile = Join-Path $env:TEMP "uns-elastic-uninstall-err.txt"
    Remove-Item -Path $outFile, $errFile -Force -ErrorAction SilentlyContinue
    $process = Start-Process -FilePath $ExePath -ArgumentList $Arguments -NoNewWindow -PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    $handle = $process.Handle  # Cache the process handle so ExitCode is readable after WaitForExit
    $exitCode = $null
    if ($process.WaitForExit($TimeoutMinutes * 60 * 1000)) {
        $exitCode = $process.ExitCode
    } else {
        Write-Output "$(Get-FormattedDate) $Label did not finish within $TimeoutMinutes minutes, stopping it"
        if (Get-Command taskkill.exe -ErrorAction SilentlyContinue) { & taskkill.exe /PID $process.Id /T /F *> $null }
        else { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    }
    $null = $handle

    # The uninstaller can echo its own command line (a rejected option is printed back with its value):
    # never let an uninstall token reach the log.
    foreach ($tokenText in @(Get-UninstallTokenCandidates)) {
        foreach ($file in @($outFile, $errFile)) {
            if ((Test-Path $file) -and ((Get-Item $file).Length -gt 0)) {
                $content = Get-Content -Path $file -Raw -ErrorAction SilentlyContinue
                if ($content -and $content.Contains($tokenText)) {
                    Set-Content -Path $file -Value $content.Replace($tokenText, '<uninstall token>') -ErrorAction SilentlyContinue
                }
            }
        }
    }
    # Kept for the caller (already free of tokens): it decides from the text whether another token is worth a try.
    $script:UninstallOutputText = ((Get-Content -Path $outFile -Raw -ErrorAction SilentlyContinue) + "`n" + (Get-Content -Path $errFile -Raw -ErrorAction SilentlyContinue))
    if ($Quiet) {
        # a retry with another token: one line instead of the whole uninstaller log
        $reason = ''
        if ($null -ne $exitCode -and $exitCode -ne 0) {
            $reasonLine = ($script:UninstallOutputText -split "`r?`n" | Where-Object { $_ -match 'Invalid uninstall token|uninstall token|error' } | Select-Object -First 1)
            if ($reasonLine) { $reason = ' - ' + ($reasonLine.Trim() -replace '\s+', ' '); if ($reason.Length -gt 170) { $reason = $reason.Substring(0, 170) + '...' } }
        }
        Write-Output "$(Get-FormattedDate) $Label finished with exit code $(if ($null -eq $exitCode) { '<timed out>' } else { $exitCode })$reason"
    } else {
        Write-Output "$(Get-FormattedDate) $Label finished with exit code $(if ($null -eq $exitCode) { '<timed out>' } else { $exitCode }). Uninstaller output:"
        Format-ElasticInstallOutput $outFile
        if ((Test-Path $errFile) -and ((Get-Item $errFile).Length -gt 0)) {
            Write-Output "    Uninstaller error output:"
            Format-ElasticInstallOutput $errFile
        }
    }
    Remove-Item -Path $outFile, $errFile -Force -ErrorAction SilentlyContinue
    $script:UninstallExitCode = $exitCode
}

# Every uninstall token this machine could need, most likely first: the one given with -uninstallToken /
# for this machine's policy, then the token of each other policy. An Endpoint left behind by an earlier
# install belongs to the policy it was last enrolled in, which is not necessarily the policy this run
# enrolls into, so its uninstall token may be any of them. A wrong token is simply refused.
function Get-UninstallTokenCandidates {
    return @(Get-UninstallTokenSources | ForEach-Object { $_.Token })
}

# The same candidates, each with where it came from (a policy name, never the token itself), so a log can
# say which policy's token finally worked. Duplicate values are listed once, under the first source.
function Get-UninstallTokenSources {
    $sources = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $own = ($uninstallToken -join '').Trim()
    if ($own) {
        $sources.Add([pscustomobject]@{ Token = $own; Source = "this machine's policy ($policyName)" })
        $seen[$own] = $true
    }
    foreach ($roleName in 'Workstation', 'WorkstationNoDefend', 'Server', 'ServerNoDefend', 'HyperV', 'HyperVNoDefend', 'DC', 'DCNoDefend', 'Other') {
        $value = (@(Get-Variable -Name "uninstallToken$roleName" -ValueOnly -ErrorAction SilentlyContinue) -join '').Trim()
        if ($value -and -not $seen.ContainsKey($value)) {
            $sources.Add([pscustomobject]@{ Token = $value; Source = "policy $roleName" })
            $seen[$value] = $true
        }
    }
    return $sources.ToArray()
}

# Removes the Elastic Endpoint (Elastic Defend) with its own uninstaller:
#   & "C:\Program Files\Elastic\Endpoint\elastic-endpoint.exe" uninstall --uninstall-token <token>
# This is the only thing that removes an Endpoint whose Elastic Agent is gone. Note the token is a
# separate argument: elastic-endpoint.exe rejects the --uninstall-token=<token> form ("Unknown option").
# Tries every candidate token and stops at the first that removes the service. Never touches the
# Elastic Agent. Returns $true when the ElasticEndpoint service is gone.
function Invoke-ElasticEndpointUninstall {
    $endpointExe = Join-Path $env:ProgramFiles "Elastic\Endpoint\elastic-endpoint.exe"
    if (-not (Test-Path -LiteralPath $endpointExe)) {
        Write-Output "$(Get-FormattedDate) $endpointExe not found, cannot run the Endpoint's own uninstaller"
        return ($null -eq (Get-Service -Name "ElasticEndpoint" -ErrorAction SilentlyContinue))
    }
    $attempts = @(Get-UninstallTokenCandidates | ForEach-Object { "uninstall --uninstall-token $_" })
    $attempts += "uninstall"   # last: an Endpoint without tamper protection needs no token
    $number = 0
    foreach ($arguments in $attempts) {
        $number++
        $what = if ($arguments -eq "uninstall") { "no token" } else { "uninstall token $($number) of $($attempts.Count - 1)" }
        $script:UninstallExitCode = $null
        Invoke-ElasticAgentUninstallProcess -ExePath $endpointExe -Arguments $arguments -Label "elastic-endpoint uninstall ($what)"
        if ($script:UninstallExitCode -eq 0) {
            $state = Wait-ElasticServicesGone -TimeoutSeconds 20
            if (-not $state.EndpointPresent) {
                Write-Output "$(Get-FormattedDate) Elastic Endpoint removed with its own uninstaller ($what)"
                return $true
            }
        }
    }
    return $false
}

# Polls until neither the "Elastic Agent" nor "ElasticEndpoint" service exists, or
# TimeoutSeconds elapses. A service marked for deletion can briefly remain visible, and a
# tamper-protected service may not go away at all, so this is checked instead of assumed.
# Shared by Remove-ExistingElasticAgent and the post-install recovery retry in
# Install-ElasticAgent, so both report removal the same way.
function Wait-ElasticServicesGone {
    param ([int]$TimeoutSeconds = 30)
    $elapsed = 0
    while ((($null -ne (Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue)) -or ($null -ne (Get-Service -Name "ElasticEndpoint" -ErrorAction SilentlyContinue))) -and ($elapsed -lt $TimeoutSeconds)) {
        Start-Sleep -Seconds 2
        $elapsed += 2
    }
    return @{
        AgentPresent    = $null -ne (Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue)
        EndpointPresent = $null -ne (Get-Service -Name "ElasticEndpoint" -ErrorAction SilentlyContinue)
    }
}

# Function to cleanly remove a pre-existing Elastic Agent / Elastic Endpoint installation
# before redeploying. When the Elastic Defend integration is enabled on the agent's policy,
# Fleet installs a second, independent Windows service ("ElasticEndpoint" / "Elastic Endpoint")
# for endpoint-security.exe, in addition to the "Elastic Agent" service. That Endpoint service
# self-protects its process/service/files, and if the policy has Agent Tamper Protection
# enabled, it protects the "Elastic Agent" service too - so a raw Stop-Service/sc.exe delete
# against just "Elastic Agent" can silently no-op, leaving Endpoint running, files locked, and
# the next install/rename broken. Prefer the vendor-supported "elastic-agent.exe uninstall",
# which tears down Agent + Endpoint together and accepts --uninstall-token for tamper-protected
# policies; fall back to manual service removal (covering both services) only if that binary
# can't be found, and verify removal instead of assuming success.
function Remove-ExistingElasticAgent {
    param ()

    $script:OldEndpointSurvivedCleanup = $false
    $script:OldAgentSurvivedCleanup = $false

    $agentService = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
    $endpointService = Get-Service -Name "ElasticEndpoint" -ErrorAction SilentlyContinue

    if (($null -eq $agentService) -and ($null -eq $endpointService)) {
        Write-Verbose "$(Get-FormattedDate) No existing Elastic Agent/Endpoint services found."
        # a rolled-back or interrupted install can leave files and processes behind without any service
        Remove-ElasticInstallFiles
        return
    }

    Write-Output "$(Get-FormattedDate) Existing Elastic Agent/Endpoint installation detected, removing before redeployment, please wait"
    $existingAgentExe = Join-Path $env:ProgramFiles "Elastic\Agent\elastic-agent.exe"
    $uninstalled = $false

    if (Test-Path $existingAgentExe) {
        try {
            # An installed agent belongs to the policy it was last enrolled in, which is not necessarily the
            # policy this run enrolls into, and an uninstall token only fits its own policy. So: the token for
            # this machine's policy first, then the token of every other policy that has one, then one attempt
            # without a token (an agent without Tamper Protection needs none). Only a refusal that is about the
            # token leads to the next attempt; any other failure stops here and the fallback below takes over.
            $tokenSources = @(Get-UninstallTokenSources)
            $attempts = @()
            foreach ($source in $tokenSources) {
                $attempts += [pscustomobject]@{ Arguments = "uninstall --force --uninstall-token=$($source.Token)"; Label = "elastic-agent uninstall (token of $($source.Source))" }
            }
            $attempts += [pscustomobject]@{ Arguments = "uninstall --force"; Label = "elastic-agent uninstall (no token)" }
            Write-Verbose "$(Get-FormattedDate) Running supported uninstall via $existingAgentExe"

            $attemptNumber = 0
            $installedPolicyShown = $false
            $stoppedForOtherReason = $false
            $lastExitText = ''
            foreach ($attempt in $attempts) {
                $attemptNumber++
                $script:UninstallExitCode = $null
                $script:UninstallOutputText = ''
                # the first attempt prints the whole uninstaller log, later ones a single line each
                Invoke-ElasticAgentUninstallProcess -ExePath $existingAgentExe -Arguments $attempt.Arguments -Label "$($attempt.Label) [attempt $attemptNumber of $($attempts.Count)]" -Quiet:($attemptNumber -gt 1)
                if ($script:UninstallExitCode -eq 0) {
                    Write-Output "$(Get-FormattedDate) Existing Elastic Agent/Endpoint uninstalled successfully$(if ($attemptNumber -gt 1) { " (accepted: $($attempt.Label -replace '^elastic-agent uninstall \(', '' -replace '\)$', ''))" })"
                    $uninstalled = $true
                    break
                }
                $lastExitText = if ($null -eq $script:UninstallExitCode) { 'timed out' } else { "exit code $($script:UninstallExitCode)" }

                if ((-not $installedPolicyShown) -and ($script:UninstallOutputText -match "Policy \(id ([0-9a-fA-F-]+)\) '([^']+)'")) {
                    Write-Output "$(Get-FormattedDate) The installed agent is enrolled in policy '$($Matches[2])' (id $($Matches[1])); this run enrolls into policy $policyName"
                    $installedPolicyShown = $true
                }
                if (($null -eq $script:UninstallExitCode) -or ($script:UninstallOutputText -notmatch 'uninstall token|tamper')) {
                    Write-Output "$(Get-FormattedDate) The uninstall failed for a reason other than the token, not trying other tokens"
                    $stoppedForOtherReason = $true
                    break
                }
            }
            if (-not $uninstalled) {
                if ($tokenSources.Count -eq 0) {
                    Write-Output "$(Get-FormattedDate) WARNING: elastic-agent uninstall failed ($lastExitText). If Agent Tamper Protection is enabled on this agent's policy, set the uninstall token ($(Get-EnvSettingName 'uninstallToken') or $(Get-EnvSettingName "uninstallToken$policyName"))."
                } elseif ($stoppedForOtherReason) {
                    Write-Output "$(Get-FormattedDate) WARNING: elastic-agent uninstall failed ($lastExitText) and the failure is not about the uninstall token; using the fallback removal."
                } else {
                    Write-Output "$(Get-FormattedDate) WARNING: elastic-agent uninstall failed ($lastExitText) after $attemptNumber attempt(s), none of the $($tokenSources.Count) known uninstall token(s) was accepted; using the fallback removal."
                }
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Error "$(Get-FormattedDate) elastic-agent uninstall threw an error: $errorMessage"
        }
    } else {
        Write-Verbose "$(Get-FormattedDate) $existingAgentExe not found, cannot use supported uninstall path. Falling back to manual service removal."
    }

    # An Endpoint with no Elastic Agent in front of it (or one the agent uninstall did not take with it)
    # is removed with its own uninstaller, trying every known uninstall token.
    if (Get-Service -Name "ElasticEndpoint" -ErrorAction SilentlyContinue) {
        $uninstalled = (Invoke-ElasticEndpointUninstall) -and ($null -eq (Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue))
    }

    # Manual fallback / safety net: covers the case where the supported uninstall wasn't
    # available or didn't fully clear both services.
    if (-not $uninstalled) {
        foreach ($svcName in @("ElasticEndpoint", "Elastic Agent")) {
            if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
                Write-Verbose "$(Get-FormattedDate) Manually stopping and deleting service '$svcName'"
                try {
                    Stop-Service -Name $svcName -Force -Confirm:$false -ErrorAction SilentlyContinue
                } catch {}
                sc.exe delete "$svcName" | Out-Null
            }
        }
        # Without the supported uninstall nothing else stops the agent's processes or frees its files.
        Remove-ElasticInstallFiles
    }

    # Verify removal instead of assuming success - a service marked for deletion can briefly
    # remain visible, and a tamper-protected service may not actually go away at all.
    $removalState = Wait-ElasticServicesGone
    $script:OldEndpointSurvivedCleanup = $removalState.EndpointPresent
    $script:OldAgentSurvivedCleanup = $removalState.AgentPresent

    if ($removalState.AgentPresent -or $removalState.EndpointPresent) {
        # NOT a terminating error (this used to be Write-Error ... -ErrorAction Stop): a
        # tamper-protected Endpoint commonly survives both the supported uninstall and the
        # manual fallback above, and aborting here used to skip the new-agent install
        # entirely - the catch block in Install-ElasticAgent would exit 1 before
        # elastic-agent.exe install ever ran, leaving the machine with a half-removed
        # Endpoint (files still locked) and no working agent at all. Report it and let
        # Install-ElasticAgent proceed with its force-install anyway - confirmed to succeed
        # over this exact leftover state - then retry removal once the fresh enrollment
        # gives it a non-orphaned uninstall-token context (see the recovery block there).
        Write-Output "$(Get-FormattedDate) Could not fully remove existing installation (Elastic Agent present: $($removalState.AgentPresent), ElasticEndpoint present: $($removalState.EndpointPresent)) - likely Agent Tamper Protection blocking removal. Proceeding with the new install anyway; removal will be retried once it is enrolled."
    } else {
        Write-Output "$(Get-FormattedDate) Old agent/endpoint services removed, deploying UNS SIEM Agent"
    }
}

# Reads agent.grpc.port from an elastic-agent.yml: the number, or $null when it is not set in that file
# (commented-out lines do not count). Used to verify an edit and to report what the agent will really use.
function Get-AgentGrpcPortFromConfig {
    param ([string]$ConfigPath)

    if (-not (Test-Path -LiteralPath $ConfigPath)) { return $null }
    $inBlock = $false
    foreach ($line in [System.IO.File]::ReadAllLines($ConfigPath)) {
        if ($line -match '^\s*#') { continue }
        if ($line -match '^agent\.grpc\.port\s*:\s*(\d+)') { return [int]$Matches[1] }
        if ($line -match '^agent\.grpc\s*:\s*$') { $inBlock = $true; continue }
        if ($inBlock) {
            if ($line -match '^\s+port\s*:\s*(\d+)\s*(#.*)?$') { return [int]$Matches[1] }
            if ($line -match '^\S') { $inBlock = $false }
        }
    }
    return $null
}

# Sets agent.grpc.port in an elastic-agent.yml. Any existing agent.grpc setting (block or dotted key)
# is replaced, everything else in the file is left as it is, and the original is kept once as
# <file>.uns-bak. The file is read back afterwards: returns $true only when it now really says the
# wanted port. $script:GrpcEditSummary describes the before/after for the log.
function Set-AgentGrpcPort {
    param ([string]$ConfigPath, [int]$Port)

    $script:GrpcEditSummary = "$ConfigPath : file not found"
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return $false }
    try {
        $before = Get-AgentGrpcPortFromConfig -ConfigPath $ConfigPath
        $backup = "$ConfigPath.uns-bak"
        if (-not (Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $ConfigPath -Destination $backup -Force }

        $kept = New-Object System.Collections.Generic.List[string]
        $skipping = $false
        $pending = New-Object System.Collections.Generic.List[string]   # comment/blank lines seen inside a block being replaced
        foreach ($line in [System.IO.File]::ReadAllLines($ConfigPath)) {
            if ($line -match '^agent\.grpc(\.[A-Za-z_]+)?\s*:') { $skipping = $true; $pending.Clear(); continue }
            if ($skipping) {
                if ($line -match '^\s*(#.*)?$') { $pending.Add($line); continue }   # comment or blank: may sit inside the block
                if ($line -match '^\s+\S') { $pending.Clear(); continue }           # indented content of the old block (comments before it go too)
                $skipping = $false                                                  # next top-level key: the block is over
                foreach ($held in $pending) { $kept.Add($held) }
                $pending.Clear()
            }
            $kept.Add($line)
        }
        foreach ($held in $pending) { $kept.Add($held) }   # file ended while still in the block
        $kept.Add("agent.grpc:")
        $kept.Add("  address: localhost")
        $kept.Add("  port: $Port")
        [System.IO.File]::WriteAllLines($ConfigPath, $kept, (New-Object System.Text.UTF8Encoding($false)))

        # Do not trust the write: read the file back and confirm it now says what we meant.
        $after = Get-AgentGrpcPortFromConfig -ConfigPath $ConfigPath
        $beforeText = if ($null -eq $before) { 'not set' } else { $before }
        $afterText = if ($null -eq $after) { 'not set' } else { $after }
        $script:GrpcEditSummary = "$ConfigPath : agent.grpc.port before=$beforeText, wanted=$Port, read back=$afterText"
        return ($after -eq $Port)
    } catch {
        $script:GrpcEditSummary = "$ConfigPath : $($_.Exception.Message)"
        Write-Verbose "$(Get-FormattedDate) Could not update $ConfigPath : $($_.Exception.Message)"
        return $false
    }
}

# Copies the agent's own logs to a folder that survives the deployment cleanup. The installer's rollback
# deletes them, and they are the only place that says why the service died.
function Save-AgentFailureLogs {
    $destination = Join-Path $env:TEMP "UNSAgent-failure-logs"
    try {
        New-Item -Path $destination -ItemType Directory -Force | Out-Null
        $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
        foreach ($file in @(Get-ChildItem -Path "$env:ProgramFiles\Elastic\Agent\data\elastic-agent-*\logs\*" -File -ErrorAction SilentlyContinue)) {
            Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $destination "$stamp-$($file.Name)") -Force -ErrorAction SilentlyContinue
        }
        $installedYml = Join-Path $env:ProgramFiles "Elastic\Agent\elastic-agent.yml"
        if (Test-Path -LiteralPath $installedYml) { Copy-Item -LiteralPath $installedYml -Destination (Join-Path $destination "$stamp-elastic-agent.yml") -Force -ErrorAction SilentlyContinue }
    } catch { }
    return $destination
}

# Returns the agent's most recent error messages from its live log (empty when there is none).
function Get-AgentLogErrors {
    param ([int]$Count = 6)
    $messages = @()
    try {
        $logFile = Get-ChildItem -Path "$env:ProgramFiles\Elastic\Agent\data\elastic-agent-*\logs\*.ndjson" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($logFile) {
            foreach ($errorLine in @(Get-Content -Path $logFile.FullName -Tail 300 -ErrorAction SilentlyContinue | Where-Object { $_ -match '"log.level":"error"' } | Select-Object -Last $Count)) {
                try { $messages += ($errorLine | ConvertFrom-Json -ErrorAction Stop).message } catch { $messages += $errorLine }
            }
        }
    } catch { }
    return $messages
}

# True once the Elastic Agent service has been running continuously for the given time. Returns $false
# as soon as it stops after having started (the symptom of the port problem), or if it never starts.
function Wait-AgentServiceStable {
    param ([int]$Seconds = 30)
    $started = Get-Date
    $deadline = $started.AddSeconds($Seconds)
    $sawRunning = $false
    while ((Get-Date) -lt $deadline) {
        $service = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
        if (-not $service) { return $false }
        if ($service.Status -eq 'Running') { $sawRunning = $true }
        elseif ($sawRunning -or (((Get-Date) - $started).TotalSeconds -gt 15)) { return $false }
        Start-Sleep -Seconds 2
    }
    $service = Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue
    return ($sawRunning -and $service -and ($service.Status -eq 'Running'))
}

# Runs elastic-agent install and captures its output without the progress spinner. The result is left in
# $script:InstallResult (ExitCode, Text) so nothing else ends up in the function's output.
function Invoke-ElasticAgentInstallProcess {
    param ([string]$ExePath, [string]$Arguments)

    $installOutFile = Join-Path $env:TEMP "uns-elastic-install-out.txt"
    $installErrFile = Join-Path $env:TEMP "uns-elastic-install-err.txt"
    Remove-Item -Path $installOutFile, $installErrFile -Force -ErrorAction SilentlyContinue
    $process = Start-Process -FilePath $ExePath -ArgumentList $Arguments -NoNewWindow -PassThru -RedirectStandardOutput $installOutFile -RedirectStandardError $installErrFile
    $handle = $process.Handle  # Cache the process handle so ExitCode is readable after WaitForExit
    $process.WaitForExit()
    $exitCode = $process.ExitCode
    $null = $handle

    Write-Output "$(Get-FormattedDate) elastic-agent install finished with exit code $exitCode. Installer output:"
    Format-ElasticInstallOutput $installOutFile
    if ((Test-Path $installErrFile) -and ((Get-Item $installErrFile).Length -gt 0)) {
        Write-Output "    Installer error output:"
        Format-ElasticInstallOutput $installErrFile
    }
    $text = ((Get-Content -Path $installOutFile -Raw -ErrorAction SilentlyContinue) + "`n" + (Get-Content -Path $installErrFile -Raw -ErrorAction SilentlyContinue))
    Remove-Item -Path $installOutFile, $installErrFile -Force -ErrorAction SilentlyContinue
    $script:InstallResult = [pscustomobject]@{ ExitCode = $exitCode; Text = $text }
}

# Starts the Elastic Agent service and checks that it stays running. If it dies, the agent's log (or a
# failed bind test on the current port) decides whether the local port is the cause; if so the next free
# port is written into the installed elastic-agent.yml and the service is started again (up to 3 times).
# Used after the installer and again after the script's own stop/rename/start, because a Fleet
# enrollment can rewrite elastic-agent.yml and lose the port setting. Sets $script:AgentInstallOk.
function Start-AgentServiceWithRecovery {
    $installedYml = Join-Path $env:ProgramFiles "Elastic\Agent\elastic-agent.yml"
    $portPattern = 'bind:|forbidden by its access permissions|only one usage of each socket|address already in use|elastic-agent-system|could not reload agent'
    $port = if ($script:AgentGrpcPort) { [int]$script:AgentGrpcPort } else { $defaultAgentGrpcPort }
    $triedPorts = @($script:AgentTriedPorts)
    if ($triedPorts -notcontains $port) { $triedPorts += $port }

    for ($try = 1; $try -le 3; $try++) {
        if (-not (Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue)) { $script:AgentInstallOk = $false; return }
        try { Start-Service -Name "Elastic Agent" -ErrorAction Stop } catch { Write-Output "$(Get-FormattedDate) Start-Service: $($_.Exception.Message)" }
        if (Wait-AgentServiceStable -Seconds 30) {
            Write-Output "$(Get-FormattedDate) Agent service is running (local port $port)"
            # Prove it: what the installed config says, and who really owns the port right now.
            $configured = Get-AgentGrpcPortFromConfig -ConfigPath $installedYml
            Write-Output "    Installed config agent.grpc.port: $(if ($null -eq $configured) { 'not set (agent default 6789)' } else { $configured })"
            $owners = @(Get-PortListener -Port $port)
            if ($owners.Count -gt 0) { foreach ($owner in $owners) { Write-Output "    Port $port is held by: $owner" } }
            else { Write-Output "    Port $port has no listener yet (the agent may still be starting)" }
            if (($owners -join ' ') -notmatch 'elastic-agent') { Write-Output "    WARNING: elastic-agent.exe is not seen listening on port $port" }
            $script:AgentInstallOk = $true; return
        }

        Write-Output "$(Get-FormattedDate) Agent service did not stay running (start attempt $try of 3)"
        $logDir = Save-AgentFailureLogs
        $agentErrors = @(Get-AgentLogErrors)
        foreach ($agentError in $agentErrors) { Write-Output "    Agent log error: $agentError" }
        Write-Output "    Agent logs saved to $logDir"
        try { Stop-Service -Name "Elastic Agent" -Force -ErrorAction SilentlyContinue } catch { }

        $bindProblem = (($agentErrors -join "`n") -match $portPattern) -or (-not (Test-PortBindable -Port $port))
        if (-not $bindProblem) {
            Write-Output "    The logs do not point at the port, so another port will not help. See the saved logs (antivirus/EDR blocking elastic-agent.exe is the next thing to check)."
            $script:AgentInstallOk = $false; return
        }
        $next = Find-FreeAgentGrpcPort -Exclude $triedPorts
        if ($null -eq $next) { Write-Output "    No other free port available"; $script:AgentInstallOk = $false; return }
        if (-not (Set-AgentGrpcPort -ConfigPath $installedYml -Port $next)) {
            Write-Output "$(Get-FormattedDate) NOT VERIFIED: could not set the agent port to $next. $script:GrpcEditSummary"
            $script:AgentInstallOk = $false; return
        }
        Write-Output "$(Get-FormattedDate) Verified config change: $script:GrpcEditSummary"
        Write-Output "$(Get-FormattedDate) Switching the agent to local port $next and restarting it"
        $port = $next
        $triedPorts += $next
        $script:AgentGrpcPort = $port
        $script:AgentTriedPorts = $triedPorts
    }
    $script:AgentInstallOk = $false; return
}

# Installs the agent and recovers from a service that dies right after it starts:
#   1. Pre-flight: if the default local port (6789) is listened on or cannot be bound, a free one is chosen
#      and written into the package's elastic-agent.yml before installing.
#   2. Normal install. If it works, done.
#   3. If it fails, the installer has rolled everything back and its logs are gone. Install again with
#      --delay-enroll, which does not roll back, so the service can be started and the logs read. If the
#      service dies again and the logs (or the port itself) point at the port, the next free port is
#      written into the installed elastic-agent.yml and the service is restarted (up to 3 times).
# Returns $true when an agent service is installed and stays running.
function Invoke-ElasticAgentInstallWithRecovery {
    param ([string]$PackageDir, [string]$BaseArguments)

    $exe = Join-Path $PackageDir "elastic-agent.exe"
    $packageYml = Join-Path $PackageDir "elastic-agent.yml"
    $portPattern = 'bind:|forbidden by its access permissions|only one usage of each socket|address already in use|elastic-agent-system|could not reload agent'
    $triedPorts = @()

    # Saved failure logs from earlier runs are only useful for a few days.
    Get-ChildItem -Path (Join-Path $env:TEMP "UNSAgent-failure-logs") -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force -ErrorAction SilentlyContinue

    # 1. Pre-flight
    $port = Find-FreeAgentGrpcPort
    if ($null -eq $port) {
        Write-Output "$(Get-FormattedDate) No free local port found for the agent, installing with the default $defaultAgentGrpcPort"
        $port = $defaultAgentGrpcPort
    } elseif ($port -ne $defaultAgentGrpcPort) {
        foreach ($listener in @(Get-PortListener -Port $defaultAgentGrpcPort)) { Write-Output "$(Get-FormattedDate) Default agent port $defaultAgentGrpcPort is in use: $listener" }
        if (@(Get-PortListener -Port $defaultAgentGrpcPort).Count -eq 0) { Write-Output "$(Get-FormattedDate) Default agent port $defaultAgentGrpcPort cannot be bound" }
        if (Set-AgentGrpcPort -ConfigPath $packageYml -Port $port) {
            Write-Output "$(Get-FormattedDate) Verified config change: $script:GrpcEditSummary"
            Write-Output "$(Get-FormattedDate) Agent will use local port $port"
        } else {
            Write-Output "$(Get-FormattedDate) NOT VERIFIED: could not set the agent port to $port in the package config. $script:GrpcEditSummary"
        }
    } else {
        Write-Verbose "$(Get-FormattedDate) Local port $defaultAgentGrpcPort is free"
    }
    $triedPorts += $port
    $script:AgentGrpcPort = $port
    $script:AgentTriedPorts = $triedPorts

    # 2. Normal install
    Invoke-ElasticAgentInstallProcess -ExePath $exe -Arguments "$BaseArguments --enroll-timeout=2m"
    if ($script:InstallResult.ExitCode -eq 0) { $script:AgentInstallOk = $true; return }

    # 3. Recovery
    $portRelated = ($script:InstallResult.Text -match $portPattern)
    Write-Output "$(Get-FormattedDate) Install failed$(if ($portRelated) { ' with an error that points at the agent port or its startup' }). Retrying with delayed enrollment so the failure logs are kept"
    if ($portRelated) {
        $next = Find-FreeAgentGrpcPort -Exclude $triedPorts
        if ($null -ne $next) {
            if (Set-AgentGrpcPort -ConfigPath $packageYml -Port $next) {
                Write-Output "$(Get-FormattedDate) Verified config change: $script:GrpcEditSummary"
                Write-Output "$(Get-FormattedDate) Switching the agent to local port $next"
                $port = $next
                $triedPorts += $next
                $script:AgentGrpcPort = $port
                $script:AgentTriedPorts = $triedPorts
            }
        }
    }

    Invoke-ElasticAgentInstallProcess -ExePath $exe -Arguments "$BaseArguments --delay-enroll"
    if ($script:InstallResult.ExitCode -ne 0) { $script:AgentInstallOk = $false; return }

    Start-AgentServiceWithRecovery
}

#Function to deploy Elastic Agent
function Install-ElasticAgent {
    param (
    )
        try {
			Write-Verbose "$(Get-FormattedDate) Downloading and installing UNS SIEM Agent."

            Start-Sleep -Milliseconds 500

                #Unzipping files
                Write-Verbose "$(Get-FormattedDate) Unzipping agent files, it will take few seconds..."
                Write-Output "$(Get-FormattedDate) Unzipping agent files, it will take few seconds..."
                try {
                    # Try unzipping the files
                    Write-Verbose "$(Get-FormattedDate) LogPath is $datapath"
                    $archiveFile = $datapath.Trim() + $agentFiles[2].Trim()
                    Write-Verbose "$(Get-FormattedDate) Archive file is $archiveFile"
                    # a folder left by an earlier run would make the package path below ambiguous
                    Get-ChildItem -Path $datapath -Directory -Filter "elastic-agent-*" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue


                    if ($Version -ge $RequiredVersion) {
                        # Execute the command for .NET Framework 4.5 and above
                        #Check what PS version we are using.
                        if ($PSVersionTable.PSVersion.Major -lt 5) {
                            Write-Verbose "$(Get-FormattedDate) This is PowerShell version less than V5, using .NET framework classes to unpack"
                            Add-Type -assembly "system.io.compression.filesystem"
                            [io.compression.zipfile]::ExtractToDirectory("$archiveFile", "$datapath")
                        } else {
                            Write-Verbose "$(Get-FormattedDate) This is PowerShell version V5 or above, unziping via Expand-Archive"
                            Expand-Archive $archiveFile -DestinationPath $datapath -Force -ErrorAction Stop
                        }
                    } else {
                        Write-Verbose "$(Get-FormattedDate) DOTNET version is below 4.5 Using COM Shell Application to Expand"
                        $shell = New-Object -ComObject Shell.Application
                        $zip = $shell.NameSpace($zipFilePath)
                        $destination = $shell.NameSpace($extractPath)
                        $destination.CopyHere($zip.Items(), 0x10)
                    }
                    
                    $agentinstallPath = $datapath.Trim() + (Get-Item -Path $datapath\elastic-agent-*).Name
                    
                    Start-Sleep -Milliseconds 500
                    Write-Verbose "$(Get-FormattedDate) All files were unzipped, installing agent..."
                    Write-Output "$(Get-FormattedDate) Files were unzipped, installing siem agent..."
                }
                catch {
                    $errorMessage = $_.Exception.Message
                    Write-Error "$(Get-FormattedDate) Agent files copy failed because of $($errorMessage)" -ErrorAction Stop
                    break
                }
                
                # Checking if tokens and URL is provided and triggering token Form LOGIC NEED FIX
                Write-Verbose "$(Get-FormattedDate) Starting Fleet and Token procedures."
                Start-Sleep -Milliseconds 300
                if ($token -and $fleetURL) {
                    Write-Verbose "$(Get-FormattedDate) Token and fleetURL already provided"
                } elseif (($fleetURL) -and (-not $token)) {
                    Write-Verbose "$(Get-FormattedDate) Fleet URL is already provided: $fleetURL"
                    Write-Verbose "$(Get-FormattedDate) Missing token. Initiating form input."
                    $token = Show-TokenForm
                    if (($null -eq $token) -or ((($token -join '').Length) -lt 30)) {
                        Write-Error "$(Get-FormattedDate): Token is empty or too short. Seems that the user cancelled the input or did not provided required value" -ErrorAction Stop
                    }
                } elseif (($token) -and (-not $fleetURL)) {
                    Write-Verbose "$(Get-FormattedDate) Token is already provided: $(Get-MaskedSecret $token)"
                    Write-Verbose "$(Get-FormattedDate) Missing FleetURL. Initiating form input."
                    $fleetURL = Show-TokenForm
                    if (($null -eq $fleetURL) -or ((($fleetURL -join '').Length) -lt 30)) {
                        Write-Error "$(Get-FormattedDate): fleetURL is empty or too short. Seems that the user cancelled the input or did not provided required values" -ErrorAction Stop
                    }
                    Write-Verbose "$(Get-FormattedDate) FleetURL provided: $fleetURL"

                } else {
                    $tokenVars = Show-TokenForm
                    $token = $tokenVars[0].Trim()
                    $fleetURL = $tokenVars[1].Trim()
                    if (($null -ne $token) -or ($null -ne $fleetURL)) {
                        Write-Verbose "$(Get-FormattedDate) Tokens were provided"
                    } else {
                        Write-Error "$(Get-FormattedDate): fleetURL or token is empty. Seems that the user cancelled the input or did not provided required values" -ErrorAction Stop
                    }
                }

         	$arguments = "install -f"
            $arguments += " --url=$fleetURL"
            $arguments += " --enrollment-token=$token"
            if ($insecure) {
            $arguments += " --insecure"
            }
            if ($tag) {
            # quoted because tags may contain spaces; the list itself is comma-separated per Elastic docs
            $arguments += " --tag=`"$tag`""
            }

			$maskedToken = Get-MaskedSecret $token
			
			Write-Verbose -Message "$(Get-FormattedDate) UNS SIEM Agent Install Path: $agentinstallPath"
			Write-Verbose -Message "$(Get-FormattedDate) UNS SIEM fleet URL: $fleetURL"
			Write-Verbose -Message "$(Get-FormattedDate) UNS SIEM Enrollment token: $maskedToken"
			Write-Verbose -Message "$(Get-FormattedDate) UNS SIEM Tags: $(if ($tag) { $tag } else { '<none>' })"
			Write-Output "$(Get-FormattedDate) UNS SIEM fleet URL: $fleetURL"
			Write-Output "$(Get-FormattedDate) UNS SIEM Enrollment token: $maskedToken"
            
            # additional check if token was provided and value is not null
            if ($null -eq $token) {
                Write-Error "$(Get-FormattedDate) Token issues after token forms"
                Stop-Deployment

            } else {
                # installing elastic services
                try {
                    Write-Verbose "$(Get-FormattedDate) Installing UNS SIEM Agent..."
                    Write-Output "$(Get-FormattedDate) Installing UNS SIEM Agent..."

                #Remove existing agent/endpoint services if present. It helps during redeployment.
                Remove-ExistingElasticAgent

                # Insalling UNS SIEM Agent
                # The installer's progress spinner is captured to files and printed afterwards without the
                # spinner, so the real error is not buried in (or cut off from) the NinjaOne output.
                # Port pre-check, install, and recovery (alternative port + elastic-agent.yml edit + retry)
                # when the service dies after it starts: see Invoke-ElasticAgentInstallWithRecovery.
                $script:AgentInstallOk = $false
                Invoke-ElasticAgentInstallWithRecovery -PackageDir $agentinstallPath -BaseArguments $arguments
                if (-not $script:AgentInstallOk) {
                    throw "Installation failed after recovery attempts"
                }
                Write-Verbose -Message "$(Get-FormattedDate) Elastic Agent has been installed."
                }
                catch {
                    $errorMessage = $_.Exception.Message
                    Write-Output "$(Get-FormattedDate) Installation failed because of $($errorMessage)"
                    $script:deployExitCode = 1
                    exit 1
                }

                #Sleep 3 seconds before attempting to stop services.
                Start-Sleep -Seconds 3

                #modifying services
                if (Get-Service -ServiceName "Elastic Agent") {
                    try {
                        #Rename elastic service:
                        Write-Verbose "$(Get-FormattedDate) Services operations started:"

                        Start-Sleep -Milliseconds 500
                        Write-Verbose "$(Get-FormattedDate) Stopping elastic agent service"
                        try {
                            # stopping the agent
                            Stop-Service -ServiceName "Elastic Agent" -Force -Confirm:$false -ErrorAction Stop
                            
                        }
                        catch {
                            $errorMessage = $_.Exception.Message
                            Write-Error $errorMessage -ErrorAction Stop
                            Stop-Deployment
                        }

                        Write-Verbose "$(Get-FormattedDate) Elastic agent service stopped."

                        # Fleet enrollment rewrites the installed elastic-agent.yml and drops agent.grpc, so the port chosen
                        # before the install has to be written again before the service is started the next time.
                        if ($script:AgentGrpcPort -and ([int]$script:AgentGrpcPort -ne $defaultAgentGrpcPort)) {
                            if (Set-AgentGrpcPort -ConfigPath (Join-Path $env:ProgramFiles "Elastic\Agent\elastic-agent.yml") -Port ([int]$script:AgentGrpcPort)) {
                                Write-Output "$(Get-FormattedDate) Verified config change: $script:GrpcEditSummary"
                            } else {
                                Write-Output "$(Get-FormattedDate) NOT VERIFIED: could not set the agent port to $($script:AgentGrpcPort) in the installed config. $script:GrpcEditSummary"
                            }
                        }
                        
                        Start-Sleep -Milliseconds 500
                        #set service displayname and description
                        Write-Verbose "$(Get-FormattedDate) Renaming elastic agent service name"
                        try {

                            Set-Service -ServiceName "Elastic Agent" -DisplayName "UNS SIEM Agent" -ErrorAction Stop
                            Set-Service -ServiceName "Elastic Agent" -Description "UNS SIEM Agent is a unified agent to observe, monitor and protect your system."
 
                        }
                        catch {
                            $errorMessage = $_.Exception.Message
                            Write-Error "$(Get-FormattedDate) Installation failed because of $($errorMessage)" -ErrorAction Stop
                            Stop-Deployment
                        }

                        Write-Verbose "$(Get-FormattedDate) Elastic agent service renamed to UNS SIEM Agent"
                        Write-Verbose "$(Get-FormattedDate) UNS SIEM Agent service description changed"
                        
                        Start-Sleep -Milliseconds 500
                        #Atetmpting to start uns siem agent
                        Write-Verbose "$(Get-FormattedDate) Attempting to start UNS SIEM Agent Service"
                        try {
                            Start-Service -ServiceName "Elastic Agent"
                        }
                        catch {
                            $errorMessage = $_.Exception.Message
                            Write-Output $errorMessage
                            break
                        }
                        # The installer's own start worked, but the restart after the rename is what the machine keeps.
                        # Make sure the service really stays up, and repair the port if it does not.
                        $script:AgentInstallOk = $false
                        Start-AgentServiceWithRecovery
                        if (-not $script:AgentInstallOk) {
                            $script:deployExitCode = 1
                            Write-Output "$(Get-FormattedDate) UNS SIEM Agent service is installed but is not staying running"
                        } else {
                            Write-Verbose "$(Get-FormattedDate) Service started successfully"
                        }

                        # An Endpoint that survived the cleanup before this install (tamper protection) is still there.
                        # What to do with it depends on the policy this machine just enrolled in:
                        #  * A policy with Elastic Defend (anything not ...NoDefend): the new agent takes over the
                        #    existing Endpoint (same service) and reconfigures it. The old and the new Endpoint cannot
                        #    be told apart by name, so removing it now could remove the protection that was just
                        #    deployed. It is left in place and only reported.
                        #  * A ...NoDefend policy: no Endpoint is wanted, so the survivor is a stray. It is removed with
                        #    its own uninstaller once the agent has enrolled; the new agent stays.
                        # This -InstallOnly process cannot call Set-SiemNeedsReview (it lives in the evaluation process),
                        # so a failure is signalled with exit code 4, which the evaluation process reads.
                        if ($script:AgentInstallOk -and $script:OldEndpointSurvivedCleanup) {
                            if ($policyName -match 'NoDefend$') {
                                Write-Output "$(Get-FormattedDate) An Endpoint from the previous install survived the cleanup and policy $policyName does not use Elastic Defend; the new agent is enrolled and running - waiting 60s for its policy, then removing the stray Endpoint"
                                Start-Sleep -Seconds 60
                                $null = Invoke-ElasticEndpointUninstall

                                $recoveryState = Wait-ElasticServicesGone
                                if (-not $recoveryState.EndpointPresent) {
                                    Write-Output "$(Get-FormattedDate) Stray Endpoint removed; the new Elastic Agent is installed and running."
                                } else {
                                    Write-Output "$(Get-FormattedDate) Stray Endpoint could NOT be removed (Elastic Agent present: $($recoveryState.AgentPresent), ElasticEndpoint present: $($recoveryState.EndpointPresent)). Manual review required."
                                    Write-SiemDiagnostics
                                    Clear-ElasticEnvSettings
                                    Stop-Deployment -Code 4
                                }
                            } else {
                                Write-Output "$(Get-FormattedDate) An Endpoint from the previous install is still present. Policy $policyName includes Elastic Defend, so it is NOT removed: the new agent takes over the existing Endpoint. Check in Fleet that the Endpoint reports healthy for this host."
                            }
                        }

                    }
                    catch {
                        $errorMessage = $_.Exception.Message
                        Write-Error "$(Get-FormattedDate) Modifying services failed because of $($errorMessage)" -ErrorAction Stop
                        Remove-Item -Path $InstallDIR\agent -Recurse -Force -ErrorAction SilentlyContinue
                        Stop-Deployment
                    }
                }
            }
        } 
        catch {
                $errorMessage = $_.Exception.Message
                Write-Error "$(Get-FormattedDate) UNS ElasticSIEM Agent deployment failed for following reason: $($errorMessage)" -ErrorAction Stop
                Remove-Item -Path $InstallDIR\agent -Recurse -Force -ErrorAction SilentlyContinue
                Stop-Deployment
        }
}

### ACTION ###
$script:deployExitCode = 0
try {
  if ($UninstallOnly) {
    # Cleanup only: remove the agent and Endpoint (supported uninstall with the uninstall token, then the
    # manual fallback and file cleanup). Sysmon and Perch are left exactly as they are, and nothing is installed.
    Write-Output "$(Get-FormattedDate) UNINSTALL ONLY: removing the UNS SIEM Agent and Elastic Endpoint"
    if (-not ($uninstallToken -join '').Trim()) {
        Write-Output "$(Get-FormattedDate) No uninstall token available for this machine (policy $policyName). An agent without Agent Tamper Protection can still be removed; a protected one will refuse."
    }
    Remove-ExistingElasticAgent
    Write-Output "$(Get-FormattedDate) Uninstall finished"
  } else {

    if (Get-Service -Name Perch*) {
        Uninstall-Perch
    } else 
        {Write-Verbose "$(Get-FormattedDate) Perch is not installed on the system"
    }
    if ($null -eq (Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue)) {
        $nativeSysmon = Get-Service -Name $sysmonSvcName -ErrorAction SilentlyContinue

        # On ARM64 a leftover x64 Sysmon64.exe registration never actually loads (kernel drivers
        # can't run under emulation) and must be replaced by the native Sysmon64a.exe. Detection is
        # by exact service name/path, so a stale Sysmon64 is not confused with a healthy Sysmon64a.
        if (Test-WrongArchSysmon64Present) {
            Write-Verbose "$(Get-FormattedDate) Wrong-architecture Sysmon64 (x64) detected on ARM64 host. Replacing with native $sysmonExe..."
            Uninstall-Sysmon64WrongArch
            Start-Sleep -Seconds 1
            if (-not (Get-Service -Name $sysmonSvcName -ErrorAction SilentlyContinue)) {
                Install-Sysmon64
                Start-Sleep -Seconds 1
            }
            Set-Sysmon64
            Start-Sleep -Seconds 1
        } elseif ($nativeSysmon) {
            Write-Verbose "$(Get-FormattedDate) $sysmonSvcName already installed."
            Update-Sysmon64ConfigIfChanged
        } else {
            Write-Verbose "$(Get-FormattedDate) $sysmonSvcName not installed on the system. Installing..."
            Install-Sysmon64
            Set-Sysmon64
        }
    } else {
        Write-Verbose "$(Get-FormattedDate) Uninstalling Sysmon32"
        Uninstall-Sysmon32
        Start-Sleep -Seconds 1
        Write-Verbose "$(Get-FormattedDate) Installing Sysmon64"
        Install-Sysmon64
        Start-Sleep -Seconds 1
        Write-Verbose "$(Get-FormattedDate) Setting Sysmon64 config"
        Set-Sysmon64
        Start-Sleep -Seconds 1
    }

    Test-Sysmon64Health

    # Gate on the expected service by exact name; a stale wrong-architecture Sysmon64 must not satisfy it.
    # Not-running is reported by the health check above but does not block the SIEM agent deployment.
    if (($null -eq (Get-Service -Name Perch*)) -and (Get-Service -Name $sysmonSvcName -ErrorAction SilentlyContinue)) {
        Install-ElasticAgent
            if ($null -ne (Get-Service -ServiceName "Elastic Agent")) {
                Write-Verbose "$(Get-FormattedDate) UNS SIEM Agent successfully installed"
            }
    } else {
        Write-Output "$(Get-FormattedDate) Something went wrong"
    }
  }
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Error "$(Get-FormattedDate) UNS ElasticSIEM Agent deployment failed because of $($errorMessage)"
    $script:deployExitCode = 1
    break
}
finally {
    Remove-ElasticLeftovers -path $datapath
    Write-Verbose "$(Get-FormattedDate) Going back to initial location: $($InitialLocation)" 
    Push-Location -LiteralPath $InitialLocation
    Clear-ElasticEnvSettings
    Stop-Transcript -ErrorAction SilentlyContinue
    Write-Verbose "$(Get-FormattedDate) All temp files were removed."
    Write-Output "$(Get-FormattedDate) All temp files were removed."
    Write-Output "$(Get-FormattedDate) Good bye"
    $datapath = $null 
    $agentFiles = $null
    Start-Sleep 5
    exit $script:deployExitCode
}
### END ACTION ###
