##### EDIT CURRENT VERSION HERE ######
$defaultVersion = [version]"8.19.5"

if ($env:requiredVersion -and $env:requiredVersion -notlike "null") {
    try {
        [version]$requiredVersion = $env:requiredVersion # Ninja One variables setup
    } catch {
        Write-Output "requiredVersion env variable ('$env:requiredVersion') is not a valid version, falling back to default $defaultVersion"
        $requiredVersion = $defaultVersion
    }
} else {
    $requiredVersion = $defaultVersion # Default to preset if no environmental variables are set via automation.
}
#####################################

# Fixed, ASCII-only markers for NinjaOne to key its next-task condition on (output contains).
# Kept separate from the human-readable Write-Output lines below so rewording those later
# doesn't silently break the automation gate, and to avoid non-ASCII characters, which a
# no-BOM UTF-8 script can have mangled by Windows PowerShell 5.1's ANSI-codepage file reading.
$StatusActionRequired = "SIEM_AGENT_STATUS: ACTION_REQUIRED"
$StatusNeedsReview = "SIEM_AGENT_STATUS: NEEDS_REVIEW"
$StatusCompliant = "SIEM_AGENT_STATUS: COMPLIANT"

$agentBinaryPath = "$env:ProgramFiles\Elastic\Agent\elastic-agent.exe"

$siemAgentService = Get-Service -DisplayName 'UNS SIEM Agent' -ErrorAction SilentlyContinue

if (-not $siemAgentService) {
    Write-Output "UNS SIEM Agent is not installed"
    Ninja-Property-Set siemAgent "Not Installed"
    Write-Output $StatusActionRequired
    return
}

if (-not (Test-Path $agentBinaryPath)) {
    Write-Output "UNS SIEM Agent service exists but binary is missing"
    Ninja-Property-Set siemAgent "Broken Install"
    Write-Output $StatusNeedsReview
    return
}

# Always query binary version only (daemon may be dead)
$versionOutput = & $agentBinaryPath version --binary-only 2>$null

if ($versionOutput -notmatch 'Binary:\s+([0-9]+\.[0-9]+\.[0-9]+)') {
    Write-Output "UNS SIEM Agent installed, but version could not be parsed"
    Ninja-Property-Set siemAgent "Installed (Version Unknown)"
    Write-Output $StatusNeedsReview
    return
}

$installedVersion = [version]$matches[1]

# Check daemon health separately (optional but useful)
$daemonHealthy = $versionOutput -notmatch 'Daemon:\s+<failed'

# Version enforcement
if ($installedVersion -lt $requiredVersion) {
    Write-Output "UNS SIEM Agent $installedVersion detected - update required"
    Ninja-Property-Set siemAgent "Outdated ($installedVersion)"
    Write-Output $StatusActionRequired
}
else {
    Write-Output "UNS SIEM Agent is compliant"
    Ninja-Property-Set siemAgent "$installedVersion"
    Write-Output $StatusCompliant
}

# Optional health signal (non-blocking)
if (-not $daemonHealthy) {
    Write-Output "WARNING: Elastic Agent daemon is not responding"
}