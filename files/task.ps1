# Define the repository
$user = "unsinc"
$repo = "siemagent"
$tempPath = "$env:HOMEDRIVE\Windows\Temp\UnsAgentUpdater.log"

# Timestamp function
function Get-FormattedTimestamp {
    Get-Date -Format "yyyyMMdd_HHmmss"
    #Possible formats are:
    # "yyyyMMdd_HHmmss"
    # "dddd MM/dd/yyyy HH:mm K"
    # -UFormat "%A %m/%d/%Y %R %Z"
    # For more information see Get-Date - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-date?view=powershell-7.4
}

$timestamp = Get-FormattedTimestamp
Write-Verbose -Message "Timestamp is: $timestamp"

try {
    # Call the GitHub API
    $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$user/$repo/releases/latest" -UseBasicParsing
}
catch {
    $errorMessage = $_.Exception
    Write-Output "Unable to get response from the server for following reasons: $errorMessage" | OutFile -FilePath $tempPath -Append -ErrorAction SilentlyContinue
}
# Check the tag_name property for the latest release version
$latestVersion = $response.tag_name

# Compare $latestVersion to your current version and update if necessary
$messages = @()

if ($latestVersion -eq "2024.01.15") {
    $messages += "$timestamp : No updates available"
} elseif ($latestVersion -gt "2024.01.15") {
    $messages += "$timestamp : Updates available. New version is $latestVersion"
    try {
        # Download the script
        $scriptPath = Join-Path $env:TEMP "update.ps1"
        Invoke-RestMethod -Uri "https://raw.githubusercontent.com/$user/$repo/main/files/update.ps1" -UseBasicParsing -OutFile $scriptPath

        # Execute the script
        & $scriptPath
    }
    catch {
        $errorMessage = $_.Exception
        $messages += "$errorMessage"
        Start-Sleep 3
    }
} else {
    $messages += "Version is below currently installed agent version or just empty. Exiting."
}

# Write all messages to the log file
$messages | Out-File -FilePath $tempPath -Append -ErrorAction SilentlyContinue