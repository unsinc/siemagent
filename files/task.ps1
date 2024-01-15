# Define the repository
$user = "unsinc"
$repo = "siemagent"
$token = "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"
$tempPath = "C:\Windows\Temp\UnsAgentUpdater.log"

# Create a header with your token
$headers = @{
    "Authorization" = "token $token"
}

try {
    # Call the GitHub API
    $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$user/$repo/releases/latest" -Headers $headers
}
catch {
    $errorMessage = $_.Exception
    Write-Output "Unable to get response from the server for following reasons: $errorMessage" | OutFi;e -FilePath $tempPath -Append -ErrorAction SilentlyContinue
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
        Invoke-RestMethod -Uri "https://raw.githubusercontent.com/unsinc/siemagent/testing/files/update.ps1" -Headers $headers -OutFile $scriptPath

        # Execute the script
        & $scriptPath
    }
    catch {
        $errorMessage = $_.Exception
        $messages += "$errorMessage"
        Start-Sleep 3
        exit
    }
} else {
    $messages += "Version is below currently installed agent version or just empty. Exiting ..."
    exit
}

# Write all messages to the log file
$messages | Out-File -FilePath $tempPath -Append -ErrorAction SilentlyContinue