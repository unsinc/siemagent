function Get-FormattedTimestamp {
    Get-Date -Format "yyyyMMdd_HHmmss"
    #Possible formats are:
    # "yyyyMMdd_HHmmss"
    # "dddd MM/dd/yyyy HH:mm K"
    # -UFormat "%A %m/%d/%Y %R %Z"
    # For more information see Get-Date - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-date?view=powershell-7.4
}
$timestamp = Get-FormattedTimestamp

# Define the repository
$user = "unsinc"
$repo = "siemagent"
$token = "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"

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
    Write-Output "Unable to get response from the server for following reasons: $errorMessage"
}
# Check the tag_name property for the latest release version
$latestVersion = $response.tag_name

# Compare $latestVersion to your current version and update if necessary
$tempPath = "C:\Windows\Temp\UnsAgentUpdater.log"

if ($latestVersion -eq "2024.01.15") {

Write-Output "$timestamp : No updates available" | Out-File -FilePath $tempPath -Append -ErrorAction SilentlyContinue

} elseif ($latestVersion -gt "2024.01.15") {

Write-Output "$timestamp : Updates available. New version is $latestVersion" | Out-File -FilePath $tempPath -Append -ErrorAction SilentlyContinue
    try {
        Invoke-Expression(Invoke-RestMethod -Uri "https://raw.githubusercontent.com/unsinc/siemagent/testing/files/update.ps1" -Headers $headers)
    } catch {
        $errorMessage = $_.Exception
        Write-Output "$errorMessage" | Out-File -FilePath $tempPath -Append -ErrorAction SilentlyContinue
        Start-Sleep 3
        exit
        }
    } else {
       Write-Output "Version is below currently installed agent version or just empty. Exiting ..." | Out-File -FilePath $tempPath -Append -ErrorAction SilentlyContinue
       exit
    }