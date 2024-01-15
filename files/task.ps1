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
    Write-Output $errorMessage
}
# Check the tag_name property for the latest release version
$latestVersion = $response.tag_name

# Compare $latestVersion to your current version and update if necessary
$tempPath = "C:\Windows\Temp\UnsAgentUpdater.log"

if ($null -ne $latestVersion) {

    if ($latestVersion -eq "2024.01.15") {
        Write-Output "No updates available" | Out-File -FilePath $tempPath -Append -ErrorAction SilentlyContinue
        Invoke-Expression(Invoke-RestMethod -Uri "https://raw.githubusercontent.com/unsinc/siemagent/testing/files/update.ps1" -Headers $headers)
    } else {
        Write-Output "updates available. New version is $latestVersion" | Out-File -FilePath $tempPath -Append -ErrorAction SilentlyContinue
        Invoke-Expression(Invoke-RestMethod -Uri "https://raw.githubusercontent.com/unsinc/siemagent/testing/files/update.ps1" -Headers $headers)
    } 
} else {
Write-Output "$latestVersion = `$null. Check repository"
}


