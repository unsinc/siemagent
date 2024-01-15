# Define the repository and your personal access token
$user = "unsinc"
$repo = "unsagent"
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
$tempPath = "C:\Widnows\Temp\UnsAgentUpdater.log"

if ($latestVersion -eq "2024.01.15") {

    Write-Output "No updates available" | Out-File -FilePath $tempPath -Append -ErrorAction SilentlyContinue

} else {

    Write-Output "updates available. New version is $latestVersion" | Out-File -FilePath $tempPath -Append -ErrorAction SilentlyContinue

}


