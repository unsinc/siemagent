<#
.SYNOPSIS
UNS SIEM Agent deployment tool

.DESCRIPTION
Deployment scrip will perform following tasks:
1. Uninstall Sysmon 32 bit from the system.
2. Install Sysmon 64bit on the system.
3. Install and enforce proprietary Sysmon64 config file.
4. Deploy UNS SIEM Agent and require enrollment-token/URL input from the user, if inputs are not given on the CLI.


.NOTES
File Name      : SiemAgentInstaller.ps1
Author         : nkolev@unsinc.com
Prerequisite   : PowerShell V5
Copyright	   : 2024, UNS Inc
Version		   : 2024.01.15

.EXAMPLE
.\SiemAgentInstaller.ps1 -token <elastic enrollment token>

.PARAMETER token
Use this switch to provide an enrollment token, enabling the registration of new UNS nodes to a specific UNS SIEM instance.

.PARAMETER fleetURL
Use this switch to assign a specific UNS Fleet URL to a particular UNS SIEM instance. Format is: https://750258aff4014f51a3fvc4a9d68bf5f.fleet.us-east-1.aws.elastic-cloud.com:443

.PARAMETER logpath
Use this switch to direct the log/data output to the specified directory.

.PARAMETER SlackURI
Use this switch to provide slack URI
Example: .\elastic_installer.ps1 -SlackURI https://hooks.slack.com/services/T3BMPT6C1/B14TEQDBz52/VJDw5aGVlVvJeXdtLvgBxWGL 

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
	[string[]]$logpath,

    [Parameter(Mandatory = $false,ValueFromPipeline=$true)]
	[string[]]$SlackURI
)


# Check if the script is running with elevated privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script with elevated privileges
    Write-Output "Rerun as administrator please."
    Start-Sleep 5
    exit
}


## setttings ##
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($fleetURL) {
Write-Verbose "URL is: $fleetURL"
}
if ($token) {
Write-Verbose "Token is: $token"
}

$sysmon32 = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
$currentLocation = Get-Location
$InitialLocation = $currentLocation
Write-Verbose -Message "Initial location is: $($InitialLocation)"


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

#Perform spelling check and create logpath folder for all further actions.
$logpath = $logpath -replace '\\\\+', '\'
$logpath = $logpath -replace '\\+$', '\'

if ($logpath) {
    $unsfiles = "UNSFiles\"
    if ($logpath -like "*\") {

        $logpath = $logpath.Trim(), $unsfiles -join ''
        Write-Verbose "Custom Log Path selected. Log path will be $logpath"

    } else {
        
        $logpath = $logpath.Trim(), "\", $unsfiles -join ''
        Write-Verbose "Custom Log Path selected. Log path will be $logpath"
    }
    if (Test-Path $logpath) {
        Write-Verbose "$logpath directory exist."
    } else {
        try {
            New-Item -Path $logpath -ItemType Directory -ErrorAction Stop 
        }
        catch {
            $errorMessage = $_.Exception
            Write-Verbose "$logpath folder creation failed because of: $errorMessage"
        }
    }
} else {
    $logpath = $env:temp.Trim(), "\UNSFiles\" -join ''
    Write-Verbose -Message "$($timestamp) Default LogPath is: $logpath"
}

$transcriptFilePath = Join-Path -Path $logpath -ChildPath "UNSAgent_Installer_Transcript_$($timestamp).txt"
Start-Transcript -Path $transcriptFilePath


# Download folder in case files are being downloaded from internet.
$downloadFolder = $logpath
Write-Verbose -Message "$($timestamp) Download Folder is: $downloadFolder"

#Default Install Directory
$InstallDIR = $env:programfiles + '\UNS SIEM Agent'
if (Test-Path $InstallDIR) {
    "Exist" | Out-Null
} else {
    try {
        New-Item -Path $InstallDIR -ItemType Directory
        Write-Output "Setting up Install DIR to $($InstallDIR)" 
        Write-Verbose -Message "$($timestamp) Default Installation Directory is: $InstallDIR"
    }
    catch {
        $errorMessage = $_.Exception
        Write-Output "Creating folders failed because: $errorMessage"
    }
}

# Remove leftovers from Elastic folder
function Remove-ElasticLeftovers {
    param (
        [string]$path
    )

    if (Test-Path -Path $path) {
        $items = Get-ChildItem $path -Exclude *.log -Depth 3 -Recurse
		foreach ($item in $items) {
			if (Test-Path $item -PathType Leaf) {
                Write-Debug "Removing $item."
				Remove-Item -Path $item -Recurse -Force -ErrorAction SilentlyContinue -
			} else { Write-Output "" }
		}
        Write-Verbose "Leftovers removed"
    } else {
    }
}

# Execute function if Ctrl+C is passed on the console.
function OnCtrlC {
    Write-Output "Ctrl+C was pressed. Executing Remove-Leftovers"
    Remove-ElasticLeftovers -path $logpath
    Write-Verbose -Message "Going back to initial location: $($InitialLocation)" 
    Push-Location -LiteralPath $InitialLocation
    Stop-Transcript
    Start-Sleep -Milliseconds 500
    Remove-ElasticLeftovers -path $logpath
    Write-Verbose "All temp files were removed."
}

# trap statement to handle Ctrl+C
trap {
    OnCtrlC
    break
}

# Current execution directory (useful to remove leftovers after deployment)
$currentLocation = Get-Location
Write-Verbose -Message "$($timestamp) Current location is: $currentLocation"

# Slack-Error notification. If This is required, uncomment and provide Slack API.
<#
function Invoke-SendSlack {
    param(
        [string]$errorMessage,
        [string]$SlackURI
    )
        $msg = "$($errorMessage) occurred on hostname: ${env:computername}"
        $body = @{
            username = "Elastic deployment BOT"
            pretext = "Error enountered during deployment process."
            text = $msg
            icon_emoji = "ghost"
        } | ConvertTo-Json
        if ($null -eq $SlackURI) {
            break
        }
        else {
        try {
        Invoke-RestMethod -Uri $SlackURI -Method Post -Body $body -ContentType 'application/json'
        }
        catch {
            Write-Error "Error sending Slack notification: $_"
            Add-Content -Path $errorlogfile -Value "$($timestamp) - Error sending Slack notification: $_"
            continue
        }
    }
}
#>

# In case we want to download the files from google drive, below lines should be uncomment.
# Add your links here in same order.
$originalLinks = @(
    "https://download.sysinternals.com/files/Sysmon.zip"  ## UNS Sysmon File
	"https://raw.githubusercontent.com/unsinc/files/main/UNS-Sysmon.xml"   ## UNS Sysmon Configuration File
	"https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.11.3-windows-x86_64.zip"   ## Elastic elastic-agent
    "https://raw.githubusercontent.com/unsinc/files/main/logo.ico"   ## UNS Logo ico
    "https://raw.githubusercontent.com/unsinc/files/main/logo.png"   ## UNS Logo
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
    Write-Debug "Modified URL: $downloadUrls"
}

$agentFiles = @(
    "Sysmon.zip",
    "UNS-Sysmon.xml",
	"uns-agent.zip",
    "logo.ico",
    "logo.png"
)
$agentPaths = $agentFiles | ForEach-Object { Join-Path $logpath $_ }
foreach ($i in 0..($agentPaths.Length - 1)) {
    Write-Verbose "Agent Path at Index $i : $($agentPaths[$i])" -ErrorAction SilentlyContinue
}

 

# Function to download an image from the internet
function Get-UNSFiles($downloadUrl, $installPath) {
    try {
        $webClient = New-Object System.Net.WebClient
        $downloadTask = $webClient.DownloadFileTaskAsync($downloadUrl, $installPath)
        $downloadTask.Wait()
    }
    catch {
        $errorMessage = $_.Exception
        Write-Verbose $errorMessage
        exit
    }
}
# Download files
Write-Verbose "Downloading $($agentPaths[0])"
Get-UNSFiles -downloadUrl $downloadUrls[0] -installPath $agentPaths[0]
Write-Verbose "Downloading $($agentPaths[1])"
Get-UNSFiles -downloadUrl $downloadUrls[1] -installPath $agentPaths[1]
Write-Verbose "Downloading $($agentPaths[2])"
Get-UNSFiles -downloadUrl $downloadUrls[2] -installPath $agentPaths[2]
Write-Verbose "Downloading $($agentPaths[3])"
Get-UNSFiles -downloadUrl $downloadUrls[3] -installPath $agentPaths[3]
Write-Verbose "Downloading $($agentPaths[4])"
Get-UNSFiles -downloadUrl $downloadUrls[4] -installPath $agentPaths[4]

# Create necessary directories
try {
    if (Test-Path $InstallDIR\sysmon) {
        Write-Verbose "Sysmon directory exist"
    } else {
        New-Item -Path $InstallDIR -Name "sysmon" -ItemType Directory -ErrorAction Stop
        Write-Output "Sysmon folder created successfully." 
        Write-Verbose -Message "$($timestamp) Sysmon folder created successfully."
    }
    
    if (Test-Path $InstallDIR\configs) {
        Write-Verbose "Config directory exist"

    } else {
        New-Item -Path $InstallDIR -Name "configs" -ItemType Directory -ErrorAction Stop
        Write-Output "Config folder created successfully." 
        Write-Verbose -Message "$($timestamp) Config folder created  successfully."
    }

    if (Test-Path $InstallDIR\agent) {
        Write-Verbose "Agent directory exist"
    } else {
        New-Item -Path $InstallDIR -Name "agent" -ItemType Directory -ErrorAction Stop 
        Write-Output "Agent folder created successfully."
        Write-Verbose -Message "$($timestamp) Config folder created  successfully."
    }
}
catch {
    $errorMessage = $_.Exception.Message
    "$($timestamp) Folder creation error message: $errorMessage."
    exit
    #Invoke-SendSlack -errorMessage $errorMessage
}

# Copy required files to the installation directory
function CopyFilesToDir {
    try {
        if (-not (Test-Path "$InstallDIR\sysmon\Sysmon.exe")) {
            Expand-Archive -Path $logpath\Sysmon.zip -DestinationPath $InstallDIR\sysmon -ErrorAction Stop -Verbose
            Start-Sleep -Milliseconds 500
                if (Test-Path "$InstallDIR\sysmon\Sysmon.exe") {
                    Write-Verbose "$($timestamp) Sysmon copied successfully."
                    Write-Verbose "$($timestamp) Sysmon64.exe copied successfully."
                } else {
                    Write-Error "$($timestamp) Sysmon failed to copy to $($InstallDIR)"
                    return CopyFilesToDir
                }
        } else {
            Write-Verbose "Sysmon files already exist"
        }

        Copy-Item "$logpath\UNS-Sysmon.xml" -Destination "$InstallDIR\configs\" -ErrorAction Stop
    }
    catch {
        Write-Verbose "Sysmon files copy failed"
        $errorMessage = $_.Exception.Message
        Write-Output "Error copying sysmon files because: $errorMessage"
        exit
    }
}
CopyFilesToDir


# Set current location to the installation directory
Set-Location -Path $InstallDIR -ErrorAction Stop
$currentLocation = Get-Location
Write-Verbose -Message "Setting working location of $(Get-Location)"


function Uninstall-Sysmon32 {
    param ()
    Write-Output "$($timestamp) Sysmon32 was found, uninstalling" 
    Write-Verbose -Message "$($timestamp) Sysmon32 was found, uninstalling"
    try {
        $process = Start-Process -FilePath "$InstallDIR\sysmon\Sysmon.exe" -ArgumentList "-u" -NoNewWindow -PassThru
        $process.WaitForExit()
        Start-Sleep -Milliseconds 500
        Write-Output  "$($timestamp) Uninstall of Sysmon32 is complete" 
        Write-Verbose -Message "Uninstall of Sysmon32 is complete."
        Remove-Item -Path "$InstallDIR\sysmon\Sysmon.exe" -Force -ErrorAction SilentlyContinue
    }
    catch {
        $errorMessage = $_.Exception.Message
        "$($timestamp) Error while uninstalling Sysmon32: $errorMessage"
        exit
        #Invoke-SendSlack -errorMessage $errorMessage
    }
}

# Uninstall Perch
function Uninstall-Perch {
    param()
		$arguments = "/X{18B16389-F8F8-4E48-9E78-A043D5742B99}"
        try {
                Write-Verbose "$timestamp Uninstalling Perch agent"
                $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "$arguments" -NoNewWindow -PassThru
                $process.WaitForExit()
            } catch {
                $errorMessage = $_.Exception.Message
                "$($timestamp) Error while uninstalling Sysmon32: $errorMessage"
                exit
            }
}

# Function to install Sysmon64 and configure it
function Install-Sysmon64 {
    param ()
    Write-Output "$($timestamp) Installing Sysmon64" 
    try {
        $process = Start-Process -FilePath "$InstallDIR\sysmon\Sysmon64.exe" -ArgumentList "-accepteula -i" -NoNewWindow -PassThru
        $process.WaitForExit()
        Start-Sleep -Milliseconds 500
        Write-Output "$($timestamp) Installation of Sysmon64 is complete" 
        Write-Verbose -Message "Installation of Sysmon64 is complete"
    }
    catch {
        $errorMessage = $_.Exception.Message
        "$($timestamp) Error while installing Sysmon64: $errorMessage"
        #Invoke-SendSlack -errorMessage $errorMessage
    }
}

# Function to configure running Sysmon64
function Set-Sysmon64 {
    param ()
    $sysmon64 = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
    if ($sysmon64) {
        try {
            Write-Output  "$($timestamp) Sysmon64 is running. Setting the configuration for Sysmon64." 
            $process = Start-Process -FilePath "$InstallDIR\sysmon\sysmon64.exe" -ArgumentList "-c `"$InstallDIR\configs\UNS-Sysmon.xml`"" -NoNewWindow -PassThru
            $process.WaitForExit()
            Start-Sleep -Seconds 1
            Write-Output  "$($timestamp) Configuration of Sysmon64 is complete" 
            Write-Verbose -Message "$($timestamp) Configuration of Sysmon64 is complete"
        }
        catch {
            $errorMessage = $_.Exception.Message
            "$($timestamp) Error while setting Sysmon64 config: $errorMessage"
            #Invoke-SendSlack -errorMessage $errorMessage
        }
    } else {
        Write-Output "$($timestamp) Sysmon64 was not found on the system" 
        Write-Verbose -Message "$($timestamp) Sysmon64 was not found on the system"
        return Install-Sysmon64
    }
}

#Execute next piece only if service is in "Running" State
function Wait-Service {
    param (
        [Parameter(Mandatory=$true)]
        [string]$serviceName,
        [Parameter(Mandatory=$true)]
        [string]$status
    )

    $service = Get-Service -Name $serviceName
    while ($service.Status -ne $status) {
        Start-Sleep -Seconds 1
        $service.Refresh()
    }
}

# Function to popup token form
function Show-TokenForm {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Create a form
    $form = New-Object Windows.Forms.Form
    $form.Text = 'UNS Elastic'
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
        Write-Verbose "Token already provided"
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
        Write-Verbose "fLeetURL already provided"
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

#Function to deploy Elastic Agent
function Install-ElasticAgent {
    param (
    )
        try {
			Write-Output "$timestamp : Downloading and installing elastic agent."

            Start-Sleep -Milliseconds 500

                #Unzipping files
                try {
                    # Try unzipping the files
                    Write-Verbose "LogPath is: $logpath"
                    $archiveFile = $logpath.Trim() + $agentFiles[2].Trim()
                    Write-Verbose "Archive file is $archiveFile"
                    Expand-Archive $archiveFile -DestinationPath $logpath\agent -Force -ErrorAction Stop
                    Start-Sleep -Milliseconds 500
                    Write-Verbose "All files were unzipped, moving files to $installDIR\agent now..."
                }
                catch {
                    $errorMessage = $_.Exception
                    Write-Output "$($timestamp) Agent files copy failed because of $($errorMessage)"
                    exit
                }
                # moving files to ProgramFiles directory
                try {
                    $agentVersion = (Get-ChildItem $logpath\agent -Filter "elastic-agent-*").Name
                    Write-Verbose "Agent version path: $agentVersion"

                    $agentSrcPath = ($logpath.Trim() + 'agent\' + $agentVersion.Trim())
                    Write-Verbose "Agent source path: $agentSrcPath"
                    $agentDstPath = "$($InstallDIR)\agent"
                    Write-Verbose "Agent destination path: $agentDstPath"

                    # Move all items from the source to the destination
                    Write-Verbose "Moving agent files from $agentSrcPath to $agentDstPath"
                    Get-ChildItem -Path $agentSrcPath -Recurse | ForEach-Object {
                    $destination = $agentDstPath + $_.FullName.Substring($agentSrcPath.Length)
                    $itemtype = (Get-ChildItem $destination -ErrorAction SilentlyContinue | ForEach-Object { $_.Extension })
                    Write-Verbose "Moving item $($_.FullName) (type: $itemType) to $destination"
                        try {
                            Move-Item -Path $_.FullName -Destination $destination -Force -ErrorAction Stop
                        }
                        catch {
                            Write-Verbose "Failed to move item $($_.FullName) to $($destination+':') $($_.Exception.Message)"
                            Remove-ElasticLeftovers -path $InstallDIR\agent
                            exit
                        }
                    
                    }
                    Write-Verbose "All files were moved to $InstallDIR\agent"
                }
                catch {
                    $errorMessage = $_.Exception
                    Write-Output "$($timestamp) Moving agent files to $agentDstPath failed because of $($errorMessage)"
                    Remove-ElasticLeftovers -path $InstallDIR\agent
                    exit
                }
                
                # Checking if tokens and URL is provided and triggering token Form
                Write-Verbose "Starting Fleet and Token procedures. Current values are: $fleetURL and $token"
                Start-Sleep -Seconds 2
                if (($fleetURL) -and (-not $token)) {
                    Write-Verbose "Fleet URL is already provided: $fleetURL"
                    Write-Verbose "Missing token. Initiating form input."
                    $token = Show-TokenForm
                } elseif (($token) -and (-not $fleetURL)) {
                    Write-Verbose "Token is already provided: $token"
                    Write-Verbose "Missing FleetURL. Initiating form input."
                    $fleetURL = Show-TokenForm
                    Write-Verbose "FleetURL provided: $fleetURL"
                } else {
                    $tokenVars = Show-TokenForm
                    $token = $tokenVars[0]
                    $fleetURL = $tokenVars[1]
                }

                Write-Verbose "Token provided is: $token"
                Write-Verbose "FleetURL provided is: $fleetURL"

                    if (($null -eq $token) -or ($null -eq $fleetURL)) {
                        Write-Verbose "$($timestamp): Token is empty. Seems that the user cancelled the input"
                        Write-Output "User cancelled the input"
                        exit

                    } else {

                        Write-Verbose "Tokens are provided, deployment can continue"
                    }
            
            
         	$arguments = "install -f"
            $arguments += " --url=$fleetURL"
            $arguments += " --enrollment-token=$token"

            Write-Verbose -Message "$($timestamp) Elastic agent Path: $InstallDIR`agent"
            Write-Verbose -Message "$($timestamp) Elastic fleet URL: $fleetURL"
            Write-Verbose -Message "$($timestamp) Elastic enrollment token: $token"
            
            # additional check if token was provided and value is not null
            if ($null -eq $token) {
                Write-Verbose "Token issues after token forms"
                Remove-ElasticLeftovers -path $InstallDIR\agent
                exit

            } else {
                # installing elastic services
                try {
                    Write-Verbose "Installing ElasticSIEM Agent..."
                # Insalling UNS SIEM Agent
                $process = Start-Process -FilePath "$InstallDIR\agent\elastic-agent.exe" -ArgumentList $arguments -NoNewWindow -PassThru
                $process.WaitForExit()
                
                Write-Verbose -Message "$($timestamp) Elastic Agent has been installed."
                Start-Sleep -Milliseconds 3
                }
                catch {
                    $errorMessage = $_.Exception
                    Write-Output "$($timestamp) Installation failed because of $($errorMessage)"
                    Remove-ElasticLeftovers -path $InstallDIR\agent
                    exit
                }

                #modifying services
                if (Get-Service -Name "Elastic Agent") {
                    try {
                        #Delete and recreate service:
                        Write-Verbose "Services operations began:"
                        Start-Sleep -Milliseconds 500
                        Write-Verbose "Stopping elastic agent service"
                        Stop-Service -Name "Elastic Agent" -ErrorAction Stop
                        Start-Sleep -Milliseconds 500
                        Write-Verbose "Renaming elastic agent to UNSAgent.exe"
                        Rename-Item -Path "$InstallDIR\agent\elastic-agent.exe" -NewName "UNSAgent.exe" -ErrorAction Stop
                        Start-Sleep -Milliseconds 500
                        Write-Verbose "Deleting Elastic Agent service"
                        sc.exe delete "Elastic Agent" -ErrorAction Stop
                        Start-Sleep -Milliseconds 500
                        Write-Verbose "Creating UNSAgent service with $InstallDIR\agent\UNSAgent.exe service path"
                        sc.exe create "UNSAgent" binPath= "$InstallDIR\agent\UNSAgent.exe" start= "auto" DisplayName= "UNS SIEM Agent"
                        Start-Sleep -Milliseconds 500
                        Write-Verbose "Setting UNSAgent service description."
                        sc.exe description "UNSAgent" "UNS SIEM Agent is elastic-based unified agent to observe, monitor and protect your system."
                        Start-Sleep -Milliseconds 500
                        Write-Verbose "Attempting to start new service"
                        Start-Service -Name "UNSAgent"
                        Wait-Service -serviceName "UNSAgent" -status "Running"
                        if ((Get-Service "UNSAgent").Status -eq "Running") {
                            Write-Verbose "'UNSAgent' service, successfully started."
                        }
    
                    }
                    catch {
                        $errorMessage = $_.Exception
                        Write-Output "$($timestamp) Modifying services failed because of $($errorMessage)"
                        Remove-ElasticLeftovers -path $InstallDIR\agent
                        Remove-Item -Path $InstallDIR\agent -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        } 
        catch {
                $errorMessage = $_.Exception
                Write-Output "$($timestamp) UNS ElasticSIEM Agent deployment failed because of $($errorMessage)"
                Remove-ElasticLeftovers -path $InstallDIR\agent
                Remove-Item -Path $InstallDIR\agent -Recurse -Force -ErrorAction SilentlyContinue
                break
        }
}

### ACTION ###
try {
    
    if (Get-Service -Name Perch*) {
        Uninstall-Perch
    } else 
        {Write-Output "Perch is not installed on the system"
    }
    if ($null -eq $sysmon32) {
        $sysmon64 = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
        if ($sysmon64) {
            Write-Output "Sysmon64 already is already installed."
        } else {
            Write-Verbose "Sysmon64 is not installed on the system. Installing..."
            Install-Sysmon64
            Set-Sysmon64
        }    
    } else {
        Write-Verbose "Uninstalling Sysmon32"
        Uninstall-Sysmon32
        Start-Sleep -Seconds 1
        Write-Verbose "Installing Sysmon64"
        Install-Sysmon64
        Start-Sleep -Seconds 1
        Write-Verbose "Setting Sysmon64 config"
        Set-Sysmon64
        Start-Sleep -Seconds 1
    }

    if (($null -eq (Get-Service -Name Perch*)) -and (Get-Service -Name Sysmon64)) { 
        Install-ElasticAgent
            if ($null -ne (Get-Service -Name "UNSAgent")) {
                Write-Verbose "UNS SIEM Agent successfully installed"
            }
    } else {
        Write-Output "Something went wrong"
    }

    if (Get-Service -Name "UNSAgent") {

        Write-Verbose "Setting update task..."
        # Define the task properties
        $taskName = "UNS Update Task"
        $taskDescription = "This task checks a private GitHub repository for updates"
        $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command {iex (Invoke-RestMethod -Uri `"https://raw.githubusercontent.com/unsinc/unsagent/testing/files/task.ps1`" -Headers @`{`"Authorization`" = `"token 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`"`})}"
        $taskTrigger1 = New-ScheduledTaskTrigger -Daily -At 9am
        $taskTrigger2 = New-ScheduledTaskTrigger -Daily -At 9pm
    
        # Define the principal to run the task with system privileges
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
        try {
           # Register the task
            Register-ScheduledTask -Action $taskAction -Trigger $taskTrigger1, $taskTrigger2 -TaskName $taskName -Description $taskDescription -Principal $taskPrincipal 
            Start-Sleep -Seconds 1
            if (Get-ScheduledTask -TaskName $taskName) {
                Write-Verbose "UNS Update Task creation successful"
            }
        }
        catch {
            $errorMessage = $_.Exception
            Write-Output "$($timestamp) UNS Agent Update Task creation failed because of $($errorMessage)"
        }
    }

}
catch {
    $errorMessage = $_.Exception
    Write-Output "$($timestamp) UNS ElasticSIEM Agent deployment failed because of $($errorMessage)"
}
finally {
    Remove-ElasticLeftovers -path $logpath
    Write-Verbose -Message "Going back to initial location: $($InitialLocation)" 
    Push-Location -LiteralPath $InitialLocation
    Stop-Transcript -ErrorAction SilentlyContinue
    Remove-Item -Recurse $logpath
    Write-Verbose "All temp files were removed."
}
### END ACTIN ###