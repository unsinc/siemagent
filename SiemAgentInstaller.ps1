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

    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)
if($invalid_parameter)
{
    Write-Output "[-] $($invalid_parameter) is not a valid parameter"
    throw

}

# Check if the script is running with elevated privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script with elevated privileges
    Write-Output "[-] Administrator privileges required."
    Start-Sleep 5
    exit
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


## setttings ##
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($fleetURL) {
Write-Verbose "$(Get-FormattedDate) URL is: $fleetURL"
}
if ($token) {
Write-Verbose "$(Get-FormattedDate) oken is: $token"
}

$currentLocation = Get-Location
$InitialLocation = $currentLocation
Write-Verbose -Message "$(Get-FormattedDate) Initial location is: $($InitialLocation)"

#Perform spelling check and create logpath folder for all further actions.
[String]$logpath = $logpath -replace '\\\\+', '\'
[String]$logpath = $logpath -replace '\\+$', '\'

if ($logpath) {
    [String]$unsfiles = "UNSFiles\"
    if ($logpath -like "*\") {

        [String]$logpath = $logpath.Trim(), $unsfiles -join ''
        Write-Verbose "$(Get-FormattedDate) Custom Log Path selected. Log path will be $logpath"

    } else {
        
        [String]$logpath = $logpath.Trim(), "\", $unsfiles -join ''
        Write-Verbose "$(Get-FormattedDate) Custom Log Path selected. Log path will be $logpath"
    }
    if (Test-Path $logpath) {
        Write-Verbose "$(Get-FormattedDate) $logpath directory exist."
    } else {
        try {
            New-Item -Path $logpath -ItemType Directory -Force -ErrorAction Stop
        }
        catch [System.IO.PathTooLongException] {
            $errorMessage = "File Path too long. Maximum allowed characters 256."
            throw $errorMessage
            Start-Sleep 5
            exit
        }
        catch {
            $errorMessage = $_.Exception
            Write-Output "$(Get-FormattedDate) $logpath folder creation failed because of: $errorMessage"
            Start-Sleep 5
            exit
        }
    }
} else {
    [String]$logpath = $env:temp.Trim(), "\UNSFiles\" -join ''
    Write-Verbose -Message "$(Get-FormattedDate) Default LogPath is: $logpath"
}

$transcriptFilePath = Join-Path -Path $logpath -ChildPath "UNSAgent_Installer_Transcript_$(Get-FormattedDate).txt"
Start-Transcript -Path $transcriptFilePath


# Download folder in case files are being downloaded from internet.
$downloadFolder = $logpath
Write-Verbose -Message "$(Get-FormattedDate) Download Folder is: $downloadFolder"

#Default Install Directory
$InstallDIR = $env:programfiles + '\UNS SIEM Agent'
if (Test-Path $InstallDIR) {
    "Exist" | Out-Null
} else {
    try {
        New-Item -Path $InstallDIR -ItemType Directory
        Write-Output "Setting up Install DIR to $($InstallDIR)" 
        Write-Verbose -Message "$(Get-FormattedDate) Default Installation Directory is: $InstallDIR"
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
				Remove-Item -Path $item -Recurse -Force -ErrorAction SilentlyContinue -Exclude "*.log"
			} else { Write-Output "" }
		}
        Write-Verbose "$(Get-FormattedDate) Leftovers removed"
    } else {
    }
}

# Current execution directory (useful to remove leftovers after deployment)
$currentLocation = Get-Location
Write-Verbose -Message "$(Get-FormattedDate) Current location is: $currentLocation"

# In case we want to download the files from google drive, below lines should be uncomment.
# Add your links here in same order.
$originalLinks = @(
    "https://download.sysinternals.com/files/Sysmon.zip"  ## UNS Sysmon File
	"https://raw.githubusercontent.com/unsinc/siemagent/main/files/UNS-Sysmon.xml"   ## UNS Sysmon Configuration File
	"https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.11.4-windows-x86_64.zip"   ## Elastic elastic-agent
    "https://raw.githubusercontent.com/unsinc/siemagent/main/files/logo.ico"   ## UNS Logo ico
    "https://raw.githubusercontent.com/unsinc/siemagent/main/files/logo.png"   ## UNS Logo
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
    Write-Verbose "$(Get-FormattedDate) Agent Path at Index $i : $($agentPaths[$i])" -ErrorAction SilentlyContinue
}


# Function to download files from the internet
function Get-UNSFiles($downloadUrl, $installPath) {
    $retryCount = 0
    do {
        try {
            $webClient = New-Object System.Net.WebClient
            $downloadTask = $webClient.DownloadFileTaskAsync($downloadUrl, $installPath)
            $downloadTask.Wait()
            $downloadSuccessful = $true
        }
        catch {
            $errorMessage = $_.Exception
            Write-Error "$(Get-FormattedDate) Failed to download files for following reasons: $errorMessage"
            $downloadSuccessful = $false
            $retryCount++
        }
    } while (-not $downloadSuccessful -and $retryCount -lt 3)

    if (-not $downloadSuccessful) {
        Write-Error "$(Get-FormattedDate) Failed to download files after 3 attempts"
        exit
    }
}

# Download files
for ($i=0; $i -lt $downloadUrls.Length; $i++) {
    Write-Verbose "$(Get-FormattedDate) Downloading $($agentPaths[$i])"
    Get-UNSFiles -downloadUrl $downloadUrls[$i] -installPath $agentPaths[$i]
}

# Create necessary directories
try {
    $directories = @("sysmon", "configs")

    foreach ($dir in $directories) {
        $dirPath = Join-Path -Path $InstallDIR -ChildPath $dir
        if (-not (Test-Path $dirPath)) {
            New-Item -Path $dirPath -ItemType Directory -Force -ErrorAction Stop
            Write-Output "$dir folder created successfully." 
            Write-Verbose "$(Get-FormattedDate) $dir folder created successfully."
        } else {
            Write-Verbose "$(Get-FormattedDate) $dir directory exists"
        }
    }

}
catch {
    $errorMessage = $_.Exception.Message
    Write-Error "$(Get-FormattedDate) Folder creation error message: $errorMessage."
    exit
}

# Copy required files to the installation directory
function CopyFilesToDir {
    $retryCount = 0
    do {
        try {
            if (-not (Test-Path "$InstallDIR\sysmon\Sysmon.exe")) {
                Expand-Archive -Path $logpath\Sysmon.zip -DestinationPath $InstallDIR\sysmon -ErrorAction Stop -Verbose
                if (Test-Path "$InstallDIR\sysmon\Sysmon.exe") {
                    Write-Verbose "$(Get-FormattedDate) Sysmon copied successfully."
                    Write-Verbose "$(Get-FormattedDate) Sysmon64.exe copied successfully."
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
                Copy-Item "$logpath\UNS-Sysmon.xml" -Destination "$InstallDIR\configs\" -ErrorAction Stop
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
        catch [FileNotFoundException] {
            Write-Output "$(Get-FormattedDate) File not found. Attempting to download again."
            throw
            $copySuccessful = $false
            $retryCount++
            throw 
        }
        catch {
            Write-Error "Sysmon files copy failed"
            $errorMessage = $_.Exception.Message
            Write-Error "$(Get-FormattedDate) Error copying sysmon files because: $errorMessage"
            $copySuccessful = $false
            $retryCount++
        }
    } while (-not $copySuccessful -and $retryCount -lt 3)

    if (-not $copySuccessful) {
        Write-Error "$(Get-FormattedDate) Failed to copy Sysmon files after 3 attempts"
        exit
    }
}
CopyFilesToDir

# Set current location to the installation directory
Set-Location -Path $InstallDIR -ErrorAction Stop
$currentLocation = Get-Location
Write-Verbose -Message "$(Get-FormattedDate) Setting working location of $(Get-Location)"


function Uninstall-Sysmon32 {
    param ()
    Write-Output "$(Get-FormattedDate) Sysmon32 was found, uninstalling" 
    Write-Verbose "$(Get-FormattedDate) Sysmon32 was found, uninstalling"
    try {
        $process = Start-Process -FilePath "$InstallDIR\sysmon\Sysmon.exe" -ArgumentList "-u force"  -NoNewWindow -PassThru
        $process.WaitForExit()
        Write-Output  "$(Get-FormattedDate) Uninstalling Sysmon32 completed" 
        Write-Verbose "$(Get-FormattedDate) Uninstalling Sysmon32 completed."
        Remove-Item -Path "$InstallDIR\sysmon\Sysmon.exe" -Force -ErrorAction SilentlyContinue
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Error "$(Get-FormattedDate) Error while uninstalling Sysmon32: $errorMessage"
        exit
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
                Write-Error "$(Get-FormattedDate) Error while uninstalling Sysmon32: $errorMessage"
                exit
            }
}

# Function to install Sysmon64 and configure it
function Install-Sysmon64 {
    param ()
    Write-Output "$(Get-FormattedDate) Installing Sysmon64" 
    try {
        $process = Start-Process -FilePath "$InstallDIR\sysmon\Sysmon64.exe" -ArgumentList "-accepteula -i" -NoNewWindow -PassThru
        $process.WaitForExit()
        Write-Output "$(Get-FormattedDate) Installation of Sysmon64 is complete" 
        Write-Verbose -Message "Installation of Sysmon64 is complete"
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Error "$(Get-FormattedDate) Error while installing Sysmon64: $errorMessage"
        #Invoke-SendSlack -errorMessage $errorMessage
    }
}

# Function to configure running Sysmon64
function Set-Sysmon64 {
    param ()
    $sysmon64 = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
    if ($sysmon64) {
        try {
            Write-Output  "$(Get-FormattedDate) Sysmon64 is running. Setting the configuration for Sysmon64." 
            $process = Start-Process -FilePath "$InstallDIR\sysmon\sysmon64.exe" -ArgumentList "-c `"$InstallDIR\configs\UNS-Sysmon.xml`"" -NoNewWindow -PassThru
            $process.WaitForExit()
            Write-Output "$(Get-FormattedDate) Configuration of Sysmon64 is complete" 
            Write-Verbose "$(Get-FormattedDate) Configuration of Sysmon64 is complete"
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Error "$(Get-FormattedDate) Error while setting Sysmon64 config: $errorMessage"
        }
    } else {
        Write-Error "$(Get-FormattedDate) Sysmon64 was not found on the system" 
        Write-Verbose "$(Get-FormattedDate) Sysmon64 was not found on the system"
        exit
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

#Function to deploy Elastic Agent
function Install-ElasticAgent {
    param (
    )
        try {
			Write-Output "$(Get-FormattedDate) Downloading and installing elastic agent."

            Start-Sleep -Milliseconds 500

                #Unzipping files
                Write-Verbose "$(Get-FormattedDate) Unzipping agent files, it will take few seconds..."
                try {
                    # Try unzipping the files
                    Write-Verbose "$(Get-FormattedDate) LogPath is $logpath"
                    $archiveFile = $logpath.Trim() + $agentFiles[2].Trim()
                    Write-Verbose "$(Get-FormattedDate) Archive file is $archiveFile"
                    Expand-Archive $archiveFile -DestinationPath $logpath -Force -ErrorAction Stop
                    $agentinstallPath = $logpath.Trim() + (Get-Item -Path $logpath\elastic-agent-*).Name
                    
                    Start-Sleep -Milliseconds 500
                    Write-Verbose "$(Get-FormattedDate) All files were unzipped, installing agent..."
                }
                catch {
                    $errorMessage = $_.Exception
                    Write-Error "$(Get-FormattedDate) Agent files copy failed because of $($errorMessage)" -ErrorAction Stop
                    exit
                }
                
                # Checking if tokens and URL is provided and triggering token Form
                Write-Verbose "$(Get-FormattedDate) Starting Fleet and Token procedures."
                Start-Sleep -Milliseconds 300
                if (($fleetURL) -and (-not $token)) {
                    Write-Verbose "$(Get-FormattedDate) Fleet URL is already provided: $fleetURL"
                    Write-Verbose "$(Get-FormattedDate) Missing token. Initiating form input."
                    $token = Show-TokenForm
                    if (($null -eq $token) -or ($token.Length -lt 30)) {
                        Write-Error "$(Get-FormattedDate): Token is empty or too short. Seems that the user cancelled the input or did not provided required value" -ErrorAction Stop
                        exit
                    }
                } elseif (($token) -and (-not $fleetURL)) {
                    Write-Verbose "$(Get-FormattedDate) Token is already provided: $token"
                    Write-Verbose "$(Get-FormattedDate) Missing FleetURL. Initiating form input."
                    $fleetURL = Show-TokenForm
                    if (($null -eq $fleetURL) -or ($fleetURL.Length -lt 30)) {
                        Write-Error "$(Get-FormattedDate): fleetURL is empty or too short. Seems that the user cancelled the input or did not provided required values" -ErrorAction Stop
                        exit
                    }
                    Write-Verbose "$(Get-FormattedDate) FleetURL provided: $fleetURL"

                } else {
                    $tokenVars = Show-TokenForm
                    $token = $tokenVars[0]
                    $fleetURL = $tokenVars[1]
                    if (($null -ne $token) -or ($null -ne $fleetURL)) {
                        Write-Verbose "$(Get-FormattedDate) Tokens were provided"
                    } else {
                        Write-Error "$(Get-FormattedDate): fleetURL or token is empty. Seems that the user cancelled the input or did not provided required values" -ErrorAction Stop
                    }
                }

         	$arguments = "install -f"
            $arguments += " --url=$fleetURL"
            $arguments += " --enrollment-token=$token"
                
            Write-Verbose -Message "$(Get-FormattedDate) UNS SIEM Agent Install Path: $agentinstallPath"
            Write-Verbose -Message "$(Get-FormattedDate) Elastic fleet URL: $fleetURL"
            Write-Verbose -Message "$(Get-FormattedDate) Elastic enrollment token: $token"
            
            # additional check if token was provided and value is not null
            if ($null -eq $token) {
                Write-Verbose "$(Get-FormattedDate) Token issues after token forms"
                exit

            } else {
                # installing elastic services
                try {
                    Write-Verbose "$(Get-FormattedDate) Installing ElasticSIEM Agent..."
                # Insalling UNS SIEM Agent
                $process = Start-Process -FilePath "$agentinstallPath\elastic-agent.exe" -ArgumentList $arguments -NoNewWindow -PassThru
                $process.WaitForExit()
                
                Write-Verbose -Message "$(Get-FormattedDate) Elastic Agent has been installed."
                Start-Sleep -Milliseconds 3
                }
                catch {
                    $errorMessage = $_.Exception
                    Write-Output "$(Get-FormattedDate) Installation failed because of $($errorMessage)"
                    exit
                }

                #modifying services
                if (Get-Service -ServiceName "Elastic Agent") {
                    try {
                        #Rename elastic service:
                        Write-Verbose "$(Get-FormattedDate) Services operations started:"
                        Start-Sleep -Milliseconds 500
                        Write-Verbose "$(Get-FormattedDate) Stopping elastic agent service"
                        try {
                            Stop-Service -ServiceName "Elastic Agent" -ErrorAction Stop 
                            Write-Verbose "$(Get-FormattedDate) Elastic agent service stopped"
                        }
                        catch {
                            $errorMessage = $_.Exception
                            Write-Error $errorMessage -ErrorAction Stop
                        }
                        #set service displayname and description
                        Start-Sleep -Milliseconds 500
                        Write-Verbose "$(Get-FormattedDate) Renaming elastic agent service name"
                        try {

                            Set-Service -ServiceName "Elastic Agent" -DisplayName "UNS SIEM Agent" -ErrorAction Stop
                            Set-Service -ServiceName "Elastic Agent" -Description "UNS SIEM Agent is a unified agent to observe, monitor and protect your system."
                            Write-Verbose "$(Get-FormattedDate) Elastic agent service renamed to UNS SIEM Agent"
                            Write-Verbose "$(Get-FormattedDate) UNS SIEM Agent service description changed"

                        }
                        catch {
                            $errorMessage = $_.Exception
                            Write-Error $errorMessage -ErrorAction Stop
                        }
                        Start-Sleep -Milliseconds 500

                        #Moving agent files to Program Files
                        $source = $env:programfiles.Trim() + "\Elastic\Agent".Trim()
                        $destination = $env:programfiles.Trim() + "\UNS SIEM Agent\".Trim()
                        Write-Verbose "$(Get-FormattedDate) Moving files from $source to $destination"
                        try {
                            Move-Item -Path $source -Destination $destination -Force
                            Write-Verbose "$(Get-FormattedDate) Agent files moved successfully"
                        }
                        catch {
                            $errorMessage = $_.Exception
                            Write-Error $errorMessage -ErrorAction Stop
                            
                        }

                        #assuming everything went through, lets modify service binPath
                        Write-Verbose "$(Get-FormattedDate) modifying UNS SIEM Agent binPath via sc.exe"
                        # Define the base directory
                        $baseDirectory = "C:\Program Files\UNS SIEM Agent\agent\Agent\data"
                        # Get the dynamic folder
                        $dynamicFolder = Get-ChildItem -Path $baseDirectory | Where-Object { $_.PSIsContainer } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                        # Define the file you want to get
                        $agentname = "elastic-agent.exe"
                        # Get the file within the dynamic folder
                        $agentfile = Get-ChildItem -Path $dynamicFolder.FullName -Recurse -File | Where-Object { $_.Name -eq $agentname }
                        $agentfile.FullName
                        Remove-Item -Path $InstallDIR\agent\elastic-agent.exe -Force
                        New-Item -ItemType SymbolicLink -Path $InstallDIR\agent\elastic-agent.exe -Target $agentfile.FullName -Force

                        try {
                            sc.exe config "Elastic Agent" binPath= "C:\Program Files\UNS SIEM Agent\agent\elastic-agent.exe"
                            Write-Verbose "$(Get-FormattedDate) binPath modified successfully"
                        }
                        catch {
                            $errorMessage = $_.Exception
                            Write-Error $errorMessage -ErrorAction Stop
                        }

                        #Atetmpting to start uns siem agent
                        Write-Verbose "$(Get-FormattedDate)  Attempting to start UNS SIEM Agent Service"
                        try {
                            Start-Service -ServiceName "Elastic Agent"
                            Write-Verbose "$(Get-FormattedDate)  Service started successfully"
                        }
                        catch {
                            $errorMessage = $_.Exception
                            Write-Output $errorMessage
                        }
                        Wait-Service -serviceName "Elastic Agent" -status "Running"
                        
                        if ((Get-Service -ServiceName "Elastic Agent").Status -eq "Running") {
                            Write-Verbose "$(Get-FormattedDate) Everythng looks good, continue."
                        }
    
                    }
                    catch {
                        $errorMessage = $_.Exception
                        Write-Error "$(Get-FormattedDate) Modifying services failed because of $($errorMessage)" -ErrorAction Stop
                        Remove-Item -Path $InstallDIR\agent -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        } 
        catch {
                $errorMessage = $_.Exception
                Write-Error "$(Get-FormattedDate) UNS ElasticSIEM Agent deployment failed for following reason: $($errorMessage)" -ErrorAction Stop
                Remove-Item -Path $InstallDIR\agent -Recurse -Force -ErrorAction SilentlyContinue
        }
}

### ACTION ###
try {
    
    if (Get-Service -Name Perch*) {
        Uninstall-Perch
    } else 
        {Write-Output "Perch is not installed on the system"
    }
    if ($null -eq (Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue)) {
        if ((Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue)) {
            Write-Output "Sysmon64 already installed."
        } else {
            Write-Verbose "Sysmon64 not installed on the system. Installing..."
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
            if ($null -ne (Get-Service -ServiceName "Elastic Agent")) {
                Write-Verbose "UNS SIEM Agent successfully installed"
            }
    } else {
        Write-Output "Something went wrong"
    }

   <# if (Get-Service -Name "UNSAgent") {

        Write-Verbose "Setting update task..."
        # Define the task properties
        $taskName = "UNS Update Task"
        # Task description
        $taskDescription = "This task checks a private GitHub repository for updates"
        # Task action

        $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -Command {IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/unsinc/siemagent/main/files/task.ps1')}"


        # Define the trigger to run the task every 5 minutes
        $taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)

        # Define the principal to run the task with system privileges
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
        try {
           # Register the task
            Register-ScheduledTask -Action $taskAction -Trigger $taskTrigger -TaskName $taskName -Description $taskDescription -Principal $taskPrincipal 
            if (Get-ScheduledTask -TaskName $taskName) {
                Write-Verbose "UNS Update Task creation successful"
            }
        }
        catch {
            $errorMessage = $_.Exception
            Write-Error "$(Get-FormattedDate) UNS Agent Update Task creation failed because of $($errorMessage)"
            break
        }
    } #>

}
catch {
    $errorMessage = $_.Exception
    Write-Error "$(Get-FormattedDate) UNS ElasticSIEM Agent deployment failed because of $($errorMessage)"
    break
}
finally {
    Remove-ElasticLeftovers -path $logpath
    Write-Verbose -Message "Going back to initial location: $($InitialLocation)" 
    Push-Location -LiteralPath $InitialLocation
    Stop-Transcript -ErrorAction SilentlyContinue
    Write-Verbose "All temp files were removed."
}
### END ACTIN ###