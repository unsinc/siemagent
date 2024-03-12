<#
.SYNOPSIS
UNS SIEM Agent deployment tool

.DESCRIPTION
Deployment scrip will perform following tasks:
1. Uninstall Sysmon 32 bit from the system.
2. Install Sysmon 64bit on the system.
3. Install and enforce proprietary Sysmon64 config file.
4. Deploy UNS SIEM Agent and require enrollment-token/URL input from the user, if values are not passed with -token or -fleetURL parameters.


.NOTES
File Name      : SiemAgentInstaller.ps1
Author         : nkolev@unsinc.com
Prerequisite   : PowerShell V5
Copyright	   : 2024, UNS Inc
Version		   : 2024.03.12.3

.EXAMPLE
.\SiemAgentInstaller.ps1 -Verbose

.EXAMPLE
.\SiemAgentInstaller.ps1 -token <elastic enrollment token> -fleetURL <url> -Verbose

.EXAMPLE
For additioanal help "Get-Help .\SiemAgentInstaller.ps1 -Online"

.LINK
https://github.com/unsinc/siemagent/blob/main/README.md

.PARAMETER token
Use this switch to provide an enrollment token, enabling the registration of new UNS nodes to a specific UNS SIEM instance.

.PARAMETER fleetURL
Use this switch to assign a specific UNS Fleet URL to a particular UNS SIEM instance. Format is: https://750258aff4014f51a3fvc4a9d68bf5f.fleet.us-east-1.aws.elastic-cloud.com

.PARAMETER datapath
Use this switch to indicate where deployment files are. If this switch is used, installer will not download files, but instead grab them from the indicated folder.

.PARAMETER noDownload
To be used with $datapth. When passed, script will look for files stored under datapath. If no datapath is specified while passing noDownload, datapath will default to current script location.


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
    [switch]$noDownload,

    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)

#check if invalid parameter was passed on the console
if($invalid_parameter)
{
    Write-Output "[-] $($invalid_parameter) is not a valid switch. Please type Get-Help .\SiemAgentInstaller.ps1"
    throw

}

######## Uncomment if you want to have hard-coded fleeturl and token variables ##########
#$fleetURL = "" 
#$token = ""
#datapath = (Get-Location)
#noDownload = $true
###########################################################################################

if (($noDownload) -and (-not $datapath)) {
    Write-Verbose "-noDownload was provided without -datapath. dataPath will default to current script location."
    $datapath = (Get-Location)
}

# Check dotnet version installed.
$DotNetVersionKey = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -EA 0 -name Version | Where-Object { $_.PSChildName -match '^(?!Setup)[\d\.]+' } | Select-Object -Property PSChildName, Version | Sort-Object Version -Descending | Select-Object -First 1
$Version = New-Object Version($DotNetVersionKey.Version)
$RequiredVersion = New-Object Version("4.5")


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
    exit
}

## setttings ##
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# check if fleetURL was passed on the console
if ($fleetURL) {
Write-Verbose "$(Get-FormattedDate) URL is: $fleetURL"
}
# check if token was passed on the console
if ($token) {
Write-Verbose "$(Get-FormattedDate) token is: $token"
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
            exit
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Error "$(Get-FormattedDate) $datapath folder creation failed because of: $errorMessage"
            Start-Sleep 5
            exit
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
            exit
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Error "$(Get-FormattedDate) $datapath folder creation failed because of: $errorMessage"
            Start-Sleep 5
            exit
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
if (Test-Path $InstallDIR) {
    "Exist" | Out-Null
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

Write-Output "$(Get-FormattedDate) Downloading required deployment files, please be patient."
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
            Write-Error "$(Get-FormattedDate) Asynchronous download failed. Trying synchronous download."
            try {
                $webClient.DownloadFile($downloadUrl, $installPath)
                $downloadSuccessful = $true
            }
            catch {
                Write-Error "$(Get-FormattedDate) Synchronous download failed. Trying Invoke-WebRequest."
                try {
                    Invoke-WebRequest -Uri $downloadUrl -OutFile $installPath -UseBasicParsing
                    while (!(Test-Path $installPath) -or (Get-Item $installPath).length -eq 0) {
                        Write-Host "Waiting for the file to be downloaded..."
                        Start-Sleep -Seconds 1
                    }
                    $downloadSuccessful = $true
                }
                catch {
                    $errorMessage = $_.Exception.Message
                    Write-Error "$(Get-FormattedDate) Failed to download files for following reasons: $errorMessage"
                    $downloadSuccessful = $false
                    $retryCount++
                }
            }
        }
    } while (-not $downloadSuccessful -and $retryCount -lt 3)

    if (-not $downloadSuccessful) {
        Write-Error "$(Get-FormattedDate) Failed to download files after 3 attempts"
        exit
    }
}

# verify if $noDownload
if ($noDownload) {
    Write-Verbose "$(Get-FormattedDate) `$noDownload switch provided. Looking for files in $($datapath.TrimEnd('UNSFiles\'))"
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
    $directories = @("sysmon", "configs")

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
    exit
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
        catch [FileNotFoundException] {
            Write-Output "$(Get-FormattedDate) File not found. Attempting to copy file  again."
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
        exit
    }
    #destroy the handle cache
    $null = $handle
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
            if ($process.ExitCode -ne 0) {
                throw "Installation failed with exit code $($process.ExitCode)"
            } else {
                Write-Verbose "$(Get-FormattedDate) Perch uninstall completed."
            }

        } catch {
                $errorMessage = $_.Exception.Message
                Write-Error "$(Get-FormattedDate) Error while uninstalling Sysmon32: $errorMessage"
                exit
            }
            #destroy the handle cache
            $null = $handle
}

# Function to install Sysmon64 and configure it
function Install-Sysmon64 {
    param ()
    Write-Output "$(Get-FormattedDate) Installing Sysmon64" 
    try {
        $process = Start-Process -FilePath "$InstallDIR\sysmon\Sysmon64.exe" -ArgumentList "-accepteula -i" -NoNewWindow -PassThru
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
    param ()
    $sysmon64 = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
    if ($sysmon64) {
        try {
            Write-Output  "$(Get-FormattedDate) Setting the configuration for Sysmon64." 
            $process = Start-Process -FilePath "$InstallDIR\sysmon\sysmon64.exe" -ArgumentList "-c `"$InstallDIR\configs\UNS-Sysmon.xml`"" -NoNewWindow -PassThru
            $handle = $process.Handle  # Cache the process handle
            $process.WaitForExit()

            # Check the exit code
            if ($process.ExitCode -ne 0) {
                throw "Installation failed with exit code $($process.ExitCode)"
            } else {
                Write-Output "$(Get-FormattedDate) Configuration of Sysmon64 is complete" 
                Write-Verbose "$(Get-FormattedDate) Configuration of Sysmon64 is complete"
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
        exit
    }
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
                    if (($null -eq $token) -or ($token.Length -lt 30)) {
                        Write-Error "$(Get-FormattedDate): Token is empty or too short. Seems that the user cancelled the input or did not provided required value" -ErrorAction Stop
                    }
                } elseif (($token) -and (-not $fleetURL)) {
                    Write-Verbose "$(Get-FormattedDate) Token is already provided: $token"
                    Write-Verbose "$(Get-FormattedDate) Missing FleetURL. Initiating form input."
                    $fleetURL = Show-TokenForm
                    if (($null -eq $fleetURL) -or ($fleetURL.Length -lt 30)) {
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
                
            Write-Verbose -Message "$(Get-FormattedDate) UNS SIEM Agent Install Path: $agentinstallPath"
            Write-Verbose -Message "$(Get-FormattedDate) UNS SIEM fleet URL: $fleetURL"
            Write-Verbose -Message "$(Get-FormattedDate) UNS SIEM Enrollment token: $token"
            Write-Output "$(Get-FormattedDate) UNS SIEM fleet URL: $fleetURL"
            Write-Output "$(Get-FormattedDate) UNS SIEM Enrollment token: $token"
            
            # additional check if token was provided and value is not null
            if ($null -eq $token) {
                Write-Error "$(Get-FormattedDate) Token issues after token forms"
                exit

            } else {
                # installing elastic services
                try {
                    Write-Verbose "$(Get-FormattedDate) Installing UNS SIEM Agent..."
                    Write-Output "$(Get-FormattedDate) Installing UNS SIEM Agent..."

                #Delete existing service if exists. It helps during redeployment.
                if ($null -ne (Get-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue)) {
                    Write-Output "$(Get-FormattedDate) Removing old agent service, please wait"
                    try {
                        Stop-Service -Name "Elastic Agent" -ErrorAction SilentlyContinue -Force -Confirm:$false
                        sc.exe delete "Elastic Agent"
                    }
                    catch {
                        Write-Error "Siem agent removal failed, we will try again during deployment of current version."
                    }
                    Write-Output "$(Get-FormattedDate) Old agent service removed, deploying UNS SIEM Agent"
                }

                # Insalling UNS SIEM Agent
                $process = Start-Process -FilePath "$agentinstallPath\elastic-agent.exe" -ArgumentList $arguments -NoNewWindow -PassThru
                $handle = $process.Handle  # Cache the process handle
                $process.WaitForExit()
                    # Check the exit code
                    if ($process.ExitCode -ne 0) {
                        throw "Installation failed with exit code $($process.ExitCode)"
                    } else {
                        Write-Verbose -Message "$(Get-FormattedDate) Elastic Agent has been installed."
                    }
                }
                catch {
                    $errorMessage = $_.Exception.Message
                    Write-Output "$(Get-FormattedDate) Installation failed because of $($errorMessage)"
                    exit
                }
                # destroy the handle cache
                $null = $handle

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
                            exit
                        }

                        Write-Verbose "$(Get-FormattedDate) Elastic agent service stopped."
                        
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
                            exit
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
                        Write-Verbose "$(Get-FormattedDate) Service started successfully"
    
                    }
                    catch {
                        $errorMessage = $_.Exception.Message
                        Write-Error "$(Get-FormattedDate) Modifying services failed because of $($errorMessage)" -ErrorAction Stop
                        Remove-Item -Path $InstallDIR\agent -Recurse -Force -ErrorAction SilentlyContinue
                        exit
                    }
                }
            }
        } 
        catch {
                $errorMessage = $_.Exception.Message
                Write-Error "$(Get-FormattedDate) UNS ElasticSIEM Agent deployment failed for following reason: $($errorMessage)" -ErrorAction Stop
                Remove-Item -Path $InstallDIR\agent -Recurse -Force -ErrorAction SilentlyContinue
                exit
        }
}

### ACTION ###
try {
    
    if (Get-Service -Name Perch*) {
        Uninstall-Perch
    } else 
        {Write-Verbose "$(Get-FormattedDate) Perch is not installed on the system"
    }
    if ($null -eq (Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue)) {
        if ((Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue)) {
            Write-Verbose "$(Get-FormattedDate) Sysmon64 already installed."
        } else {
            Write-Verbose "$(Get-FormattedDate) Sysmon64 not installed on the system. Installing..."
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

    if (($null -eq (Get-Service -Name Perch*)) -and (Get-Service -Name Sysmon64)) { 
        Install-ElasticAgent
            if ($null -ne (Get-Service -ServiceName "Elastic Agent")) {
                Write-Verbose "$(Get-FormattedDate) UNS SIEM Agent successfully installed"
            }
    } else {
        Write-Output "$(Get-FormattedDate) Something went wrong"
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
            $errorMessage = $_.Exception.Message
            Write-Error "$(Get-FormattedDate) UNS Agent Update Task creation failed because of $($errorMessage)"
            break
        }
    } #>

}
catch {
    $errorMessage = $_.Exception.Message
    Write-Error "$(Get-FormattedDate) UNS ElasticSIEM Agent deployment failed because of $($errorMessage)"
    break
}
finally {
    Remove-ElasticLeftovers -path $datapath
    Write-Verbose "$(Get-FormattedDate) Going back to initial location: $($InitialLocation)" 
    Push-Location -LiteralPath $InitialLocation
    Stop-Transcript -ErrorAction SilentlyContinue
    Write-Verbose "$(Get-FormattedDate) All temp files were removed."
    Write-Output "$(Get-FormattedDate) All temp files were removed."
    Write-Output "$(Get-FormattedDate) Good bye"
    Start-Sleep 5
    exit
}
### END ACTION ###