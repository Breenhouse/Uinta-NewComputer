# Updated 2/7/2020


# ------------------------

# This will run the script as admin.
# Get the ID and security principal of the current user account
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID)
# Get the security principal for the administrator role
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
# Check to see if we are currently running as an administrator
if ($myWindowsPrincipal.IsInRole($adminRole)) {
    # We are running as an administrator, so change the title and background colour to indicate this
    $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + '(Elevated)'
    Clear-Host
} 
else {
    # We are not running as an administrator, so relaunch as administrator
    # Create a new process object that starts PowerShell
    $newProcess = New-Object Diagnostics.ProcessStartInfo 'powershell.exe'
    # Specify the current script path and name as a parameter with added scope and support for scripts with spaces in its path
    $newProcess.Arguments = '-ExecutionPolicy Bypass -File "' + $script:MyInvocation.MyCommand.Path + '"'
    # Indicate that the process should be elevated
    $newProcess.Verb = 'runas'
    # Start the new process
    [System.Diagnostics.Process]::Start($newProcess)
    # Exit from the current, unelevated, process
    exit
}

# ------------------------
	
$host.UI.RawUI.WindowTitle = "Uinta - New Computer"

Write-Host '######################'
Write-Host '# Uinta Technologies #'
Write-Host '######################'
Write-Host '
This script will:
* Change peer to peer updates to local clients only
* Disable Cortana
* Turn off Microsoft Consumer Experiences
* Keep Chrome from running in the background when closed
* Enables Remote Desktop
* Set PC to never sleep when plugged in
* Changes time zone to Mountain Standard Time
* Install Adobe Reader if not installed
* Install Chrome if not installed
* Ask if you want to remove Office 365
'

Pause

# ------------------------

# Registry/Win10 Settings

Clear-Host
Write-Host 'Updating settings...'

# Only peer Windows Updates with local clients
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DownloadModeRestricted" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 1 /f

# Disables Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f

# Turn off Microsoft consumer experiences https://blogs.technet.microsoft.com/mniehaus/2015/11/23/seeing-extra-apps-turn-them-off/
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f

# Disables Chrome from running in the background when it's closed
reg add "HKLM\Software\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d 0 /f

# Enables remote desktop
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Sets PC to never sleep when plugged in
Powercfg /Change standby-timeout-ac 0

# Sets TimeZone to MST
Set-TimeZone -Name "Mountain Standard Time"

# ------------------------

# Software Install

# Import BITS for download
Import-Module BitsTransfer

# Check if Adobe Reader is installed. If installed, will move on.
$AdobeInstallCheck = Get-WmiObject -Class Win32_Product -Filter "Name='Adobe Acrobat Reader DC'"
if ($AdobeInstallCheck -ne $null){
    Clear-Host
    Write-Host 'Adobe Reader is already installed.'
}
else{
    # Create temporary directory
    $TempDirGuid = [System.Guid]::NewGuid().ToString()
    New-Item -Type Directory -Name $TempDirGuid -Path $env:TEMP | Out-Null
    $TempDir = "$env:TEMP\$TempDirGuid"
    $AdobeOutput = "$TempDir\adobeDC.exe"

    #Download software
    Clear-Host
    Write-Host 'Downloading Adobe Reader...'
    Start-BitsTransfer -Source 'http://ardownload.adobe.com/pub/adobe/reader/win/AcrobatDC/1901020098/AcroRdrDC1901020098_en_US.exe'  -Destination "$AdobeOutput"

    #Install software
    Clear-Host
    Write-Host 'Installing Adobe Reader...'

    Start-Process -FilePath $AdobeOutput -ArgumentList "/sPB /rs /msi" -Wait

    #Delete folder for software
    Remove-Item -path $TempDir -Recurse
    Clear-Host
    Write-Host 'Adobe reader has been installed.'
}

Start-Sleep -s 5

# Install Chrome

# Check if Chrome is installed. If installed, will move on.

$ChromeInstallPath1 = "$Env:ProgramFiles\Google\Chrome\Application\chrome.exe"
$ChromeInstallPath2 = "${Env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"

$ChromeInstalled = $false
if (Test-Path $ChromeInstallPath1){$ChromeInstalled = $true}
if (Test-Path $ChromeInstallPath2){$ChromeInstalled = $true}

if ($ChromeInstalled -eq $true)
{
    Clear-Host
    Write-Host 'Google Chrome is already installed.'
}
else{
    # Create temporary directory
    $TempDirGuid = [System.Guid]::NewGuid().ToString()
    New-Item -Type Directory -Name $TempDirGuid -Path $env:TEMP | Out-Null
    $TempDir = "$env:TEMP\$TempDirGuid"
    $ChromeOutput = "$TempDir\chrome_installer.exe"

    #Download software
    Clear-Host
    Write-Host ' Downloading Google Chrome...'
    Start-BitsTransfer -Source "http://dl.google.com/chrome/install/375.126/chrome_installer.exe" -Destination "$ChromeOutput"

    #Install software
    Clear-Host
    Write-Host 'Installing Google Chrome...'

    Start-Process -FilePath $ChromeOutput -Args "/silent /install" -Verb RunAs -Wait

    #Delete folder for software
    Remove-Item -path $TempDir -Recurse
    Clear-Host
    Write-Host 'Google Chrome has been installed.'
}

# ------------------------

# This will remove all instances of Office 365.

#Prompt for yes/no.

Clear-Host
$msg = 'Do you want to remove all instances of Office 365? [y/n]'
$response = Read-Host -Prompt $msg

if ($response -eq 'y') {
    Clear-Host
    Write-Host 'Removing Office 365...'
    Cscript.exe "$PSScriptRoot\OffScrubC2R.vbs" ALL /Quiet /NoCancel /Force /OSE -Wait
}

Clear-Host
Write-Host 'Scrip complete!'

pause
exit