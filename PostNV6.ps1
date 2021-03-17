# Set function to test for existance of Registry keys or valved
function Test-RegistryValue {
    # https://www.jonathanmedd.net/2014/02/testing-for-the-presence-of-a-registry-key-and-value.html
    param (
     [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Path,

    [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Value
    )

    try {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
        return $true
        }
    catch {
        return $false
        }
}

# Creating new folder to download Tools 
if((Test-Path -Path 'C:\AdminTools') -eq $true) {} Else {New-Item -Path 'C:\' -Name AdminTools -Force -ItemType Folder}

# Checking for OS
$osType = Get-CimInstance -ClassName Win32_OperatingSystem
if($osType.Caption -like "*Windows Server 2012 R2*") {
    # When OS is Server 2012 R2
    Write-Host -Object ('Your OS ({0}) is supported' -f $OSType.Caption) -ForegroundColor Green
} elseif ($osType.Caption -like "*Windows Server 2019*" -or $osType.Caption -like "*Windows Server 2016*") {
    # When OS is Server 2016 or 2019
    Write-Host -Object ('Your OS ({0}) is supported' -f $OSType.Caption) -ForegroundColor Green
} else {
Write-Host -ForegroundColor Red ("
Sorry, but we dont support ({0})
We are currently supporting following Windows versions:
Microsoft Windows Server 2012 R2
Microsoft Windows Server 2016
Microsoft Windows Server 2019
Please use the OS above or suggest your OS in GitHub, thanks :)
" -f $osType.Caption)
}

# Changing Title to "First-time setup for Gaming on Microsoft Azure"
$host.ui.RawUI.WindowTitle = "First-time setup for Gaming on Microsoft Azure"

# Changing SecurityProtocol for prevent SSL issues with websites
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 


# Checking if this script get executed on a Microsoft Azure instance
$azure = $(
# Pinging Azure Instance Metadata Service
# Source: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service?tabs=windows
Try {(Invoke-WebRequest -Uri "http://169.254.169.254/metadata/instance?api-version=2020-09-01" -Headers @{Metadata="true"} -TimeoutSec 5)}
    catch {}
    )

# IF startement for WebRequest Statuscode
if ($azure.StatusCode -eq 200) {
        # When Azure instance got detected
        Write-Host -ForegroundColor Green "Microsoft Azure Instance detected"
        }
    Else {
        # When non-azure instance got detected
        Write-Output "VM is not hosted on Azure. Aborting script..."
        throw "No Azure instance detected."
        }

# Enable .NET 3.5 for running software based on this framework
# Source: https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/enable-net-framework-35-by-using-windows-powershell#steps
Install-WindowsFeature Net-Framework-Core | Out-Null
# Enable DirectX for older games
Install-WindowsFeature DirectPlay | Out-Null
# Disable Internet Explorer
Uninstall-WindowsFeature Internet-Explorer-Optional-amd64 -NoRestart | Out-Null
# Disable Windows Media Player
Uninstall-WindowsFeature WindowsMediaPlayer -NoRestart | Out-Null
# Download and install Chocolatey [Package Manager for Windows]
Write-Output "Installing Chocolatey..."
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
(New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1') | Out-Null
# Enable to execute PowerShell scripts silently without to confirm
Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "feature enable -n allowGlobalConfirmation" -Wait | Out-Null
# Download and install most common game launchers 
    # Download and install Steam
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install steam" -Wait | Out-Null
    # Download and install Epic Games Launcher
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install epicgameslauncher" -Wait | Out-Null
    # Download and install Origin
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install origin" -Wait | Out-Null
    # Download and install Ubisoft Connect [earlier known as uPlay]
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install ubisoft-connect" -Wait | Out-Null
# Download and install most common software
    # Download and install 7-Zip
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install 7zip" -Wait | Out-Null
    

# Enabling Audio on Windows Server
Install-WindowsFeature -Name "qWave" | Out-Null
Set-Service -Name "Windows Audio" -StartupType Automatic | Out-Null
Set-Service -Name "Windows Audio Endpoint Builder" -StartupType Automatic | Out-Null 
Start-Service -Name "Windows Audio" | Out-Null 
Start-Service -Name "Windows Audio Endpoint Builder" | Out-Null

# Disable "Shutdown Event Tracker"
if((Test-Path -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Reliability') -eq $true) {} Else {New-Item -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT' -Name Reliability -Force}
Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Reliability' -Name ShutdownReasonOn -Value 0 -ErrorAction SilentlyContinue

# Disable Windows Update
if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'DoNotConnectToWindowsUpdateInternetLocations') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null}
if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'UpdateServiceURLAlternative') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null}
if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null}
if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUSatusServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name "AUOptions" -Value 1 | Out-Null
if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -value 'UseWUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null} else {new-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null}


# Change "Performance for Applications"


# Set automatic Time and Timezone
Set-ItemProperty -path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Name Type -Value NTP | Out-Null
Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate' -Name Start -Value 00000003 | Out-Null

# Disable "New network window"
if((Test-RegistryValue -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -Value NewNetworkWindowOff)-eq $true) {} Else {new-itemproperty -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -name "NewNetworkWindowOff" | Out-Null}

# Disable logout and lock user from start menu
if((Test-RegistryValue -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Value StartMenuLogOff )-eq $true) {Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null} Else {New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null}
if((Test-Path -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} Else {New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name Software | Out-Null}
if((Test-RegistryValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Value DisableLockWorkstation) -eq $true) {Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null } Else {New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null}

# Disable "Recent start menu" items
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -name Explorer -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -PropertyType DWORD -Name HideRecentlyAddedApps -Value 1 -ErrorAction SilentlyContinue | Out-Null 

# Disable non-NVIDIA GPU's
if($osType.Caption -like "*Windows Server 2012 R2*") {
    # This command get executed when OS is Server 2012
    Get-CimInstance -ClassName Win32_PnpEntity -Filter 'NAME LIKE "%Microsoft Hyper-V Video%"' | Invoke-CimMethod -MethodName Disable | Out-Null
} else {
    # This command get executed when OS is Server 2016/2019
    Get-PnpDevice -Class "Display" -Status OK | Where-Object { $_.Name -notmatch "nvidia" } | Disable-PnpDevice -confirm:$false | Out-Null
}

# Allowing GameStream Rules on