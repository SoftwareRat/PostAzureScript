# Set function to test for existance of Registry valves
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


# Creating folder everything related to this script 
if((Test-Path -Path 'C:\AzureTools') -eq $true) {} Else {New-Item -Path 'C:\' -Name AzureTools -Force -ItemType Directory}
if((Test-Path -Path 'C:\AzureTools\logs') -eq $true) {} Else {New-Item -Path 'C:\AzureTools\' -Name logs -Force -ItemType Directory}
if((Test-Path -Path 'C:\AzureTools\GameStream') -eq $true) {} Else {New-Item -Path 'C:\AzureTools\' -Name GameStream -Force -ItemType Directory}
Start-Transcript -Path "C:\AzureTools\logs\script.log"

function CheckOSsupport {
    if($osType.Caption -like "*Windows Server 2012 R2*") {
        # When OS is Server 2012 R2
        Write-Host -Object ('Your OS ({0}) is supported' -f $OSType.Caption) -ForegroundColor Green
    } elseif ($osType.Caption -like "*Windows Server 2019*" -or $osType.Caption -like "*Windows Server 2016*") {
        # When OS is Server 2016 or 2019
        Write-Host -Object ('Your OS ({0}) is supported' -f $OSType.Caption) -ForegroundColor Green
    } else {
        Write-Host -ForegroundColor Red ("
        Sorry, but we dont support your OS ({0}) at the moment.
        We are currently supporting following Windows versions:
        Microsoft Windows Server 2012 R2
        Microsoft Windows Server 2016
        Microsoft Windows Server 2019
        Please use the OS above or suggest your OS in GitHub, thanks :)
        " -f $osType.Caption)
        throw "Unsupported OS detected"
    }
}

function TestForAzure {
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
        Start-Sleep -Seconds 3
        throw "No Azure instance detected."
        }
}

function ManageWindowsFeatures {
    # Enable .NET 3.5 for running software based on this framework
    # Source: https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/enable-net-framework-35-by-using-windows-powershell#steps
    Install-WindowsFeature -Name 'Net-Framework-Core' | Out-Null
    if($osType.Caption -like "*Windows Server 2012 R2*") {
    Install-WindowsFeature -Name "qWave" | Out-Null
    }
    # Enable DirectPlay for older games
    Install-WindowsFeature -Name 'DirectPlay' | Out-Null
    # Disable Internet Explorer for security reasons and better open-source alternatives
    Uninstall-WindowsFeature -Name 'Internet-Explorer-Optional-amd64' -NoRestart | Out-Null
    # Disable Windows Media Player for security reasons and better open-source alternatives
    Uninstall-WindowsFeature -Name 'WindowsMediaPlayer' -NoRestart | Out-Null
}

function InstallChocolatey {
    # Download and install Chocolatey [Package Manager for Windows]
    Write-Output "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    (New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1') | Out-Null
    # Enable to execute PowerShell scripts silently without to confirm
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "feature enable -n allowGlobalConfirmation" -Wait | Out-Null
}

function InstallGameLaunchers {
# Download and install most common game launchers 
    # Download and install Steam
    Write-Host -Object 'Downloading and installing Steam'
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install steam" -Wait | Out-Null
    # Download and install Epic Games Launcher
    Write-Host -Object 'Downloading and installing EpicGames Launcher'
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install epicgameslauncher" -Wait | Out-Null
    # Download and install Origin
    Write-Host -Object 'Downloading and installing Origin'
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install origin" -Wait | Out-Null
    # Download and install Ubisoft Connect [earlier known as uPlay]
    Write-Host -Object 'Downloading and installing Ubisoft Connect'
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install ubisoft-connect" -Wait | Out-Null
    # Download and install GOG GALAXY
    Write-Host -Object 'Downloading and installing GOG GALAXY'
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install goggalaxy" -Wait | Out-Null
}

function InstallCommonSoftware {
# Download and install most common software
    # Download and install 7-Zip
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install 7zip" -Wait | Out-
    # Download and install Google Chrome
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install googlechrome" -Wait | Out-Null
    # Download and install VLC media Player
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install vlc" -Wait | Out-Null
    # Download Microsoft Visual C++ Redist
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install vcredist140" -Wait | Out-Null
}

function StreamingSolutionSelection {
    Do{
        Clear-Variable selection -ErrorAction SilentlyContinue
        $Selection = Read-Host "Do you want Moonlight or Parsec? (M|P)"
        switch($Selection){
            M{"Selected Moonlight"}
            P{"Secected Parsec"}
        }}until($Selection -match 'M|P')
}

function CheckForRDP {
    if([bool]((quser) -imatch "rdp")) {
        Clear-Host
        Write-Error 'RDP session detected, please use alternatives like AnyDesk or VNC!'
        throw "RDP session detected"
    }
}

function InstallDrivers {
    $ExitCode = (Start-Process -FilePath "$DriverSetup" -ArgumentList "/s","/clean" -NoNewWindow -Wait -PassThru).ExitCode
    if($ExitCode -ne 0) {
        Write-Error -Message 'Driver installation failed'
        Write-Host -Object 'Downloading the Cloud GPU Updater script by jamesstringerparsec'
        
    }
}

function EnableAudio {
# Enabling Audio on Windows Server
    New-ItemProperty "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" -Name "ServicesPipeTimeout" -Value 600000 -PropertyType "DWord" | Out-Null
    Set-Service -Name "Windows Audio" -StartupType Automatic | Out-Null
    Set-Service -Name "Windows Audio Endpoint Builder" -StartupType Automatic | Out-Null 
    Start-Service -Name "Windows Audio" | Out-Null 
    Start-Service -Name "Windows Audio Endpoint Builder" | Out-Null
}

function SetWindowsSettings {
# Disable "Shutdown Event Tracker"
    if((Test-Path -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Reliability') -eq $true) {} Else {New-Item -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT' -Name Reliability -Force}
    Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Reliability' -Name ShutdownReasonOn -Value 0 -ErrorAction SilentlyContinue

# Disable Windows Update
    if((Test-RegistryValue -path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'DoNotConnectToWindowsUpdateInternetLocations') -eq $true) {Set-itemproperty -path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null} else {new-itemproperty -path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null}
    if((Test-RegistryValue -path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'UpdateServiceURLAlternative') -eq $true) {Set-itemproperty -path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null}
    if((Test-RegistryValue -path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUServer') -eq $true) {Set-itemproperty -path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null}
    if((Test-RegistryValue -path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUSatusServer') -eq $true) {Set-itemproperty -path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null}
    if((Test-RegistryValue -path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -value 'AUOptions') -eq $true) {Set-itemproperty -path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "AUOptions" -Value 1 | Out-Null} else {new-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "AUOptions" -Value 1 | Out-Null}
    if((Test-RegistryValue -path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -value 'UseWUServer') -eq $true) {Set-itemproperty -path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null} else {new-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null}

# Change "Performance for Applications"
    Set-ItemProperty -Path "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" -Name "PriorityControl" -Value 00000026 | Out-Null

# Set automatic Time and Timezone
    Set-ItemProperty -path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Name Type -Value NTP | Out-Null
    Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate' -Name Start -Value 00000003 | Out-Null

# Disable "New network window"
    if((Test-RegistryValue -path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network' -Value NewNetworkWindowOff)-eq $true) {} Else {new-itemproperty -path registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network -name "NewNetworkWindowOff" | Out-Null}

# Disable logout and lock user from start menu
    if((Test-RegistryValue -Path 'registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Value StartMenuLogOff )-eq $true) {Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null} Else {New-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null}
    if((Test-Path -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') -eq $true) {} Else {New-Item -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name Software | Out-Null}
    if((Test-RegistryValue -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Value DisableLockWorkstation) -eq $true) {Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null } Else {New-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null}

# Disable "Recent start menu" items
    if((Test-Path -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') -eq $true) {} Else {New-Item -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\' -Name Explorer | Out-Null}
    if((Test-RegistryValue -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Value HideRecentlyAddedApps) -eq $true) {} Else {New-Item -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\' -Name Explorer | Out-Null}
    New-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer' -PropertyType DWORD -Name HideRecentlyAddedApps -Value 1 -ErrorAction SilentlyContinue | Out-Null 
}

function DownloadNVIDIAdrivers {
# Downloading NVIDIA drivers
if($osType.Caption -like "*Windows Server 2012 R2*") {
    # This command get executed when OS is Server 2012
    Write-Host -Object ('Detected OS: ({0})' -f $OSType.Caption) -ForegroundColor Green    
    $azuresupportpage = (Invoke-WebRequest -Uri https://docs.microsoft.com/en-us/azure/virtual-machines/windows/n-series-driver-setup -UseBasicParsing).links.outerhtml -like "*server2012R2*"
    $GPUversion = $azuresupportpage.split('(')[1].split(')')[0]
    (New-Object System.Net.WebClient).DownloadFile($($azuresupportpage[0].split('"')[1]), 'C:\AzureTools' + "\" + $($GPUversion) + "_grid_server2012R2_64bit_azure_swl.exe")
    $DriverSetup = 'C:\AzureTools' + "\" + $($GPUversion) + "_grid_server2012R2_64bit_azure_swl.exe"
} else {
    # This command get executed when OS is Server 2016/2019
    Write-Host -Object ('Detected OS: ({0})' -f $OSType.Caption) -ForegroundColor Green
    $azuresupportpage = (Invoke-WebRequest -Uri https://docs.microsoft.com/en-us/azure/virtual-machines/windows/n-series-driver-setup -UseBasicParsing).links.outerhtml -like "*GRID*"
    $GPUversion = $azuresupportpage.split('(')[1].split(')')[0]
    (New-Object System.Net.WebClient).DownloadFile($($azuresupportpage[0].split('"')[1]), 'C:\AzureTools' + "\" + $($GPUversion) + "_grid_win10_server2016_server2019_64bit_azure_swl.exe")
    $DriverSetup = 'C:\AzureTools' + "\" + $($GPUversion) + "_grid_win10_server2016_server2019_64bit_azure_swl.exe"
    }
}

function Autologon {
    $Pass = Read-Host -Prompt "Enter password for $env:UserName" -AsSecureString
    $RegistryPath = 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String
    $PassPlaintext = $Pass | ConvertFrom-SecureString
    Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "$env:UserName" -type String 
    Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "$PassPlaintext" -type String
}

function DisableVGA {
# Disable non-NVIDIA GPU's
    if($osType.Caption -like "*Windows Server 2012 R2*") {
        # This command get executed when OS is Server 2012
        Start-Process -FilePath $($WorkDir) + '\Tools\devcon.exe' -ArgumentList '/r disable *Microsoft Hyper-V Video*' -Wait -NoNewWindow
    } else {
        # This command get executed when OS is Server 2016/2019
        Get-PnpDevice -Class "Display" -Status OK | Where-Object { $_.Name -notmatch "nvidia" } | Disable-PnpDevice -confirm:$false | Out-Null
    }
}

Function ProgressWriter {
    param (
    [int]$percentcomplete,
    [string]$status
    )
    Write-Progress -Activity "Azure VM will be prepared for CloudGaming" -Status $status -PercentComplete $PercentComplete
    }

function GameStream {
    Write-Output -InputObject 'Downloading GameStream Patcher [CREDIT: acceleration3]'
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/acceleration3/cloudgamestream/master/Steps/Patcher.ps1", "C:\AdminTools\GameStream\Patcher.ps1")
    # Allowing GameStream Rules via Windows Firewall [for Moonlight]
    New-NetFirewallRule -DisplayName "NVIDIA GameStream TCP" -Direction Inbound -LocalPort 47984,47989,48010 -Protocol TCP -Action Allow | Out-Null
    New-NetFirewallRule -DisplayName "NVIDIA GameStream UDP" -Direction Inbound -LocalPort 47998,47999,48000,48010 -Protocol UDP -Action Allow | Out-Null
}

# Set $osType for checking for OS
$osType = Get-CimInstance -ClassName Win32_OperatingSystem

# Changing Title to "First-time setup for Gaming on Microsoft Azure"
$host.ui.RawUI.WindowTitle = "Automate Azure CloudGaming Tasks [Version 0.3]"

# Changing SecurityProtocol for prevent SSL issues with websites
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

Write-Host -ForegroundColor White "
                                   ((                     
                                (((                       
                             (((((     ((
                          (((((((    (((((
                       ((((((((     (((((((
                     (((((((((     ((((((((((
                   (((((((((      ((((((((((((
                  (((((((((     ((((((((((((((((
                ((((((((((        (((((((((((((((
               (((((((((            (((((((((((((((
             ((((((((((               ((((((((((((((
            ((((((((((                  (((((((((((((
          ((((((((((                      (((((((((((((
         ((                                  (((((((((((
                            %(((((((((((((((((((((((((((((
                                  _____                 _             
     /\                          / ____|               (_)            
    /  \    _____   _ _ __ ___  | |  __  __ _ _ __ ___  _ _ __   __ _ 
   / /\ \  |_  / | | | '__/ _ \ | | |_ |/ _` | '_ ` _ \| | '_ \ / _` |
  / ____ \  / /| |_| | | |  __/ | |__| | (_| | | | | | | | | | | (_| |
 /_/    \_\/___|\__,_|_|  \___|  \_____|\__,_|_| |_| |_|_|_| |_|\__, |
                                                                 __/ |
                                                                |___/ 
                   _____           _       _   
                  / ____|         (_)     | |  
                 | (___   ___ _ __ _ _ __ | |_ 
                  \___ \ / __| '__| | '_ \| __|
                  ____) | (__| |  | | |_) | |_ 
                 |_____/ \___|_|  |_| .__/ \__|
                                    | |
                                    |_|
"

$ScripttaskList = @(

)

foreach ($func in $ScripttaskList) {
    $PercentComplete =$($ScriptTaskList.IndexOf($func) / $ScripttaskList.Count * 100)
    & $func $PercentComplete
    }