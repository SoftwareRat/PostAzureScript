# Setting argument for using Script after Reboot [Moonlight only]
param (
    [switch]$MoonlightAfterReboot = $false,
    [switch]$nvdrivers = $false
)

if(!$MoonlightAfterReboot) {
    # Start logging for this script after reboot
    if((Test-Path -Path "C:\AWSTools\logs\ScriptReboot.log") -eq $true) {
        Rename-Item -Path "C:\AWSTools\logs\ScriptReboot.log" -NewName 'ScriptRebootOLD.log'
    } if((Test-Path -Path "C:\AWSTools\logs\ScriptRebootOLD.log") -eq $true) {
    Remove-Item -Path "C:\AWSTools\logs\ScriptRebootOLD.log"
} Start-Transcript -Path "C:\AWSTools\logs\ScriptReboot.log"
} else { # Start logging for this script first-time
if((Test-Path -Path "C:\AWSTools\logs\ScriptOLD.log") -eq $true) {
    Remove-Item -Path "C:\AWSTools\logs\ScriptOLD.log"
} if((Test-Path -Path "C:\AWSTools\logs\script.log") -eq $true) {
    Rename-Item -Path "C:\AWSTools\logs\script.log" -NewName 'ScriptOLD.log'
} Start-Transcript -Path "C:\AWSTools\logs\script.log"
}

# Setting function to test for existance of Registry valves
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

function AdminCheck {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        # Terminating script when it gets executed without administrator privileges 
        throw "The script got executed without Administrator privileges, please execute it as Administrator" 
    }
}

# Creating necessary folders
if((Test-Path -Path 'C:\AWSTools') -eq $true) {} Else {New-Item -Path 'C:\' -Name AWSTools -Force -ItemType Directory| Out-Null} 
if((Test-Path -Path 'C:\AWSTools\Scripts') -eq $true) {} Else {New-Item -Path 'C:\AWSTools\' -Name Script -Force -ItemType Directory | Out-Null} 
if((Test-Path -Path 'C:\AWSTools\logs') -eq $true) {} Else {New-Item -Path 'C:\AWSTools\' -Name logs -Force -ItemType Directory | Out-Null}
if((Test-Path -Path 'C:\AWSTools\drivers') -eq $true) {} Else {New-Item -Path 'C:\AWSTools\' -Name drivers -Force -ItemType Directory | Out-Null}
if((Test-Path -Path 'C:\AWSTools\drivers\NVIDIA') -eq $true) {} Else {New-Item -Path 'C:\AWSTools\drivers' -Name NVIDIA -Force -ItemType Directory | Out-Null}
if((Test-Path -Path 'C:\AWSTools\GameStream') -eq $true) {} Else {New-Item -Path 'C:\AWSTools\' -Name GameStream -Force -ItemType Directory | Out-Null}
if((Test-Path -Path 'C:\AWSTools\DirectX') -eq $true) {} Else {New-Item -Path 'C:\AWSTools\' -Name DirectX -Force -ItemType Directory | Out-Null}
Move-Item -Force "C:\AWSTools\Scripts\Tools\*" -Destination "C:\AWSTools\" | Out-Null

function CheckOSsupport {
    if($osType.Caption -like "*Windows Server 2012 R2*" -or $osType.Caption -like "*Windows Server 2019*" -or $osType.Caption -like "*Windows Server 2016*") {
        # If OS is supported
        Write-Host -Object ('Your OS ({0}) is supported' -f $OSType.Caption) -ForegroundColor Green
    } else {
        # If OS is not supported
        Write-Host -ForegroundColor Red ("
        Sorry, but we dont support your OS ({0}) at the moment.
        We are currently supporting following Windows versions:
        Microsoft Windows Server 2012 R2
        Microsoft Windows Server 2016
        Microsoft Windows Server 2019
        Please use the OS above or suggest your OS in the GitHub Repository, thanks :)
        " -f $osType.Caption)
        throw "Unsupported OS detected"
    }
}

function TestForAWS { 
    # Pinging AWS Instance Metadata Service to check if the system is an AWS VM
    # Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
    $aws = $(
                  Try {(Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/" -Headers @{Metadata="true"} -TimeoutSec 5)}
                  catch {}              
               )

    if ($aws.StatusCode -eq 200) {
        Write-Host -ForegroundColor Green "AWS Instance detected"
        }
    Else {
        throw "No AWS instance detected."
        }
}

function ManageWindowsFeatures {
    # Enable .NET Framework 3.5 for running software based on it
    # Source: https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/enable-net-framework-35-by-using-windows-powershell#steps
    Write-Output -InputObject 'Installing .NET Framework 3.5...'
    Install-WindowsFeature -Name 'Net-Framework-Core' | Out-Null
    # Installing special features for Server 2012 R2
    if($osType.Caption -like "*Windows Server 2012 R2*") {
        # Installing qWave
            Write-Output -InputObject 'Installing qWave...'
            Install-WindowsFeature -Name 'qWave' | Out-Null
        # Installing Desktop Experience for more PC features
            Write-Output -InputObject 'Installling Desktop Experience...'
            Install-WindowsFeature -Name 'Desktop-Experience' | Out-Null
        # Installing Group Policy Management for better administration
            Write-Output -InputObject 'Installling Group Policy Management...'
            Get-WindowsFeature -Name "*GPMC*" | Install-WindowsFeature | Out-Null
        # Installing BITS for some network tasks
            Write-Output -InputObject 'Installling Background Intelligent Transfer Service...'
            Install-WindowsFeature -Name "BITS" | Out-Null
        }
    
    # Uninstalling Windows Defender on Windows Server 2016 and 2019 for saving resources
    if($osType.Caption -like "*Windows Server 2016*" -or $osType.Caption -like "*Windows Server 2019*") {
        Write-Output -InputObject 'Uninstall Windows Defender...'
        Uninstall-WindowsFeature -Name 'Windows-Defender' | Out-Null
    }
    # Enable DirectPlay for older games
        Write-Output -InputObject 'Installing DirectPlay...'
        Get-WindowsFeature -Name "*Direct-Play*" | Install-WindowsFeature | Out-Null
    # Enable Wireless LAN Service because some software need it
        Write-Output -InputObject 'Install Wireless Networking...'
        Install-WindowsFeature -Name 'Wireless-Networking' | Out-Null
    # Installing Windows Update module for PowerShell
    # Source: https://www.powershellgallery.com/packages/PSWindowsUpdate/
        Write-Output -InputObject 'Installing Windows Update module...'
        # Installing NuGet
        Install-PackageProvider -Name NuGet -Scope AllUsers -Force | Out-Null
        # Adding PSGallery to trusted Repositorys
        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted | Out-Null
        # Installing base Windows Update module
        Install-Module -Name PSWindowsUpdate -Scope AllUsers -Force | Out-Null
}
    
function InstallChocolatey {
    # Download and install Chocolatey [Package Manager for Windows]
    Write-Output "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-WebRequest 'https://chocolatey.org/install.ps1' -UseBasicParsing | Invoke-Expression | Out-Null
    # Enable executing PowerShell scripts silently without to confirm
    Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\choco.exe" -ArgumentList "feature enable -n allowGlobalConfirmation" -Wait -NoNewWindow | Out-Null
}

function InstallGameLaunchers {
# Downloading and installing common game launchers 
    # Downloading and installing Steam
        Write-Host -Object 'Downloading and installing Steam'
        Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\choco.exe" -ArgumentList "install steam --limit-output" -Wait -NoNewWindow | Out-Null
        # Disable Steam Autostart
        Set-ItemProperty -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'Steam' -Value ([byte[]](0x33,0x32,0xFF)) | Out-Null
    # Downloading and installing Epic Games Launcher
        Write-Host -Object 'Downloading and installing Epic Games Launcher'
        Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\choco.exe" -ArgumentList "install epicgameslauncher --limit-output" -Wait -NoNewWindow | Out-Null
    <# Adding this launchers as optional function soon 
    # Downloading and installing Origin
    Write-Host -Object 'Downloading and installing Origin'
    Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\choco.exe" -ArgumentList "install origin --limit-output" -Wait -NoNewWindow | Out-Null
    # Downloading and installing Ubisoft Connect [Used to be known as uPlay]
    Write-Host -Object 'Downloading and installing Ubisoft Connect'
    Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\choco.exe" -ArgumentList "install ubisoft-connect --limit-output" -Wait -NoNewWindow | Out-Null
    # Downloading and installing GOG GALAXY
    Write-Host -Object 'Downloading and installing GOG GALAXY'
    Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\choco.exe" -ArgumentList "install goggalaxy--limit-output" -Wait -NoNewWindow | Out-Null
    #>
}

function InstallCommonSoftware {
# Downloading and installing most common software
    # Downloading and installing 7-Zip
        ProgressWriter -Status "Installing 7-Zip" -PercentComplete $PercentComplete
        Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\choco.exe" -ArgumentList "install 7zip --limit-output" -Wait -NoNewWindow | Out-Null
    # Downloading and installing Microsoft Edge
        ProgressWriter -Status "Installing Microsoft Edge" -PercentComplete $PercentComplete
        Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\choco.exe" -ArgumentList "install microsoft-edge --limit-output" -Wait -NoNewWindow | Out-Null
    # Downloading and installing VLC Media Player
        ProgressWriter -Status "Installing VLC Media Player" -PercentComplete $PercentComplete
        Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\choco.exe" -ArgumentList "install vlc --limit-output" -Wait -NoNewWindow | Out-Null
    # Downloading Microsoft Visual C++ Redist
        ProgressWriter -Status "Installing Microsoft Visual C++ Redist" -PercentComplete $PercentComplete
        Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\choco.exe" -ArgumentList "install vcredist140 --limit-output" -Wait -NoNewWindow | Out-Null
    # Downloading and installing required DirectX libraries
        ProgressWriter -Status "Installing DirectX" -PercentComplete $PercentComplete
        Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\choco.exe" -ArgumentList "install directx --limit-output" -Wait -NoNewWindow | Out-Null
    # Downloading and installing ChocolateyGUI
        ProgressWriter -Status "Installing ChocolateyGUI" -PercentComplete $PercentComplete
        Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\choco.exe" -ArgumentList "install ChocolateyGUI --limit-output" -Wait -NoNewWindow | Out-Null
        IF ((Test-Path -Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Chocolatey GUI.lnk') -eq $true) {
            Write-Host 'Copying ChocolateyGUI shortcut to public Desktop'
            Copy-Item 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Chocolatey GUI.lnk' 'C:\Users\Public\Desktop\Chocolatey GUI.lnk'} else {
                Write-Host -Object 'No shortcut in ProgramData found, creating ChocolateyGUI shortcut manually'
                $ChocoShortcut = $WScriptShell.CreateShortcut("$env:USERPROFILE\Desktop\Chocolatey GUI.lnk")
                $ChocoShortcut.TargetPath="C:\Program Files (x86)\Chocolatey GUI\ChocolateyGui.exe"
                $ChocoShortcut.WorkingDirectory = "C:\Program Files (x86)\Chocolatey GUI\";
                $ChocoShortcut.IconLocation = "$env:SystemRoot\Installer\{A910A3D5-1BF4-40FA-9A2C-CD0FF79C9F0A}\icon.ico, 0";
                $ChocoShortcut.WindowStyle = 0;
                $ChocoShortcut.Description = "GUI for Chocolatey";
                $ChocoShortcut.Save()
            }
    # Downloading and installing Moonlight Internet Hosting Tool
        $MIHTHTML = (Invoke-WebRequest -Uri "https://github.com/moonlight-stream/Internet-Hosting-Tool/releases" -UseBasicParsing).Links.Href -like "*InternetHostingToolSetup-*"
        $MIHTDOWNLOAD = $MIHTHTML.split('(')[1].split(')')[0]
        (New-Object System.Net.WebClient).DownloadFile($($MIHTDOWNLOAD), "C:\AWSTools\InternetHostingToolSetup.exe")
        Start-Process -FilePath 'C:\AWSTools\InternetHostingToolSetup.exe' -ArgumentList '/quiet','/install','/norestart' -Wait -NoNewWindow | Out-Null
    
    if($osType.Caption -like "*Windows Server 2012 R2*") {
    # Installing following features if OS is Windows Server 2012 R2
        # Downloading and installing Open Shell
            ProgressWriter -Status "Installing Open Shell" -PercentComplete $PercentComplete
            Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\choco.exe" -ArgumentList "install open-shell --limit-output" -Wait -NoNewWindow | Out-Null
        # Downloading and installing DirectX SDK (specify version as temp WAR for wrong hash)
            ProgressWriter -Status "Installing DirectX SDK" -PercentComplete $PercentComplete
            Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\choco.exe" -ArgumentList "install directx-sdk --version 9.29.1962.01 --limit-output" -Wait -NoNewWindow | Out-Null
    }
}

function CheckForRDP {
    if([bool]((quser) -imatch "rdp")) {
        Write-Warning 'RDP detected, this script will terminate itself'
        PAUSE
        throw "[rdp_session_detected] RDP session detected, please use alternatives like AnyDesk or VNC! `r`nFor more information check out the GitHub Wiki."
    }
}

function EnableAudio {
ProgressWriter -Status "Enabling Audio Services" -PercentComplete $PercentComplete
# Enabling Audio on Windows Server
    Set-Service -Name "Audiosrv" -StartupType Automatic
    Set-Service -Name "AudioEndpointBuilder" -StartupType Automatic 
    Start-Service -Name "Audiosrv" 
    Start-Service -Name "AudioEndpointBuilder"
# Downloading and installing VBCABLE Audio driver
IF ((Test-Path -Path 'C:\Windows\System32\drivers\vbaudio_cable64_win7.sys' -PathType Leaf)) {Write-Warning -Message 'VBAudio drivers found, skipping installation'} else {
    (New-Object System.Net.WebClient).DownloadFile("https://download.vb-audio.com/Download_CABLE/VBCABLE_Driver_Pack43.zip", "C:\AWSTools\drivers\VBCABLE_Driver_Pack43.zip")
    Expand-Archive -Path 'C:\AWSTools\drivers\VBCABLE_Driver_Pack43.zip' -DestinationPath 'C:\AWSTools\drivers\VBCABLE'
    # Adding VBCABLE certificate as trusted publisher to install VBCABLE silently 
    $DriverPath = Get-Item "C:\AWSTools\drivers\VBCABLE\"
    $CertStore = Get-Item "cert:\LocalMachine\TrustedPublisher"
    $CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    Get-ChildItem -Recurse -Path $DriverPath -Filter "*win7.cat" | ForEach-Object {
        $Cert = (Get-AuthenticodeSignature $_.FullName).SignerCertificate
        $CertStore.Add($Cert)
    }
    $CertStore.Close()
    Start-Process -FilePath "C:\AWSTools\drivers\VBCABLE\VBCABLE_Setup_x64.exe" -ArgumentList "-i","-h" -NoNewWindow -Wait
    }
}

function SetWindowsSettings {
ProgressWriter -Status "Changing Windows settings" -PercentComplete $PercentComplete
# Enabling Autologon
Set-SecureAutoLogon `
    -Username $env:USERNAME `
    -Password $autologinpassword
# Disabling Server Manager opening on Startup
    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask
# Enabling Dark Mode [Server 2019 only]
    if ($osType.Caption -like "*Windows Server 2019*") {
        if((Test-Path -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize') -eq $true) {} Else {New-Item -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes' -Name Personalize | Out-Null}
        if((Test-RegistryValue -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Value 'AppsUseLightTheme') -eq $true) {Set-ItemProperty -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name "AppsUseLightTheme" -Value '0' | Out-Null} Else {New-ItemProperty -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name "AppsUseLightTheme" -Value '0' -PropertyType 'DWord' -Force -ea SilentlyContinue | Out-Null}}
# Disabling Charms Bar [Server 2012 R2 only]
    if ($osType.Caption -like "*Windows Server 2012 R2*") {
        if((Test-Path -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi') -eq $true) {} else {New-Item -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\' -Name EdgeUi | Out-Null}
        if((Test-RegistryValue -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Value 'DisableTLCorner') -eq $true) {Set-ItemProperty -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Name "DisableTLCorner" -Value '1'} Else {New-ItemProperty -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Name "DisableTLCorner" -Value '1' -PropertyType 'DWord' -Force -ea SilentlyContinue | Out-Null}
        if((Test-RegistryValue -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Value 'DisableTRCorner') -eq $true) {Set-ItemProperty -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Name "DisableTRCorner" -Value '1'} Else {New-ItemProperty -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Name "DisableTRCorner" -Value '1' -PropertyType 'DWord' -Force -ea SilentlyContinue | Out-Null}
        if((Test-RegistryValue -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Value 'DisableCharmsHint') -eq $true) {Set-ItemProperty -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Name "DisableCharmsHint" -Value '1'} Else {New-ItemProperty -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Name "DisableCharmsHint" -Value '1' -PropertyType 'DWord' -Force -ea SilentlyContinue | Out-Null}
        }
# Disabling "Shutdown Event Tracker"
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability") -ne $true) {New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -force -ea SilentlyContinue | Out-Null}
    if((Test-RegistryValue -Path "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Value 'ShutdownReasonOn') -eq $true) {Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability' -Name "ShutdownReasonOn" -Value '0' | Out-Null} Else {New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability' -Name 'ShutdownReasonOn' -Value '0' -PropertyType 'DWord' -Force -ea SilentlyContinue | Out-Null}
    if((Test-RegistryValue -Path "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Value 'ShutdownReasonUI') -eq $true) {Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability' -Name "ShutdownReasonUI" -Value '0' | Out-Null} Else {New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability' -Name 'ShutdownReasonUI' -Value '0' -PropertyType 'DWord' -Force -ea SilentlyContinue | Out-Null}
# Adjusting Processor Scheduling to "Performance for Applications"
    if((Test-RegistryValue -Path "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" -Value 'Win32PrioritySeparation') -eq $true) {Set-ItemProperty -Path "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value '00000026'} Else {NewItemProperty -Path "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value '00000026' -PropertyType 'DWord' | Out-Null}
# Disabling Aero Shake
    if((Test-Path -path 'registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer') -eq $true) {} else {New-Item -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\' -Name 'Explorer' | Out-Null}
    if((Test-RegistryValue -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Value 'NoWindowMinimizingShortcuts') -eq $true) {Set-ItemProperty -Path "registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoWindowMinimizingShortcuts" -Value '1' | Out-Null} Else {New-ItemProperty -Path "registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoWindowMinimizingShortcuts" -Value '1' -PropertyType 'DWord' | Out-Null}
# Changing DEP to only apply for critical Windows files
    Start-Process -FilePath "C:\Windows\System32\bcdedit.exe" -ArgumentList "/set {current} nx OptIn" -Wait -NoNewWindow | Out-Null
# Disabling SEHOP
    if((Test-Path -path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel') -eq $true) {} else {New-Item -Path "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\" -Name "Kernel" -Force | Out-Null}
    if((Test-RegistryValue -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel' -Value 'DisableExceptionChainValidation') -eq $true) {Set-ItemProperty -Path "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "DisableExceptionChainValidation" -Value '1' | Out-Null} Else {New-ItemProperty -LiteralPath 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel' -Name 'DisableExceptionChainValidation' -Value '1' -PropertyType 'DWord' | Out-Null}
# Enabling Automatic Time and Timezone
    if((Test-RegistryValue -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Value 'Type') -eq $true) {Set-ItemProperty -path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Name 'Type' -Value 'NTP' | Out-Null} Else {New-ItemProperty -LiteralPath 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -Name 'Type' -Value 'NTP' -PropertyType 'String' | Out-Null}
    if((Test-Path -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate') -eq $true) {} Else {New-Item -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\' -Name 'tzautoupdate' | Out-Null}
    if((Test-RegistryValue -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate' -Value Start) -eq $true) {Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate' -Name 'Start' -Value '00000003'} Else {New-ItemProperty -LiteralPath 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate' -Name 'Start' -Value '00000003' -PropertyType 'DWord' | Out-Null}
# Disabling "New network window
    if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff") -ne $true) {New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" -force -ea SilentlyContinue | Out-Null}
# Disabling logout and lock user from the Start Menu
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer") -ne $true) {New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -force -ea SilentlyContinue | Out-Null}
    if((Test-RegistryValue -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Value StartMenuLogOff) -eq $true) {Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'StartMenuLogOff' -Value 1 | Out-Null} Else {New-ItemProperty -LiteralPath 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'StartMenuLogOff' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null}
    if((Test-Path -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') -eq $true) {} Else {New-Item -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies' -Name 'System' | Out-Null}
    if((Test-RegistryValue -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Value DisableLockWorkstation) -eq $true) {Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableLockWorkstation' -Value 1 | Out-Null} Else {New-ItemProperty -LiteralPath 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableLockWorkstation' -Value 1 -PropertyType DWord | Out-Null}
# Disabling "Recent Start Menu" items
    if((Test-Path -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') -eq $true) {} Else {New-Item -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\' -Name Explorer | Out-Null}
    if((Test-RegistryValue -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Value HideRecentlyAddedApps) -eq $true) {Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'HideRecentlyAddedApps' -Value 1} Else {new-itemproperty -LiteralPath 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer' -name "HideRecentlyAddedApps" -Value 1 -PropertyType DWord | Out-Null}
# Enabling "Show hidden files"
    if((Test-Path -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer') -eq $true) {} else {New-Item -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion' -Name Explorer | Out-Null}
    if((Test-Path -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced') -eq $true) {} else {New-Item -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name Advanced | Out-Null}
    if((Test-RegistryValue -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Value Hidden) -eq $true) {Set-ItemProperty -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -Value 1 | Out-Null} Else {new-itemproperty -path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -name "Hidden" -Value 1 -PropertyType DWord | Out-Null}
# Call "RestorePhotoViewer" function when OS is not Windows Server 2012 R2
if(!($osType.Caption -like "*Windows Server 2012 R2*")) {RestorePhotoViewer | Out-Null}
# Disabling "Hide file extention"
    if((Test-RegistryValue -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Value Hidden) -eq $true) {Set-ItemProperty -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Value 1 | Out-Null} Else {New-ItemProperty -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Value 1 -PropertyType DWord | Out-Null}
# Adding "Control Panal" Icon on the Desktop
    if((Test-Path -LiteralPath "registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel") -ne $true) {New-Item "registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -force -ea SilentlyContinue | Out-Null}
    if((Test-Path -LiteralPath "registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu") -ne $true) {New-Item "registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -force -ea SilentlyContinue | Out-Null}
    if((Test-RegistryValue -Path 'registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Value '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}') -eq $true) {Set-ItemProperty -LiteralPath 'registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value 0 | Out-Null} Else {New-ItemProperty -LiteralPath 'registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null}
    if((Test-RegistryValue -Path 'registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Value '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}') -eq $true) {Set-ItemProperty -LiteralPath 'registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value 0 | Out-Null} Else {New-ItemProperty -LiteralPath 'registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null}
    # Adding "This PC" Icon on the Desktop
    if((Test-Path -LiteralPath "registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel") -ne $true) {New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -force -ea SilentlyContinue | Out-Null}
    if((Test-Path -LiteralPath "registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu") -ne $true) {New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -force -ea SilentlyContinue | Out-Null}
    if((Test-RegistryValue -Path 'registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Value '{20D04FE0-3AEA-1069-A2D8-08002B30309D}') -eq $true) {Set-ItemProperty -LiteralPath 'registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value 0 | Out-Null} Else {New-ItemProperty -LiteralPath 'registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null}
    if((Test-RegistryValue -Path 'registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Value '{20D04FE0-3AEA-1069-A2D8-08002B30309D}') -eq $true) {Set-ItemProperty -LiteralPath 'registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value 0 | Out-Null} Else {New-ItemProperty -LiteralPath 'registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null}
# Change Wallpaper  
    (New-Object System.Net.WebClient).DownloadFile("https://imgur.com/download/GtQtKhz/AWSWallpaper", "$env:SystemRoot\Web\Wallpaper\AWSWallpaper.png")
    Set-Wallpaper "$env:SystemRoot\Web\Wallpaper\AWSWallpaper.png"
# Extract DirectX Archive to C:\Windows when OS is Server 2012 R2
    if ($osType.Caption -like "*Windows Server 2012 R2*") {Expand-Archive -Path 'C:\AWSTools\DirectXWK12.zip' -DestinationPath 'C:\Windows' -Force}
}

function Set-SecureAutoLogon {
    [cmdletbinding()]
param (
	[Parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [string]
	$Username,

	[Parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()] [System.Security.SecureString]
	$Password,
	
	[string]
	$Domain,
	
	[Int]
	$AutoLogonCount,
	
	[switch]
	$RemoveLegalPrompt,
	
	[System.IO.FileInfo]
	$BackupFile
)

begin {
	
	[string] $WinlogonPath = "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
	[string] $WinlogonBannerPolicyPath = "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

	[string] $Enable = 1
	
	#region C# Code to P-invoke LSA LsaStorePrivateData function.
	Add-Type @"
		using System;
		using System.Collections.Generic;
		using System.Text;
		using System.Runtime.InteropServices;

		namespace ComputerSystem
		{
		    public class LSAutil
		    {
		        [StructLayout(LayoutKind.Sequential)]
		        private struct LSA_UNICODE_STRING
		        {
		            public UInt16 Length;
		            public UInt16 MaximumLength;
		            public IntPtr Buffer;
		        }

		        [StructLayout(LayoutKind.Sequential)]
		        private struct LSA_OBJECT_ATTRIBUTES
		        {
		            public int Length;
		            public IntPtr RootDirectory;
		            public LSA_UNICODE_STRING ObjectName;
		            public uint Attributes;
		            public IntPtr SecurityDescriptor;
		            public IntPtr SecurityQualityOfService;
		        }

		        private enum LSA_AccessPolicy : long
		        {
		            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
		            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
		            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
		            POLICY_TRUST_ADMIN = 0x00000008L,
		            POLICY_CREATE_ACCOUNT = 0x00000010L,
		            POLICY_CREATE_SECRET = 0x00000020L,
		            POLICY_CREATE_PRIVILEGE = 0x00000040L,
		            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
		            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
		            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
		            POLICY_SERVER_ADMIN = 0x00000400L,
		            POLICY_LOOKUP_NAMES = 0x00000800L,
		            POLICY_NOTIFICATION = 0x00001000L
		        }

		        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
		        private static extern uint LsaRetrievePrivateData(
		                    IntPtr PolicyHandle,
		                    ref LSA_UNICODE_STRING KeyName,
		                    out IntPtr PrivateData
		        );

		        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
		        private static extern uint LsaStorePrivateData(
		                IntPtr policyHandle,
		                ref LSA_UNICODE_STRING KeyName,
		                ref LSA_UNICODE_STRING PrivateData
		        );

		        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
		        private static extern uint LsaOpenPolicy(
		            ref LSA_UNICODE_STRING SystemName,
		            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
		            uint DesiredAccess,
		            out IntPtr PolicyHandle
		        );

		        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
		        private static extern uint LsaNtStatusToWinError(
		            uint status
		        );

		        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
		        private static extern uint LsaClose(
		            IntPtr policyHandle
		        );

		        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
		        private static extern uint LsaFreeMemory(
		            IntPtr buffer
		        );

		        private LSA_OBJECT_ATTRIBUTES objectAttributes;
		        private LSA_UNICODE_STRING localsystem;
		        private LSA_UNICODE_STRING secretName;

		        public LSAutil(string key)
		        {
		            if (key.Length == 0)
		            {
		                throw new Exception("Key lenght zero");
		            }

		            objectAttributes = new LSA_OBJECT_ATTRIBUTES();
		            objectAttributes.Length = 0;
		            objectAttributes.RootDirectory = IntPtr.Zero;
		            objectAttributes.Attributes = 0;
		            objectAttributes.SecurityDescriptor = IntPtr.Zero;
		            objectAttributes.SecurityQualityOfService = IntPtr.Zero;

		            localsystem = new LSA_UNICODE_STRING();
		            localsystem.Buffer = IntPtr.Zero;
		            localsystem.Length = 0;
		            localsystem.MaximumLength = 0;

		            secretName = new LSA_UNICODE_STRING();
		            secretName.Buffer = Marshal.StringToHGlobalUni(key);
		            secretName.Length = (UInt16)(key.Length * UnicodeEncoding.CharSize);
		            secretName.MaximumLength = (UInt16)((key.Length + 1) * UnicodeEncoding.CharSize);
		        }

		        private IntPtr GetLsaPolicy(LSA_AccessPolicy access)
		        {
		            IntPtr LsaPolicyHandle;

		            uint ntsResult = LsaOpenPolicy(ref this.localsystem, ref this.objectAttributes, (uint)access, out LsaPolicyHandle);

		            uint winErrorCode = LsaNtStatusToWinError(ntsResult);
		            if (winErrorCode != 0)
		            {
		                throw new Exception("LsaOpenPolicy failed: " + winErrorCode);
		            }

		            return LsaPolicyHandle;
		        }

		        private static void ReleaseLsaPolicy(IntPtr LsaPolicyHandle)
		        {
		            uint ntsResult = LsaClose(LsaPolicyHandle);
		            uint winErrorCode = LsaNtStatusToWinError(ntsResult);
		            if (winErrorCode != 0)
		            {
		                throw new Exception("LsaClose failed: " + winErrorCode);
		            }
		        }

		        public void SetSecret(string value)
		        {
		            LSA_UNICODE_STRING lusSecretData = new LSA_UNICODE_STRING();

		            if (value.Length > 0)
		            {
		                //Create data and key
		                lusSecretData.Buffer = Marshal.StringToHGlobalUni(value);
		                lusSecretData.Length = (UInt16)(value.Length * UnicodeEncoding.CharSize);
		                lusSecretData.MaximumLength = (UInt16)((value.Length + 1) * UnicodeEncoding.CharSize);
		            }
		            else
		            {
		                //Delete data and key
		                lusSecretData.Buffer = IntPtr.Zero;
		                lusSecretData.Length = 0;
		                lusSecretData.MaximumLength = 0;
		            }

		            IntPtr LsaPolicyHandle = GetLsaPolicy(LSA_AccessPolicy.POLICY_CREATE_SECRET);
		            uint result = LsaStorePrivateData(LsaPolicyHandle, ref secretName, ref lusSecretData);
		            ReleaseLsaPolicy(LsaPolicyHandle);

		            uint winErrorCode = LsaNtStatusToWinError(result);
		            if (winErrorCode != 0)
		            {
		                throw new Exception("StorePrivateData failed: " + winErrorCode);
		            }
		        }
		    }
		}
"@
	#endregion
}

process {

	try {
		$ErrorActionPreference = "Stop"
		
		$decryptedPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
			[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
		)

		if ($BackupFile) {
				# Initialize the hash table with a string comparer to allow case sensitive keys.
				# This allows differentiation between the winlogon and system policy logon banner strings.
			$OrigionalSettings = New-Object System.Collections.Hashtable ([system.stringcomparer]::CurrentCulture)
			
			$OrigionalSettings.AutoAdminLogon = (Get-ItemProperty $WinlogonPath ).AutoAdminLogon
			$OrigionalSettings.ForceAutoLogon = (Get-ItemProperty $WinlogonPath).ForceAutoLogon
			$OrigionalSettings.DefaultUserName = (Get-ItemProperty $WinlogonPath).DefaultUserName
			$OrigionalSettings.DefaultDomainName = (Get-ItemProperty $WinlogonPath).DefaultDomainName
			$OrigionalSettings.DefaultPassword = (Get-ItemProperty $WinlogonPath).DefaultPassword
			$OrigionalSettings.AutoLogonCount = (Get-ItemProperty $WinlogonPath).AutoLogonCount
			
				# The winlogon logon banner settings.
			$OrigionalSettings.LegalNoticeCaption = (Get-ItemProperty $WinlogonPath).LegalNoticeCaption
			$OrigionalSettings.LegalNoticeText = (Get-ItemProperty $WinlogonPath).LegalNoticeText
			
				# The system policy logon banner settings.
			$OrigionalSettings.legalnoticecaption = (Get-ItemProperty $WinlogonBannerPolicyPath).legalnoticecaption
			$OrigionalSettings.legalnoticetext = (Get-ItemProperty $WinlogonBannerPolicyPath).legalnoticetext
			
			$OrigionalSettings | Export-Clixml -Depth 10 -Path $BackupFile
		}
		
			# Store the password securely.
		$lsaUtil = New-Object ComputerSystem.LSAutil -ArgumentList "DefaultPassword"
		$lsaUtil.SetSecret($decryptedPass)

			# Store the autologon registry settings.
		Set-ItemProperty -Path $WinlogonPath -Name AutoAdminLogon -Value $Enable -Force
        Set-ItemProperty -Path $WinlogonPath -Name DefaultUserName -Value $Username -Force
		Set-ItemProperty -Path $WinlogonPath -Name DefaultDomainName -Value $Domain -Force

		if ($AutoLogonCount) {
			Set-ItemProperty -Path $WinlogonPath -Name AutoLogonCount -Value $AutoLogonCount -Force
		} else {
			Remove-ItemProperty -Path $WinlogonPath -Name AutoLogonCount -ErrorAction SilentlyContinue
		}

		if ($RemoveLegalPrompt) {
			Set-ItemProperty -Path $WinlogonPath -Name LegalNoticeCaption -Value $null -Force
			Set-ItemProperty -Path $WinlogonPath -Name LegalNoticeText -Value $null -Force
			
			Set-ItemProperty -Path $WinlogonBannerPolicyPath -Name legalnoticecaption -Value $null -Force
			Set-ItemProperty -Path $WinlogonBannerPolicyPath -Name legalnoticetext -Value $null -Force
		}
	} catch {
		throw 'Failed to set auto logon. The error was: "{0}".' -f $_
	}

}

<#
	.SYNOPSIS
		Enables auto logon using the specified username and password.

	.PARAMETER  Username
		The username of the user to automatically logon as.

	.PARAMETER  Password
		The password for the user to automatically logon as.
		
	.PARAMETER  Domain
		The domain of the user to automatically logon as.
		
	.PARAMETER  AutoLogonCount
		The number of logons that auto logon will be enabled.
		
	.PARAMETER  RemoveLegalPrompt
		Removes the system banner to ensure interventionless logon.
		
	.PARAMETER  BackupFile
		If specified the existing settings such as the system banner text will be backed up to the specified file.

	.EXAMPLE
		PS C:\> Set-SecureAutoLogon `
				-Username $env:USERNAME `
				-Password (Read-Host -AsSecureString) `
				-AutoLogonCount 2 `
				-RemoveLegalPrompt `
				-BackupFile "C:\WinlogonBackup.xml"

	.INPUTS
		None.

	.OUTPUTS
		None.

	.NOTES
		Revision History:
			2011-04-19 : Andy Arismendi - Created.
			2011-09-29 : Andy Arismendi - Changed to use LSA secrets to store password securely.

	.LINK
		http://support.microsoft.com/kb/324737
		
	.LINK
		http://msdn.microsoft.com/en-us/library/aa378750

#>
}

function AddNewDisk {
    ProgressWriter -Status "Scanning for new disks" -PercentComplete $PercentComplete
    # Scanning for not initialized disks
    $DISK = Get-Disk | Where-Object PartitionStyle -Eq "RAW"
    IF (!$DISK) {
    # Warning when no disk is found
    Write-Warning 'No disk found, skipping configuration of disk for saving games and software'} else {
    ProgressWriter -Status "Adding new disk and formatting it" -PercentComplete $PercentComplete
    # If any non initialized disk was found
    # Changing registry key to prevent autostart of Windows Shell
    Set-ItemProperty 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoRestartShell -Value 0
    # Killing Shell as a WAR for not outputting Windows "format wizard"
    Stop-Process -Name explorer* -Force
    # Creating Disk with "SoftwareDisk" as name" 
    Get-Disk | Where-Object PartitionStyle -Eq "RAW" | Initialize-Disk -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "SoftwareDisk" -Confirm:$false
    # Rolling back registry key
    Set-ItemProperty 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoRestartShell -Value 1
    # Restarting Shell
    Start-Process "C:\Windows\System32\userinit.exe"
    }
}

function DisableVGA {
ProgressWriter -Status "Disabling non-NVIDIA GPUs" -PercentComplete $PercentComplete
# Disabling non-NVIDIA GPUs
    if($osType.Caption -like "*Windows Server 2012 R2*") {
        # This command gets executed when OS is Windows Server 2012 R2
        Start-Process -FilePath 'C:\AWSTools\devcon.exe' -ArgumentList 'disable "VMBUS\{DA0A7802-E377-4AAC-8E77-0558EB1073F8}"' -Wait -NoNewWindow
    } else {
        # This command gets executed when OS is Windows Server 2016 or 2019
        Get-PnpDevice -Class "Display" -Status OK | Where-Object { $_.Name -notmatch "nvidia" } | Disable-PnpDevice -confirm:$false
    }
}

function DisableFloppyAndCDROM {
    ProgressWriter -Status "Disabling useless hardware" -PercentComplete $PercentComplete
    # Disabling Floppy Disk drive
        Start-Process -FilePath 'C:\AWSTools\devcon.exe' -ArgumentList 'disable "FDC\GENERIC_FLOPPY_DRIVE"' -Wait -NoNewWindow
    # Disabling CDROM drive
        Start-Process -FilePath 'C:\AWSTools\devcon.exe' -ArgumentList 'disable "GenCdRom"' -Wait -NoNewWindow
}

Function ProgressWriter {
    param (
    [int]$percentcomplete,
    [string]$status
    )Write-Progress -Activity "AWS VM will be prepared for Cloud Gaming" -Status $status -PercentComplete $PercentComplete}

function BlockHost {
    $BlockedHosts = @("telemetry.gfe.nvidia.com", "ls.dtrace.nvidia.com", "ota.nvidia.com", "ota-downloads.nvidia.com", "rds-assets.nvidia.com", "nvidia.tt.omtrdc.net", "api.commune.ly", "namso-gen.com", "nulled.to")
    $HostsFile = "$env:SystemRoot\System32\Drivers\etc\hosts"
    $HostsContent = [String](Get-Content -Path $HostsFile)
    $Appended = ""

    foreach($Entry in $BlockedHosts) {
        if($HostsContent -notmatch $Entry) {
            $Appended += "0.0.0.0 $Entry`r`n"
        }
    }

    if($Appended.Length -gt 0) {
        $Appended = $Appended.Substring(0,$Appended.length-2)
        Add-Content -Path $HostsFile -Value $Appended
    }
}

function CheckForDrivers {
    if (!($nvdrivers)) {
    if (!(Get-WmiObject Win32_PnPSignedDriver| select DeviceName, DriverVersion, Manufacturer | where {$_.DeviceName -like "*NVIDIA*"})) {
        $UseExternalScript = (Read-Host "No GPU driver detected.`nWould you like to use the Cloud GPU Updater script by jamesstringerparsec?`nThe driver the script will install may or may not be compatible with this patch.`nA shortcut will be created in the Desktop to continue this installation after finishing the script. (y/n)").ToLower() -eq "y"
        InstallDrivers
    }}
}

function InstallDrivers {
$Shell = New-Object -comObject WScript.Shell
$Shortcut = $Shell.CreateShortcut("$userpath\Desktop\AutomateCloudGaming_Continue.lnk")
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-Command `"Set-ExecutionPolicy Unrestricted; & '$PSScriptRoot\PostNV6.ps1'`" -drivers"
$Shortcut.Save()
Download-File "https://github.com/jamesstringerparsec/Cloud-GPU-Updater/archive/master.zip" "$WorkDir\updater.zip" "Cloud GPU Updater"          
if(![System.IO.File]::Exists("$WorkDir\Updater")) {
Expand-Archive -Path "$WorkDir\updater.zip" -DestinationPath "$WorkDir\Updater"
Start-Process -FilePath "powershell.exe" -ArgumentList "-Command `"$WorkDir\Updater\Cloud-GPU-Updater-master\GPUUpdaterTool.ps1`""
Environment]::Exit(0)
}}

function GameStreamAfterReboot {
    if(Get-ScheduledTask | Where-Object {$_.TaskName -like "ContinueAWSGamingScript" }) {Unregister-ScheduledTask -TaskName "ContinueAWSGamingScript" -Confirm:$false}
    ProgressWriter -Status "Patching GameStream to work with unsupported NVIDIA GPU" -PercentComplete $PercentComplete
    Write-Output -InputObject 'Downloading GameStream Patcher [CREDIT: acceleration3]'
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/acceleration3/cloudgamestream/master/Steps/Patcher.ps1", "C:\AWSTools\GameStream\Patcher.ps1")
    # Allowing GameStream Rules via Windows Firewall [for Moonlight]
    New-NetFirewallRule -DisplayName "NVIDIA GameStream TCP" -Direction Inbound -LocalPort 47984,47989,48010 -Program 'C:\Program Files\NVIDIA Corporation\NvStreamSrv\nvstreamer.exe' -Protocol TCP -Action Allow | Out-Null
    New-NetFirewallRule -DisplayName "NVIDIA GameStream UDP" -Direction Inbound -LocalPort 47998,47999,48000,48010 -Program 'C:\Program Files\NVIDIA Corporation\NvStreamSrv\nvstreamer.exe' -Protocol UDP -Action Allow | Out-Null
    Write-Host "Enabling NVIDIA FrameBufferCopy..."
    Start-Process -FilePath "C:\AWSTools\NvFBCEnable.exe" -ArgumentList "-enable" -NoNewWindow -Wait | Out-Null
    Write-Host "Patching GFE to allow the GPU's Device ID..."
    Stop-Service -Name NvContainerLocalSystem | Out-Null
    $TargetDevice = (Get-WmiObject Win32_VideoController | Select-Object PNPDeviceID,Name | Where-Object Name -match "nvidia" | Select-Object -First 1) 
    if(!$TargetDevice) {
    throw "Failed to find an NVIDIA GPU."
    }
    if(!($TargetDevice.PNPDeviceID -match "DEV_(\w*)")) {
    throw "Regex failed to extract device ID."
    }
    & 'C:\AWSTools\GameStream\Patcher.ps1' -DeviceID $matches[1] -TargetFile "C:\Program Files\NVIDIA Corporation\NvContainer\plugins\LocalSystem\GameStream\Main\_NvStreamControl.dll" | Out-Null;
}

function StartupScript {
    # Adding Task to start PowerShell script everytime at logon
    $script = "-Command `"Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force; & 'C:\AWSTools\startup.ps1'`"";
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $script
    $trigger = New-ScheduledTaskTrigger -AtLogon
    $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
    Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "ScriptAfterReboot" -Description "This script getting automaticly executed after reboot"
}

function RestorePhotoViewer {
    # Restore Windows Photo Viewer
    ProgressWriter -Status "Restoring Windows Photo viewer..." -PercentComplete $PercentComplete
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\DefaultIcon") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\DefaultIcon" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell\open\command" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell\open\DropTarget") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell\open\DropTarget" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\DefaultIcon") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\DefaultIcon" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open\command" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open\DropTarget") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open\DropTarget" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\DefaultIcon") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\DefaultIcon" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open\command" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open\DropTarget") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open\DropTarget" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\DefaultIcon") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\DefaultIcon" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell\open\command" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell\open\DropTarget") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell\open\DropTarget" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\DefaultIcon") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\DefaultIcon" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\command" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\DropTarget") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\DropTarget" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\DefaultIcon") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\DefaultIcon" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open\command" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open\DropTarget") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open\DropTarget" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities" -force -ea SilentlyContinue }
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" -force -ea SilentlyContinue }
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open' -Name 'MuiVerb' -Value '@photoviewer.dll,-3043' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command' -Name '(default)' -Value '%SystemRoot%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget' -Name 'Clsid' -Value '{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap' -Name 'ImageOptionFlags' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap' -Name 'FriendlyTypeName' -Value '@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3056' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\DefaultIcon' -Name '(default)' -Value '%SystemRoot%\System32\imageres.dll,-70' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell\open\command' -Name '(default)' -Value '%SystemRoot%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell\open\DropTarget' -Name 'Clsid' -Value '{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF' -Name 'EditFlags' -Value 65536 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF' -Name 'ImageOptionFlags' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF' -Name 'FriendlyTypeName' -Value '@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3055' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\DefaultIcon' -Name '(default)' -Value '%SystemRoot%\System32\imageres.dll,-72' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open' -Name 'MuiVerb' -Value '@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open\command' -Name '(default)' -Value '%SystemRoot%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open\DropTarget' -Name 'Clsid' -Value '{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg' -Name 'EditFlags' -Value 65536 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg' -Name 'ImageOptionFlags' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg' -Name 'FriendlyTypeName' -Value '@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3055' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\DefaultIcon' -Name '(default)' -Value '%SystemRoot%\System32\imageres.dll,-72' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open' -Name 'MuiVerb' -Value '@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open\command' -Name '(default)' -Value '%SystemRoot%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open\DropTarget' -Name 'Clsid' -Value '{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif' -Name 'ImageOptionFlags' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif' -Name 'FriendlyTypeName' -Value '@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3057' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\DefaultIcon' -Name '(default)' -Value '%SystemRoot%\System32\imageres.dll,-83' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell\open\command' -Name '(default)' -Value '%SystemRoot%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell\open\DropTarget' -Name 'Clsid' -Value '{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png' -Name 'ImageOptionFlags' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png' -Name 'FriendlyTypeName' -Value '@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3057' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\DefaultIcon' -Name '(default)' -Value '%SystemRoot%\System32\imageres.dll,-71' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\command' -Name '(default)' -Value '%SystemRoot%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\DropTarget' -Name 'Clsid' -Value '{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp' -Name 'EditFlags' -Value 65536 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp' -Name 'ImageOptionFlags' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\DefaultIcon' -Name '(default)' -Value '%SystemRoot%\System32\wmphoto.dll,-400' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open' -Name 'MuiVerb' -Value '@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open\command' -Name '(default)' -Value '%SystemRoot%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1' -PropertyType ExpandString -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open\DropTarget' -Name 'Clsid' -Value '{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities' -Name 'ApplicationDescription' -Value '@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3069' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities' -Name 'ApplicationName' -Value '@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3009' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' -Name '.jpg' -Value 'PhotoViewer.FileAssoc.Jpeg' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' -Name '.wdp' -Value 'PhotoViewer.FileAssoc.Wdp' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' -Name '.jfif' -Value 'PhotoViewer.FileAssoc.JFIF' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' -Name '.dib' -Value 'PhotoViewer.FileAssoc.Bitmap' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' -Name '.png' -Value 'PhotoViewer.FileAssoc.Png' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' -Name '.jxr' -Value 'PhotoViewer.FileAssoc.Wdp' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' -Name '.bmp' -Value 'PhotoViewer.FileAssoc.Bitmap' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' -Name '.jpe' -Value 'PhotoViewer.FileAssoc.Jpeg' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' -Name '.jpeg' -Value 'PhotoViewer.FileAssoc.Jpeg' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' -Name '.gif' -Value 'PhotoViewer.FileAssoc.Gif' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' -Name '.tif' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations' -Name '.tiff' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue
}

function InstallGFE {
    $IP = (Invoke-RestMethod -Method Get -Uri "http://ip-api.com/json/$IPAddress")
    IF ($IP.countryCode -eq "US" -or $IP.countryCode -eq "SG") {
        Set-Variable -Name 'CountryCode' -Value 'US'
    } elseif ($IP.countryCode -eq "NL" -or $IP.countryCode -eq "GB" -or $IP.countryCode -eq "IE") {
        Set-Variable -Name 'CountryCode' -Value 'UK'
    } elseif ($IP.countryCode -eq "JP") {
        Set-Variable -Name 'CountryCode' -Value 'JP'
    } elseif ($IP.countryCode -eq "IN") {
        Set-Variable -Name 'CountryCode' -Value 'IN'
    } else {Set-Variable -Name 'CountryCode' -Value 'US'}
    Write-Host -Object ('Downloading GFE with {0} Mirror' -f $CountryCode)
    (New-Object System.Net.WebClient).DownloadFile("https://$($CountryCode).download.nvidia.com/GFE/GFEClient/3.13.0.85/GeForce_Experience_Beta_v3.13.0.85.exe", "C:\AWSTools\GeForceExperienceSetup.exe")
    Write-Host -Object 'Installing GeForce Experience...' -NoNewline
    $GFEExitCode = (Start-Process -FilePath "C:\AWSTools\GeForceExperienceSetup.exe" -ArgumentList "-s" -NoNewWindow -Wait -Passthru -WorkingDirectory 'C:\AWSTools').ExitCode
    if($GFEExitCode -eq 0) {Write-Host "INSTALLED" -ForegroundColor Green}
    else { 
        Write-Host "FAILED" -ForegroundColor Red
        throw "GeForce Experience installation failed (Error: $GFEExitCode)."
    }
}

function Set-Wallpaper {
        param (
        $WallpaperPath
        )

    $setwallpapersrc = @"
    using System.Runtime.InteropServices;
    public class wallpaper
    {
    public const int SetDesktopWallpaper = 20;
    public const int UpdateIniFile = 0x01;
    public const int SendWinIniChange = 0x02;
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern int SystemParametersInfo (int uAction, int uParam, string lpvParam, int fuWinIni);
    public static void SetWallpaper ( string path )
    {
    SystemParametersInfo( SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange );
    }
    }
"@
Add-Type -TypeDefinition $setwallpapersrc
[wallpaper]::SetWallpaper($WallpaperPath) 
}

Function XboxController {
    ProgressWriter -Status "Downloading Xbox 360 controller drivers" -PercentComplete $PercentComplete
    # Downloading basic Xbox 360 controller driver
    (New-Object System.Net.WebClient).DownloadFile("http://www.download.windowsupdate.com/msdownload/update/v3-19990518/cabpool/2060_8edb3031ef495d4e4247e51dcb11bef24d2c4da7.cab", "C:\AWSTools\drivers\Xbox360_64Eng.cab")
    if((Test-Path -Path C:\AWSTools\drivers\Xbox360_64Eng) -eq $true) {} Else {New-Item -Path C:\AWSTools\drivers\Xbox360_64Eng -ItemType directory}
    cmd.exe /c "C:\Windows\System32\expand.exe C:\AWSTools\drivers\Xbox360_64Eng.cab -F:* C:\AWSTools\drivers\Xbox360_64Eng" | Out-Null
    cmd.exe /c '"C:\AWSTools\devcon.exe" dp_add "C:\AWSTools\drivers\Xbox360_64Eng\xusb21.inf"' | Out-Null
    # Downloading ViGEmBus Controller Driver
    if($osType.Caption -like "*Windows Server 2012*") {
        # This command gets executed if OS is Windows Server 2012
        (New-Object System.Net.WebClient).DownloadFile("https://github.com/ViGEm/ViGEmBus/releases/download/setup-v1.16.116/ViGEmBus_Setup_1.16.116.exe", "C:\AWSTools\ViGEmBus_Setup_win2012.exe")
        Start-Process "C:\AWSTools\ViGEmBus_Setup_win2012.exe" -ArgumentList '/qn' -Wait -NoNewWindow | Out-Null
    } else {
        # This command gets executed if OS is Windows Server 2016 or 2019
        $vigembus = (Invoke-WebRequest -Uri https://github.com/ViGEm/ViGEmBus/releases -UseBasicParsing).links.outerhtml -like "*ViGEmBusSetup_x64.msi*"
        (New-Object System.Net.WebClient).DownloadFile('https://github.com/' + $($vigembus[0].split('"')[1]), 'C:\AWSTools\ViGEmBusSetup_x64.msi')
        Start-Process 'C:\Windows\System32\msiexec.exe' -ArgumentList '/i "C:\AWSTools\ViGEmBusSetup_x64.msi" /qn /norestart' -Wait -NoNewWindow | Out-Null
    }
}

# Set $osType for checking for OS
$osType = Get-CimInstance -ClassName Win32_OperatingSystem
# Changing Title to "First-time setup for Gaming on AWS"
$host.ui.RawUI.WindowTitle = "Automate AWS CloudGaming Tasks [Version 1.0.0]"
# Changing SecurityProtocol for prevent SSL issues with websites
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 
# Set WScriptShell to create Desktop shortcuts
$WScriptShell = New-Object -ComObject WScript.Shell
# Asking for username password for configure autologin
Write-Host -Object ('Enter your password for {0} to enable Autologon:' -f $env:USERNAME)
$autologinpassword = (Read-Host -AsSecureString)
Clear-Host
Write-Host -ForegroundColor DarkRed -BackgroundColor Black '
AWS Automation Gaming Script [Version 1.0.0]
(c) 2021 SoftwareRat. All rights reserved.'

if($MoonlightAfterReboot) {Write-Host -Object 'Continue script after reboot' -ForegroundColor Yellow}

if(!$MoonlightAfterReboot) {
    $ScripttaskList = (
    "CheckForRDP",
    "TestForAWS",
    "CheckOSsupport",
    "SetWindowsSettings",
    "EnableAudio",
    "ManageWindowsFeatures",
    "XboxController",
    "AddNewDisk",
    "InstallChocolatey",
    "InstallGameLaunchers",
    "InstallCommonSoftware",
    "DisableFloppyAndCDROM",
    "DownloadNVIDIAdrivers",
    "InstallDrivers"
)
} else {
    $ScripttaskListAfterReboot = (
    "CheckForRDP",
    "TestForAWS",
    "CheckOSsupport",
    "InstallGFE",
    "BlockHost",
    "GameStreamAfterReboot",
    "DisableVGA",
    "StartupScript"
)}

foreach ($func in $ScripttaskList) {
    $PercentComplete =$($ScriptTaskList.IndexOf($func) / $ScripttaskList.Count * 100)
    & $func $PercentComplete
    }

foreach ($func in $ScripttaskListAfterReboot) {
    $PercentComplete =$($ScripttaskListAfterReboot.IndexOf($func) / $ScripttaskListAfterReboot.Count * 100)
    & $func $PercentComplete
    }

Clear-Host
Stop-Transcript
Write-Host -Object 'Script finished!'
Write-Host -Object 'If you have bugs or feedback suggestions,'
Write-Host -Object 'go to the GitHub repository of this project.'
Write-Host -Object 'Restarting in 5 seconds...'
Start-Sleep -Seconds 5
Restart-Computer -Force
Start-Sleep -Seconds 3
Write-Warning 'Auto-Restart failed, please restart Windows manually'
PAUSE
[Environment]::Exit(0)