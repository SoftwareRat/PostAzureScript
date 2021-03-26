# Argument for using Script after Reboot [Moonlight only]
param (
    [switch]$MoonlightAfterReboot = $false
)

if(!$MoonlightAfterReboot) {
    # Start logging for this script 
    Start-Transcript -Path "C:\AzureTools\logs\script.log"} else
    # Start logging for this script after reboot
    {Start-Transcript -Path "C:\AzureTools\logs\ScriptReboot.log"}

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

function AdminCheck {
    If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        # When this script get executed without administrator privileges
        throw "This script got executed without Administrator privileges, please execute it with Administrator" 
    }
}

# Creating folder everything related to this script 
if((Test-Path -Path 'C:\AzureTools') -eq $true) {} Else {New-Item -Path 'C:\' -Name AzureTools -Force -ItemType Directory | Out-Null}
if((Test-Path -Path 'C:\AzureTools\Scripts') -eq $true) {} Else {New-Item -Path 'C:\AzureTools\' -Name Script -Force -ItemType Directory | Out-Null}
if((Test-Path -Path 'C:\AzureTools\logs') -eq $true) {} Else {New-Item -Path 'C:\AzureTools\' -Name logs -Force -ItemType Directory | Out-Null}
if((Test-Path -Path 'C:\AzureTools\drivers') -eq $true) {} Else {New-Item -Path 'C:\AzureTools\' -Name drivers -Force -ItemType Directory | Out-Null}
if((Test-Path -Path 'C:\AzureTools\drivers\UpdateTool') -eq $true) {} Else {New-Item -Path 'C:\AzureTools\drivers' -Name UpdateTool -Force -ItemType Directory | Out-Null}
if((Test-Path -Path 'C:\AzureTools\GameStream') -eq $true) {} Else {New-Item -Path 'C:\AzureTools\' -Name GameStream -Force -ItemType Directory | Out-Null}
if((Test-Path -Path 'C:\AzureTools\DirectX') -eq $true) {} Else {New-Item -Path 'C:\AzureTools\' -Name DirectX -Force -ItemType Directory | Out-Null}
Move-Item -Force "C:\AzureTools\Scripts\Tools\*" -Destination "C:\AzureTools\" | Out-Null

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
    # Pinging Azure Instance Metadata Service
    # Source: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service?tabs=windows
    $azure = $(
                  Try {(Invoke-WebRequest -Uri "http://169.254.169.254/metadata/instance?api-version=2020-09-01" -Headers @{Metadata="true"} -TimeoutSec 5)}
                  catch {}              
               )

    if ($azure.StatusCode -eq 200) {
        Write-Host -ForegroundColor Green "Microsoft Azure Instance detected"
        }
    Else {
        throw "No Azure instance detected."
        }
}

function ManageWindowsFeatures {
    # Enable .NET 3.5 for running software based on this framework
    # Source: https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/enable-net-framework-35-by-using-windows-powershell#steps
    Install-WindowsFeature -Name 'Net-Framework-Core' | Out-Null
    # Manage special features for Server 2012 R2
    if($osType.Caption -like "*Windows Server 2012 R2*") {
        # Install qWave
        Install-WindowsFeature -Name 'qWave' -NoRestart | Out-Null
        # Install Desktop Experience for more PC features
        Install-WindowsFeature -Name 'Desktop-Experience' -NoRestart | Out-Null
        # Install Media Foundaction for better Audio/Video
        Install-WindowsFeature -Name 'Server-Media-Foundation' -NoRestart | Out-Null}
    
    # Manage special features for Server 2016/2019
    if($osType.Caption -like "*Windows Server 2016*" -or "*Windows Server 2019*") {
        # Uninstalling Windows Defender for saving resources
        Uninstall-WindowsFeature -Name Windows-Defender
    }
    # Enable DirectPlay for older games
    Install-WindowsFeature -Name 'DirectPlay' -NoRestart | Out-Null
    # Disable Internet Explorer for security reasons and better open-source alternatives
    Uninstall-WindowsFeature -Name 'Internet-Explorer-Optional-amd64' -NoRestart | Out-Null
    # Disable Windows Media Player for security reasons and better open-source alternatives
    Uninstall-WindowsFeature -Name 'WindowsMediaPlayer' -NoRestart | Out-Null
    # Enable Wireless LAN Service because some software need it
    Install-WindowsFeature -Name 'Wireless-Networking' -NoRestart | Out-Null
}

# Downloading GPU Updater tool and creating shortcut for it
function GPUDriverUpdate {
    ProgressWriter -Status "Downloading GPU UpdateTool on Azure" -PercentComplete $PercentComplete
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/SoftwareRat/Cloud-GPU-Updater/archive/refs/heads/master.zip", "C:\AzureTools\drivers\UpdateTool.zip")
    Expand-Archive -Path 'C:\AzureTools\drivers\UpdateTool.zip' -DestinationPath 'C:\AzureTools\drivers\' | Out-Null
    Rename-Item -Path 'C:\AzureTools\drivers\Cloud-GPU-Updater-master\' -NewName 'UpdateTool'
    Unblock-File -Path "C:\AzureTools\drivers\UpdateTool\GPUUpdaterTool.ps1"
    $Shell = New-Object -ComObject ("WScript.Shell")
    $ShortCut = $Shell.CreateShortcut("$env:USERPROFILE\Desktop\GPU Update Tool.lnk")
    $ShortCut.TargetPath="powershell.exe"
    $ShortCut.Arguments='-ExecutionPolicy Bypass -File "C:\AzureTools\drivers\UpdateTool\GPUUpdaterTool.ps1"'
    $ShortCut.WorkingDirectory = "C:\AzureTools\drivers\UpdateTool\";
    $ShortCut.IconLocation = "C:\AzureTools\drivers\UpdateTool\Additional Files\UpdateTool.ico, 0";
    $ShortCut.WindowStyle = 0;
    $ShortCut.Description = "Updating your GPU drivers";
    $ShortCut.Save()
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
    ProgressWriter -Status "Installing 7-Zip" -PercentComplete $PercentComplete
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install 7zip" -Wait | Out-
    # Download and install Google Chrome
    ProgressWriter -Status "Installing Google Chrome" -PercentComplete $PercentComplete
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install googlechrome" -Wait | Out-Null
    # Download and install VLC media Player
    ProgressWriter -Status "Installing VLC media Player" -PercentComplete $PercentComplete
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install vlc" -Wait | Out-Null
    # Download Microsoft Visual C++ Redist
    ProgressWriter -Status "Installing Microsoft Visual C++ redist" -PercentComplete $PercentComplete
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\choco.exe" -ArgumentList "install vcredist140" -Wait | Out-Null
    # Downloading and installing required DirectX librarys
    (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe", "C:\AzureTools\directx_Jun2010_redist.exe")
    Start-Process -FilePath "C:\AzureTools\directx_Jun2010_redist.exe" -ArgumentList '/T:C:\AzureTools\DirectX /Q' -Wait 
    Start-Process -FilePath "C:\AzureTools\DirectX\DXSETUP.EXE" -ArgumentList '/silent' -Wait 
}

<# Currently broken, will be fixed soon
function StreamingSolutionSelection {
    Do {
       $selection = Read-Host "Do you want to use Moonlight or Parsec? (M|P)"
       Switch($selection) {
          M { 'Moonlight' }
          P { 'Parsec' }
       }
       until{$selection -match "M|P"}
    }
}
$global:streamingsolutionselection = StreamingSolutionSelection
#>

function CheckForRDP {
    if([bool]((quser) -imatch "rdp")) {
        throw '[rdp_session_detected] RDP session detected, please use alternatives like AnyDesk or VNC!
For more information check out'
    }
}

function InstallDrivers {
    # Installing NVIDIA drivers
    Start-Process -FilePath "$DriverSetup" -ArgumentList "/s","/clean" -NoNewWindow -Wait
    $script = "-Command `"Set-ExecutionPolicy Unrestricted; & '$PSScriptRoot\PostNV6.ps1'`" -MoonlightAfterReboot";
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $script
    $trigger = New-ScheduledTaskTrigger -AtLogon -RandomDelay "00:00:30"
    $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
    Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "ScriptAfterReboot" -Description "This script getting automaticly executed after reboot" | Out-Null
    Restore-Computer -Force -Wait 3
}

function EnableAudio {
ProgressWriter -Status "Enabling Audio" -PercentComplete $PercentComplete
# Enabling Audio on Windows Server
    Set-Service -Name "Windows Audio" -StartupType Automatic | Out-Null
    Set-Service -Name "Windows Audio Endpoint Builder" -StartupType Automatic | Out-Null 
    Start-Service -Name "Windows Audio" | Out-Null 
    Start-Service -Name "Windows Audio Endpoint Builder" | Out-Null
# Downloading and Installing VBCABLE driver
IF ((Test-Path -Path 'C:\Windows\System32\drivers\vbaudio_cable64_win7.sys' -PathType Leaf)) {Write-Warning -Message 'VBAudio drivers found, skipping installation'} else {
    (New-Object Systen.Net.WebClient).DownloadFile("https://download.vb-audio.com/Download_CABLE/VBCABLE_Driver_Pack43.zip", "C:\AzureTools\drivers\VBCABLE_Driver_Pack43.zip")
    Expand-Archive -Path 'C:\AzureTools\drivers\VBCABLE_Driver_Pack43.zip' -DestinationPath 'C:\AzureTools\drivers\VBCABLE' | Out-Null
    $VBcableErrorCode = (Start-Process -FilePath "C:\AzureTools\drivers\VBCABLE\VBCABLE_Setup_x64.exe" -ArgumentList "-i","-h" -NoNewWindow -Wait -PassThru).GFEExitCode
        IF ($VBcableErrorCode -eq 0) {
        Write-Host -Object 'VBcable successfully installed'
        } else {
        Write-Error -Message ('[ERROR] VBcable failed to install (Errorcode {0})' -f $VBcableErrorCode)
        }
    }
}

function SetWindowsSettings {
ProgressWriter -Status "Changing Windows settings" -PercentComplete $PercentComplete
# Disables Server Manager opening on Startup
    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null

# Enable Dark Mode [Server 2019 only]
    if ($osType.Caption -like "*Windows Server 2019*") {
        if((Test-Path -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize') -eq $true) {} Else {New-Item -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes' -Name Personalize | Out-Null}
        Set-ItemProperty -Path 'registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name AppsUseLightTheme -Value 0}

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
    if((Test-RegistryValue -path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control' -value 'PriorityControl') -eq $true) {Set-ItemProperty -Path "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" -Name "PriorityControl" -Value 00000026 | Out-Null} else {New-ItemProperty -Path "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" -Name "PriorityControl" -Value 00000026 -PropertyType DWORD | Out-Null}

# Disabling Aero Shake
    if((Test-RegistryValue -path 'registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer' -value 'NoWindowMinimizingShortcuts') -eq $true) {Set-ItemProperty -Path "registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoWindowMinimizingShortcuts" -Value 1 | Out-Null} else {New-ItemProperty -Path "registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoWindowMinimizingShortcuts" -Value 1 -PropertyType DWORD | Out-Null}

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

# Set Autologon
    Write-Host -Object ('Enter your password for {0} to enable Autologon:' -f $env:USERNAME)
    SetSecureAutoLogon `
        -Username $env:USERNAME `
        -Password (Read-Host -AsSecureString)
}

function SetSecureAutoLogon {
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
	
	[string] $WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
	[string] $WinlogonBannerPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

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
    # Scanning for disks not initialized 
    $DISK = Get-Disk | Where-Object PartitionStyle -Eq "RAW"
    IF (!$DISK) {
    # Output warning when no disk is found
    Write-Warning 'No disk found, skipping configuration of disk for saving games'} else {
    # When Disk is found
    # Change registry key for prevent autostart of explorer
    Set-ItemProperty 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoRestartShell -Value 0
    # Killing explorer process as a WAR for not output format wizard
    Stop-Process -Name explorer* -Force
    # Create Disk with "SoftwareDisk" as name mounted as "A:" 
    Get-Disk | Where-Object PartitionStyle -Eq "RAW" | Initialize-Disk -PassThru | New-Partition -DriveLetter A -UseMaximumSize | Format-Volume -confirm:$false | Out-Null
    # Rollback registry key
    Set-ItemProperty 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoRestartShell -Value 1
    # Restart Explorer
    Start-Process "C:\Windows\System32\userinit.exe"
    }
}

function DisableVGA {
ProgressWriter -Status "Disable non-NVIDIA gpu's" -PercentComplete $PercentComplete
# Disable non-NVIDIA GPU's
    if($osType.Caption -like "*Windows Server 2012 R2*") {
        # This command get executed when OS is Server 2012
        Start-Process -FilePath $($WorkDir) + 'C:\AzureTools\devcon.exe' -ArgumentList 'disable "VMBUS\{DA0A7802-E377-4AAC-8E77-0558EB1073F8}"' -Wait -NoNewWindow | Out-Null
    } else {
        # This command get executed when OS is Server 2016/2019
        Get-PnpDevice -Class "Display" -Status OK | Where-Object { $_.Name -notmatch "nvidia" } | Disable-PnpDevice -confirm:$false | Out-Null
    }
}

Function ProgressWriter {
    param (
    [int]$percentcomplete,
    [string]$status
    )Write-Progress -Activity "Azure VM will be prepared for CloudGaming" -Status $status -PercentComplete $PercentComplete}

function BlockHost {
    $BlockedHosts = @("telemetry.gfe.nvidia.com", "ls.dtrace.nvidia.com", "ota.nvidia.com", "ota-downloads.nvidia.com", "rds-assets.nvidia.com", "nvidia.tt.omtrdc.net", "api.commune.ly", "namso-gen.com", "nulled.to")
    $HostsFile = "$env:SystemRoot\System32\Drivers\etc\hosts"
    $HostsContent = [String](Get-Content -Path $HostsFile)
    $Appended = ""

    foreach($Entry in $BlockedHosts) {
        if($HostsContent -notmatch $Entry) {function BlockHost {
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
                Write-Host "Added hosts:`r`n$Appended"
                Add-Content -Path $HostsFile -Value $Appended
            }
        }
            $Appended += "0.0.0.0 $Entry`r`n"
        }
    }

    if($Appended.Length -gt 0) {
        $Appended = $Appended.Substring(0,$Appended.length-2)
        Write-Host "Added hosts:`r`n$Appended"
        Add-Content -Path $HostsFile -Value $Appended
    }
}

function DownloadNVIDIAdrivers {
    ProgressWriter -Status "Downloading NVIDIA drivers" -PercentComplete $PercentComplete
    # Downloading NVIDIA drivers
    if($osType.Caption -like "*Windows Server 2012 R2*") {
        # This command get executed when OS is Server 2012
        Write-Host -Object ('Detected OS: ({0})' -f $OSType.Caption) -ForegroundColor Green    
        $azuresupportpage = (Invoke-WebRequest -Uri https://docs.microsoft.com/en-us/azure/virtual-machines/windows/n-series-driver-setup -UseBasicParsing).links.outerhtml -like "*server2012R2*"
        $GPUversion = $azuresupportpage.split('(')[1].split(')')[0]
        (New-Object System.Net.WebClient).DownloadFile($($azuresupportpage[0].split('"')[1]), 'C:\AzureTools\drivers' + "\" + $($GPUversion) + "_grid_server2012R2_64bit_azure_swl.exe")
        Set-Variable -Name 'DriverSetup' -Value C:\AzureTools\drivers\$($GPUversion)_grid_server2012R2_64bit_azure_swl.exe
    } else {
        # This command get executed when OS is Server 2016/2019
        Write-Host -Object ('Detected OS: ({0})' -f $OSType.Caption) -ForegroundColor Green
        $azuresupportpage = (Invoke-WebRequest -Uri https://docs.microsoft.com/en-us/azure/virtual-machines/windows/n-series-driver-setup -UseBasicParsing).links.outerhtml -like "*GRID*"
        $GPUversion = $azuresupportpage.split('(')[1].split(')')[0]
        (New-Object System.Net.WebClient).DownloadFile($($azuresupportpage[0].split('"')[1]), 'C:\AzureTools\drivers' + "\" + $($GPUversion) + "_grid_win10_server2016_server2019_64bit_azure_swl.exe")
        Set-Variable -Name 'DriverSetup' -Value C:\AzureTools\drivers\$($GPUversion)_grid_win10_server2016_server2019_64bit_azure_swl.exe}
    }
        

function GameStreamAfterReboot {
    Unregister-ScheduledTask -TaskName "GSSetup" -Confirm:$false 
    ProgressWriter -Status "Patching GameStream to work with this GPU" -PercentComplete $PercentComplete
    Write-Output -InputObject 'Downloading GameStream Patcher [CREDIT: acceleration3]'
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/acceleration3/cloudgamestream/master/Steps/Patcher.ps1", "C:\AdminTools\GameStream\Patcher.ps1")
    # Allowing GameStream Rules via Windows Firewall [for Moonlight]
    New-NetFirewallRule -DisplayName "NVIDIA GameStream TCP" -Direction Inbound -LocalPort 47984,47989,48010 -Program 'C:\Program Files\NVIDIA Corporation\NvStreamSrv\nvstreamer.exe' -Protocol TCP -Action Allow | Out-Null
    New-NetFirewallRule -DisplayName "NVIDIA GameStream UDP" -Direction Inbound -LocalPort 47998,47999,48000,48010 -Program 'C:\Program Files\NVIDIA Corporation\NvStreamSrv\nvstreamer.exe' -Protocol UDP -Action Allow | Out-Null
    Write-Host "Patching GFE to allow the GPU's Device ID..."
    Stop-Service -Name NvContainerLocalSystem | Out-Null
    $TargetDevice = (Get-WmiObject Win32_VideoController | Select-Object PNPDeviceID,Name | Where-Object Name -match "nvidia" | Select-Object -First 1) 
    if(!$TargetDevice) {
    throw "Failed to find an NVIDIA GPU."
    }
    if(!($TargetDevice.PNPDeviceID -match "DEV_(\w*)")) {
    throw "Regex failed to extract device ID."
    }
    & $PSScriptRoot\Patcher.ps1 -DeviceID $matches[1] -TargetFile "C:\Program Files\NVIDIA Corporation\NvContainer\plugins\LocalSystem\GameStream\Main\_NvStreamControl.dll";
}

function InstallGFE {
    $IP = (Invoke-RestMethod -Method Get -Uri "http://ip-api.com/json/$IPAddress")
    IF ($IP.countrycode -eq "US" -or $IP.countrycode -eq "SG") {
        Set-Variable -Name 'CountryCode' -Value 'us' | Out-Null
    } elseif ($IP.countrycode -eq "NL" -or $IP.countrycode -eq "UK") {
        Set-Variable -Name 'CountryCode' -Value 'uk' | Out-Null
    } elseif ($IP.countrycode -eq "JP") {
        Set-Variable -Name 'CountryCode' -Value 'jp' | Out-Null
    } elseif ($IP.countrycode -eq "IN") {
        Set-Variable -Name 'CountryCode' -Value 'in' | Out-Null
    } else {Set-Variable -Name 'CountryCode' -Value 'us' | Out-Null}
    Write-Host -Object ('Detected country: ({0})' -f $CountryCode)
    (New-Object System.Net.WebClient).DownloadFile("https://$($CountryCode).download.nvidia.com/GFE/GFEClient/3.13.0.85/GeForce_Experience_Beta_v3.13.0.85.exe", "C:\AzureTools\GeForce_Experience.exe")
    $GFEExitCode = (Start-Process -FilePath "C:\AzureTools\GeForce_Experience.exe" -ArgumentList "-s" -NoNewWindow -Wait -PassThru).GFEExitCode
    if($GFEExitCode -eq 0) {Write-Host "Successfully installed GeForce Experience" -ForegroundColor Green}
    else { 
    throw ("[ERROR {0}] GeForce Experience installation failed." -f $GFEExitCode)}    
    }

Function XboxController {
    ProgressWriter -Status "Downloading controller drivers" -PercentComplete $PercentComplete
    # Downloading basic Xbox 360 controller driver
    (New-Object System.Net.WebClient).DownloadFile("http://www.download.windowsupdate.com/msdownload/update/v3-19990518/cabpool/2060_8edb3031ef495d4e4247e51dcb11bef24d2c4da7.cab", "C:\AzureTools\drivers\Xbox360_64Eng.cab")
    if((Test-Path -Path C:\AzureTools\drivers\Xbox360_64Eng) -eq $true) {} Else {New-Item -Path C:\AzureTools\drivers\Xbox360_64Eng -ItemType directory | Out-Null}
    cmd.exe /c "C:\Windows\System32\expand.exe C:\AzureTools\drivers\Xbox360_64Eng.cab -F:* C:\AzureTools\drivers\Xbox360_64Eng" | Out-Null
    cmd.exe /c '"C:\AzureTools\devcon.exe" dp_add "C:\AzureTools\drivers\Xbox360_64Eng\xusb21.inf"' | Out-Null
    # Downloading ViGEm
    if($osType.Caption -like "*Windows Server 2012*") {
        # This command get executed when OS is Server 2012
        (New-Object System.Net.WebClient).DownloadFile("https://github.com/ViGEm/ViGEmBus/releases/download/setup-v1.16.116/ViGEmBus_Setup_1.16.116.exe", "C:\AzureTools\ViGEmBus_Setup_win2012.exe")
        Start-Process "C:\AzureTools\ViGEmBus_Setup_win2012.exe" -ArgumentList '/qn' -Wait -NoNewWindow
    } else {
        # This command get executed when OS is Server 2016/2019
        $vigembus = (Invoke-WebRequest -Uri https://github.com/ViGEm/ViGEmBus/releases -UseBasicParsing).links.outerhtml -like "*ViGEmBusSetup_x64.msi*"
        (New-Object System.Net.WebClient).DownloadFile('https://github.com/' + $($vigembus[0].split('"')[1]), 'C:\AzureTools\ViGEmBusSetup_x64.msi')
        Start-Process 'C:\Windows\System32\msiexec.exe' -ArgumentList '/i "C:\AzureTools\ViGEmBusSetup_x64.msi" /qn /norestart' -Wait -NoNewWindow | Out-Null
    }
}

# Set $osType for checking for OS
$osType = Get-CimInstance -ClassName Win32_OperatingSystem

# Changing Title to "First-time setup for Gaming on Microsoft Azure"
$host.ui.RawUI.WindowTitle = "Automate Azure CloudGaming Tasks [Version 0.7]"

# Changing SecurityProtocol for prevent SSL issues with websites
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

Write-Host -ForegroundColor DarkBlue -BackgroundColor Black '
Azure Automation Gaming Script [Version 0.7]
(c) 2021 SoftwareRat. All rights reserved.
'

if(!$MoonlightAfterReboot) {
    $ScripttaskList = (
    "CheckForRDP",
    "TestForAzure",
    "CheckOSsupport",
    "EnableAudio",
    "ManageWindowsFeatures",
    "SetWindowsSettings",
    "XboxController",
    "AddNewDisk",
    "InstallChocolatey",
    "DownloadNVIDIAdrivers",
    "InstallDrivers"
)
} else {
    $ScripttaskListAfterReboot = (
    "CheckForRDP",
    "TestForAzure",
    "CheckOSsupport",
    "InstallGFE",
    "GameStreamAfterReboot",
    "DisableVGA"
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
Write-Host -Object 'This script finished all tasks'
Write-Host -Object 'When you have bugs or feedback suggestions,'
Write-Host -Object 'go to the GitHub repository of this project'
Restart-Computer -Wait 5 -Force
EXIT