# Changing Title to "First-time setup for Gaming on Microsoft Azure"
$host.ui.RawUI.WindowTitle = "First-time setup for Gaming on Microsoft Azure"

# Changing SecurityProtocol for prevent SSL issues with websites
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

# Checking if this script get executed on a Microsoft Azure instance
$azure = $(
# Pinging Azure service
# Source: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service?tabs=windows
Try {(Invoke-WebRequest -Uri "http://169.254.169.254/metadata/instance?api-version=2020-09-01" -Headers @{Metadata="true"} -TimeoutSec 5)}
    catch {}
    )

# IF startement for WebRequest Statuscode
if ($azure.StatusCode -eq 200) {
        # When Azure instance got detected
        Write-Output "Microsoft Azure Instance detected"
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
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
(New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')
# Enable to execute PowerShell scripts silently without to confirm
Start-Process -FilePath "C:\ProgramData\chocolatey\bin\chocolatey.exe" -ArgumentList "feature enable -n allowGlobalConfirmation" -Wait | Out-Null
# Download and install most common game launchers 
    # Download and install Steam
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\chocolatey.exe" -ArgumentList "install steam" -Wait | Out-Null
    # Download and install Epic Games Launcher
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\chocolatey.exe" -ArgumentList "install epicgameslauncher" -Wait | Out-Null
    # Download and install Origin
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\chocolatey.exe" -ArgumentList "install origin" -Wait | Out-Null
    # Download and install Ubisoft Connect [earlier known as uPlay]
    Start-Process -FilePath "C:\ProgramData\chocolatey\bin\chocolatey.exe" -ArgumentList "install ubisoft-connect" -Wait | Out-Null