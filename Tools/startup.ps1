$DATEANDTIME = (Get-Date -Format "ddMMyyyy_HH-mm-ss")
$DATEANDTIMELOG = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Start-Transcript -Path ("C:\AzureTools\logs\startup_" + $DATEANDTIME + ".log")
Write-Host("=========================================================================")
Write-Host("========================== Seat Startup =================================")
Write-Host("=========================================================================")
Write-Host ('[{0}] Forcing custom EDID' -f $DATEANDTIMELOG)
cmd.exe /C "echo y | C:\AzureTools\forcedisp\Win10-ForceDispx64.exe f C:\AzureTools\forcedisp\NvidiaVGX_custom_16_9_1920_1080.hex 0 100"
Write-Host ('[{0}] Setting native resolution in the base image' -f $DATEANDTIMELOG)
$nvDisplayResError = (Start-Process -FilePath 'C:\AzureTools\nvDisplayRes.exe' -ArgumentList '--x 1920 --y 1080' -Wait -PassThru).ExitCode
if($nvDisplayResError -eq 0) {
    # When errorcode is 0 (successful)
    Write-Host "Success setting 1920x1080 native resolution for 16x9 aspect ratio" -ForegroundColor Green } else {
    # When errorcode is other then 0 (unsuccessful)
    Write-Error ('[ERROR]: Failed to set 1920X1080 native resolution for 16x9 aspect ratio.')}
Write-Host 'Switching primary display to nvidia head using gameseatdisplay tool'
$GameSeatDisplayError = (Start-Process -FilePath 'C:\AzureTools\GameSeatDisplay.exe' -ArgumentList '--activate-display' -Wait -PassThru).ExitCode
    if ($GameSeatDisplayError -eq 0) {
        "Success setting primary display to nvidia head"
    } else {
        (Write-Error "[ERROR]: Failed setting primary display to nvidia head")
    }
# Checking if module is installed
Import-Module -Name 'PSWindowsUpdate' -Force -ErrorAction SilentlyContinue | Out-Null 
IF (!(Get-InstalledModule PSWindowsUpdate -ErrorAction SilentlyContinue)) {
    Write-Host -ForegroundColor Red -Object 'Windows Update module not installed, installing it again...'
    Set-PSRepository -Name "PSGallery" -InstallationPolicy 'Trusted'
    Install-PackageProvider -Name 'NuGet' -Scope 'AllUsers' -Force
    Install-Module -Name 'PSWindowsUpdate' -Scope 'AllUsers' -Force
}
# Checking for Windows updates
Write-Host -Object 'Scanning and installing Windows Updates...'
Get-WindowsUpdate -AcceptAll -Install
Write-Host("*************************************************************************")
Write-Host("================= Completed Startup Script Execution  ===================")
Write-Host("*************************************************************************")
Stop-Transcript