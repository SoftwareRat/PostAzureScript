$DATEANDTIME = (Get-Date -Format "ddMMyyyy_HH-mm-ss")
$DATEANDTIMELOG = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Start-Transcript -Path ("C:\AzureTools\logs\startup_" + $DATEANDTIME + ".log")
Write-Host ('[{0}] Forcing custom EDID' -f $DATEANDTIMELOG)
cmd.exe /C "echo y | C:\AzureTools\Tools\forcedisp\Win10-ForceDispx64.exe C:\AzureTools\forcedisp\NvidiaVGX_custom_16_9_1920_1080.hex"
Write-Host ('[{0}] Setting native resolution in the base image' -f $DATEANDTIMELOG)
$nvDisplayResError = (Start-Process -FilePath 'C:\AzureTools\Tools\nvDisplayRes.exe' -ArgumentList '--x 1920 --y 1080' -Wait).ExitCode
if($nvDisplayResError -eq 0) {
    # When errorcode is 0 (successful)
    Write-Host "Success setting 1920x1080 native resolution for 16x9 aspect ratio" -ForegroundColor Green } else {
    # When errorcode is other then 0 (unsuccessful)
    Write-Error ('[ERROR {0}]: Failed to set 1920X1080 native resolution for 16x9 aspect ratio.' -f $nvDisplayResError)}
Write-Host 'Switching primary display to nvidia head using gameseatdisplay tool'
$GameSeatDisplayError = (Start-Process -FilePath 'C:\AzureTools\GameSeatDisplay.exe' -ArgumentList '--activate-display')
    if ($GameSeatDisplayError -eq 0) {
        "Success setting primary display to nvidia head"
    } else {
        ("[ERROR {0}]: Failed setting primary display to nvidia head" -f $GameSeatDisplayError)
    }
Stop-Transcript