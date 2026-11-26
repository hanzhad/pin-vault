# Register the logon task that asks for the PIN: pin-vault's own window,
# logon.sh. Run in your own PowerShell; no elevation needed. Run again to
# update; -Remove to take it out.
#
#   pin-vault unlock      visible   logon.sh: asks the PIN, runs pin-vault
#                                   unlock, closes (stays open on a failure)
#
# The task runs as the logged-on user with an interactive token, which is what
# DPAPI CurrentUser and WSL interop both want. Nothing here runs elevated and
# nothing runs when nobody is logged on.
[CmdletBinding()]
param(
  [string]$Distro = 'Ubuntu-24.04',
  [string]$InstallDir = '',    # path inside WSL; default ~/Projects/pin-vault there
  [switch]$Remove
)
$ErrorActionPreference = 'Stop'
$unlock = 'pin-vault unlock'

if ($Remove) {
  if (Get-ScheduledTask -TaskName $unlock -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $unlock -Confirm:$false
    Write-Host "removed: $unlock"
  }
  exit 0
}

if (-not $InstallDir) {
  $home_ = (& wsl.exe -d $Distro -- sh -c 'printf %s "$HOME"') -replace "`0", ''
  if (-not $home_) { throw "cannot read `$HOME from $Distro - is the distro installed?" }
  $InstallDir = "$home_/Projects/pin-vault"
}
$logon = "$InstallDir/windows/logon.sh"
& wsl.exe -d $Distro -- test -x $logon
if ($LASTEXITCODE -ne 0) { throw "not executable inside ${Distro}: $logon" }

$user = "$env:USERDOMAIN\$env:USERNAME"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$common = @{ AllowStartIfOnBatteries = $true; DontStopIfGoingOnBatteries = $true; ExecutionTimeLimit = [TimeSpan]::Zero }

$unlockAction = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\wsl.exe" `
  -Argument "-d $Distro --exec $logon"
$unlockSettings = New-ScheduledTaskSettingsSet @common
Register-ScheduledTask -TaskName $unlock -Action $unlockAction -Trigger $trigger -Settings $unlockSettings -RunLevel Limited -Force | Out-Null
Write-Host "registered: $unlock  (visible, at logon of $user)"
Write-Host ""
Write-Host "test without rebooting:  Start-ScheduledTask -TaskName '$unlock'"
