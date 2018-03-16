Import-Module ServerManager
Add-WindowsFeature RemoteAccess, Routing, RSAT-RemoteAccess
Get-NetAdapter | Set-NetIPInterface -Forwarding Enabled
Set-Service remoteaccess -StartupType Automatic
Start-Service remoteaccess
