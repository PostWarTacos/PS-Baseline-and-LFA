Get-WmiObject -Class Win32_StartupCommand |
Select-Object Command,User,UserSID,Location
