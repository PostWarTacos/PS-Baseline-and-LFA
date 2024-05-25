# import targets list
$targets = Import-Csv .\AllHosts.csv |
<#    Where-Object {$_.os -eq "Win10"} |#>
    Select-Object -ExpandProperty ip

#Get Credentials from the Operator
$creds = Get-Credential

# set session options (This is required for out of band connections)
$so = New-PSSessionOption  -SkipCACheck -SkipCNCheck -SkipRevocationCheck

# get date for file name
$filename = "Software_Baseline_" + (Get-Date -Format "MM-dd-yy")

# Function to retrieve user who installed software from Event Logs
function Get-SoftwareInstallUser($appName){
    $eventLog = Get-WinEvent -LogName "Application" | Where-Object { $_.id -eq 1033 -and $_.message -like "*$appname*"}
    if($eventLog){
        if($eventLog.UserID){
            return $eventLog.UserID.value
        }
        else {
            return "Unknown"
        }
    }
}

foreach ($target in $targets) {

$softwarelist = Invoke-Command -CN $target -CR $creds -SessionOption $so {
        $result = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
        $result += Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
        $result += Get-ItemProperty REGISTRY::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*
        return $result
    }

    foreach ($software in $softwareList) {
        $InstalledBySID = Get-SoftwareInstallUser $software.Name
        if ( $InstalledBySID -ne "Unknown" ){
            $InstalledByUser = (Get-CimInstance -ClassName Win32_Useraccount | Where-Object { $_.SID -eq $InstalledBySID }).name
            if ( -Not ( $InstalledByUser )){
                $InstalledByUser = (Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -eq $InstalledBySID }).LocalPath
            }
        }
        $OutputObj = [PSCustomObject]@{
            IP                  = $target
            PSParentPath        = $software.PSPath
            PSChildName         = $software.PSChildName
            DisplayName         = if ( $software.DisplayName ) { $software.DisplayName } else { '-' }
            DisplayVersion      = if ( $software.DisplayVersion ) { $software.DisplayVersion } else { '-' }
            InstallDate         = if ( $software.InstallDate ) { $software.InstallDate } else { '-' }
            InstallLocation     = if ( $software.InstallLocation ) { $software.InstallLocation } else { '-' }
            Publisher           = if ( $software.Publisher ) { $software.Publisher } else { '-' }
            UninstallString     = if ( $software.UninstallString ) { $software.UninstallString } else { '-' }
            InstalledToProfile  = if ( $software.UninstallString -like "*C:\users\*" ) {( $software.UninstallString -split '\\' )[2]} else { '-' }
            InstalledBySID      = $InstalledBySID
            InstalledByUser     = $InstalledByUser
        }
        $OutputObj | Export-Csv .\Baseline\$filename -Append
    }
}