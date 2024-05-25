# import targets list
$targets = Import-Csv .\AllHosts.csv |
  #Where-Object {$_.os -eq "Win10"} |
    Select-Object -ExpandProperty ip

# Changed to psobject to allow for expansion of script to allow more artifacts to be extracted and linked to each object.
# Additionally, now extracting IP address vs the computername.

# get date for file name
$filename = "Autoruns_Baseline_" + (Get-Date -Format "MM-dd-yy")

# get credentials from operator
$creds = get-credential
# set session options (This is required for out of band connections)
$so = New-PSSessionOption  -SkipCACheck -SkipCNCheck -SkipRevocationCheck

foreach ( $target in $target ) {
  $autoruns = Invoke-Command -CN $target -CR $creds -SessionOption $so {
    Get-CimInstance -Class Win32_StartupCommand
  }
  foreach ( $entry in $autoruns ){
    $OutputObj = [pscustomobject]@{ 
      IP        = $target
      Name      = $entry.Name
      Command   = $entry.Command
      User      = $entry.User
      UserSID   = $entry.UserSID
      Location  = $entry.Location
    }
    $OutputObj | Export-Csv .\Baseline\$filename.csv -Append
  }
}

