$targets = Import-Csv ..\AllHosts.csv |
  #Where-Object {$_.os -like "*2012*"} |
    Select-Object -ExpandProperty ip

# get date for file name
$filename = "Autoruns_Baseline_" + (Get-Date -Format "MM-dd-yy")

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

# will replace with function to locate old baseline
$old = Import-Csv .\Baseline\Autoruns_Baseline_Old.csv

$current = Import-Csv .\Baseline\$filename.csv

# Need to explicitly list each property for the compare cmdlet to compare every property
# Doesn't show difference object (current) in result, only the reference object (old) with side indicator
# Side indicator points towards the file where the object DOES exist. ex: left for old, right for new.
Compare-Object $old $current -Property ip,name,command,user,usersid,location