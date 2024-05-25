# import targets list
$targets = Import-Csv .\AllHosts.csv |
  #Where-Object {$_.os -eq "Win10"} |
    Select-Object -ExpandProperty ip

# get date for file name
$filename = "Folders_Baseline_" + (Get-Date -Format "MM-dd-yy")

# Changed to psobject to allow for expansion of script to allow more artifacts to be extracted and linked to each object.
# Additionally, now extracting IP address vs the computername.

# get credentials from operator
$creds = get-credential
# set session options (This is required for out of band connections)
$so = New-PSSessionOption  -SkipCACheck -SkipCNCheck -SkipRevocationCheck

# import configurations
$configs = Get-Content -Path .\configuration.json | ConvertFrom-Json

foreach ( $target in $targets ) {
$common_exploited_folders = $configs.common_exploited_folders -split ','

$folders = foreach ($folderPath in $common_exploited_folders) {
    Invoke-Command -CN $target -CR $creds -SessionOption $so -ScriptBlock {
        param ($folderPath)
        Get-ChildItem -Path $folderPath -Recurse -Force -ErrorAction Continue
    } -ArgumentList $folderPath
}

  foreach ( $item in $folders ){
    $OutputObj = [pscustomobject]@{ 
        IP              = $target
        Name            = $item.Name
        Path            = $item.Fullname
        Mode            = $item.Mode
        Attributes      = $item.Attributes
        Extension       = $item.Extension
        CreationTime    = $item.CreationTime
        LastAccessTime  = $item.LastAccessTime
        LastWriteTime   = $item.LastWriteTime
    }
    $OutputObj | Export-Csv .\Baseline\$filename.csv -Append    
  }
}