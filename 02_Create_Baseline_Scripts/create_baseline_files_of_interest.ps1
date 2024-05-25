# import targets list
$targets = Import-Csv .\AllHosts.csv |
  #Where-Object {$_.os -eq "Win10"} |
  Select-Object -ExpandProperty ip

# get date for file name
$filename = "Files_Baseline_" + (Get-Date -Format "MM-dd-yy")

# import configurations
$configs = Get-Content -Path .\configuration.json | ConvertFrom-Json

# get credentials from the operator
$creds = Get-Credential
# set session options (This is required for out of band connections)
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

# Changed to psobject to allow for expansion of script to allow more artifacts to be extracted and linked to each object.
# Additionally, now extracting IP address vs the computername.

foreach ( $target in $targets ){
    $files = Invoke-Command -CN $target -CR $creds -SessionOption $so -ArgumentList $configs.file_patterns {
        param ($filePatterns)
        $filePatterns = $filePatterns -split ','
        Get-ChildItem -Path C:\ -Recurse -File -include $filePatterns -Force -ErrorAction Continue
    } 
    foreach ( $file in $files ){
        $OutputObj = [pscustomobject]@{ 
            IP              = $target
            Name            = $file.Name
            ResolvedTarget  = $file.ResolvedTarget
            Mode            = $file.Mode
            Attributes      = $file.Attributes
            Extension       = $file.Extension
            CreationTime    = $file.CreationTime
            LastAccessTime  = $file.LastAccessTime
            LastWriteTime   = $file.LastWriteTime
        }
        $OutputObj | Export-Csv .\Baseline\$filename.csv -Append
    }
}