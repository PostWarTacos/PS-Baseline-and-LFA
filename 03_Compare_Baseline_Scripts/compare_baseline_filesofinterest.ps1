$targets = Import-Csv ..\AllHosts.csv |
 #Where-Object {$_.OS -eq "Win10"} |
  Select-Object -ExpandProperty IP

# get date for file name
$filename = "Files_Baseline_" + (Get-Date -Format "MM-dd-yy")  

#Import Configurations
$configs = Get-Content -Path ..\configuration.json | ConvertFrom-Json

#Get Credentials from the Operator
$creds = Get-Credential

#Set session options (This is required for out of band connections)
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    
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

# will replace with function to locate old baseline
$old = Import-Csv .\Baseline\Files_Baseline_Old.csv

$current = Import-Csv .\Baseline\$filename.csv

# Need to explicitly list each property for the compare cmdlet to compare every property
# Doesn't show difference object (current) in result, only the reference object (old) with side indicator
# Side indicator points towards the file where the object DOES exist. ex: left for old, right for new.
Compare-Object $old $current -Property ip,name,ResolvedTarget,Mode,Attributes,Extension,CreationTime,LastAccessTime,LastWriteTime