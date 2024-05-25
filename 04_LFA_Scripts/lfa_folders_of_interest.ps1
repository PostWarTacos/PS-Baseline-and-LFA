param([int] $Count=1)

$targets = Import-Csv ..\AllHosts.csv |
        Select-Object -ExpandProperty ip

#Import Configurations
$configs = Get-Content -Path .\configuration.json | ConvertFrom-Json

#Get Credentials from the Operator
$creds = Get-Credential 

#Set session options (This is required for out of band connections)
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

$current = Invoke-Command -UseSSL -SessionOption $so -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\foldersofinterest.ps1 -ArgumentList (,$configs.common_exploited_folders)

$current | Sort-Object -Property pscomputername, Path -Unique |
    Group-Object Path |
    Where-Object {$_.count -le $Count} |
    Select-Object -ExpandProperty Group