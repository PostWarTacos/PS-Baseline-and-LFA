param([int] $Count=1)

$targets = Import-Csv ..\AllHosts.csv |
        Select-Object -ExpandProperty ip

#Get Credentials from the Operator
$creds = Get-Credential

#Set session options (This is required for out of band connections)
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

$current = Invoke-Command -UseSSL -SessionOption $so -ComputerName $targets -Credential $creds -ScriptBlock {Get-NetIPConfiguration}

$current | Sort-Object -Property pscomputername, InterfaceAlias -Unique |
    Group-Object InterfaceAlias |
    Where-Object {$_.count -le $Count} |
    Select-Object -ExpandProperty Group