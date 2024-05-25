$targets = Import-Csv .\AllHosts.csv |
<#    Where-Object {$_.os -eq "Win10"} |#>
    Select-Object -ExpandProperty ip

#Get Credentials from the Operator
<#$creds = Get-Credential#>

#Set session options (This is required for out of band connections)
<#$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck #>

Invoke-Command -ComputerName $targets -Credential $creds 
{Get-NetIPConfiguration} | Export-Csv .\Baseline\network_baseline.csv