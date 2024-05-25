param([string] $BaselinePath="..\Baseline\Interfaces_Baseline.csv")

$targets = Import-Csv ..\AllHosts.csv |
  Where-Object {$_.OS -eq "Win10"} |
    Select-Object -ExpandProperty IP

#Get Credentials from the Operator
$creds = Get-Credential

#Set session options (This is required for out of band connections)
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    
$ht = @{
  ReferenceObject = Import-Csv $BaselinePath
  Property        = "NetAdapter"
  PassThru        = $true
}

$current = Invoke-Command -UseSSL -SessionOption $so -ComputerName $targets -Credential $creds -ScriptBlock {Get-NetIPConfiguration}

ForEach ($ip in $targets){
  $ht.DifferenceObject = $current |
  Where-Object {$_.pscomputername -eq $ip} |
  Sort-Object -Property NetAdapter -Unique
    
  Compare-Object @ht |
  Where-Object {$_.sideindicator -eq "=>"}
}
