param([string] $FolderOut=".\Audit")

#Get Credentials from the Operator
$creds = Get-Credential

#Import Targets List
$targets = Import-Csv .\AllHosts.csv

#Set session options (This is required for out of band connections)
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

#Import Configurations
$configs = Get-Content -Path .\configuration.json | ConvertFrom-Json

#1 Accounts
#Get accounts stored on the computer
$targets | ForEach-Object {if($_.Subnet -eq "OpsNet" -and $_.OS -eq "Win10") {Invoke-Command -UseSSL -SessionOption $so -ComputerName $_.IP -Credential $creds -FilePath .\01_Reference_Scripts\accounts.ps1}} | Export-Csv -Path $FolderOut + "\Accounts.csv"

#2 Processes
#Pull running processes on the computer
$targets | ForEach-Object {if($_.Subnet -eq "OpsNet" -and $_.OS -eq "Win10") {Invoke-Command -UseSSL -SessionOption $so -ComputerName $_.IP -Credential $creds -FilePath .\01_Reference_Scripts\processes.ps1}} | Export-Csv -Path $FolderOut + "\Processes.csv"

#3 Services
#Audit services on the computer
$targets | ForEach-Object {if($_.Subnet -eq "OpsNet" -and $_.OS -eq "Win10") {Invoke-Command -UseSSL -SessionOption $so -ComputerName $_.IP -Credential $creds -FilePath .\01_Reference_Scripts\services.ps1}} | Export-Csv -Path $FolderOut + "\Services.csv"

#4 Software Inventory
#Get software installed on the computer
$targets | ForEach-Object {if($_.Subnet -eq "OpsNet" -and $_.OS -eq "Win10") {Invoke-Command -UseSSL -SessionOption $so -ComputerName $_.IP -Credential $creds -FilePath .\01_Reference_Scripts\softwareinventory.ps1 -ArgumentList (,$configs.program_folders)}} | Export-Csv -Path $FolderOut + "\Software.csv"

#5 Files
#Get folder listing of commonly exploited folder locations
$targets | ForEach-Object {if($_.Subnet -eq "OpsNet" -and $_.OS -eq "Win10") {Invoke-Command -UseSSL -SessionOption $so -ComputerName $_.IP -Credential $creds -FilePath .\01_Reference_Scripts\foldersofinterest.ps1 -ArgumentList (,$configs.common_exploited_folders)}} | Export-Csv -Path $FolderOut + "\FoldersOfInterest.csv"

#6 Registry Keys
#Audit services on the computer
$targets | ForEach-Object {if($_.Subnet -eq "OpsNet" -and $_.OS -eq "Win10") {Invoke-Command -UseSSL -SessionOption $so -ComputerName $_.IP -Credential $creds -FilePath .\01_Reference_Scripts\autoruns.ps1 -ArgumentList (,$configs.autorun_locations)}} | Export-Csv -Path $FolderOut + "\Registry_Keys.csv"

#7 Scheduled Tasks
#Audit scheduled tasks on the computer
$targets | ForEach-Object {if($_.Subnet -eq "OpsNet" -and $_.OS -eq "Win10") {Invoke-Command -UseSSL -SessionOption $so -ComputerName $_.IP -Credential $creds -FilePath .\01_Reference_Scripts\scheduled_task.ps1}} | Export-Csv -Path $FolderOut + "\Scheduled_Tasks.csv"

#8 EXE/DLL List
#Get file listing of given patterns (recursively)
$targets | ForEach-Object {if($_.Subnet -eq "OpsNet" -and $_.OS -eq "Win10") {Invoke-Command -UseSSL -SessionOption $so -ComputerName $_.IP -Credential $creds -FilePath .\01_Reference_Scripts\filesofinterest.ps1 -ArgumentList (,$FilePatterns)}} | Export-Csv -Path $FolderOut + "\FilesOfInterest.csv"

#9 Interfaces
#Get ipconfig info for hosts
$targets | ForEach-Object {if($_.Subnet -eq "OpsNet" -and $_.OS -eq "Win10") {Invoke-Command -UseSSL -SessionOption $so -ComputerName $_.IP -Credential $creds -ScriptBlock {Get-NetIPConfiguration}}} | Export-Csv -Path $FolderOut + "\Interfaces.csv"

#10 Firewall
#Pull firewall rules
$targets | ForEach-Object {if($_.Subnet -eq "OpsNet" -and $_.OS -eq "Win10") {Invoke-Command -UseSSL -SessionOption $so -ComputerName $_.IP -Credential $creds -FilePath .\01_Reference_Scripts\firewalls.ps1}} | Export-Csv -Path $FolderOut + "\Firewall.csv"