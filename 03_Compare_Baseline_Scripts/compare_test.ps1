#
#
#  TEST 1
#
#

# $set1 = 1, 2, 3, 4, 5
# $set2 = 3, 4, 5, 6, 7

# $diff = Compare-Object -ReferenceObject $set1 -DifferenceObject $set2

# # Display both DifferenceObject and ReferenceObject along with elements
# $diff | ForEach-Object {
#     $difference = if ($_.SideIndicator -eq "=>") { $_.InputObject } else { $null }
#     $reference = if ($_.SideIndicator -eq "<=") { $_.InputObject } else { $null }

#     [PSCustomObject]@{
#         DifferenceObject = $difference
#         ReferenceObject = $reference
#         SideIndicator = $_.SideIndicator
#     }
# } | Format-Table -AutoSize

#
#
#  TEST 2
#
#

# $baseline = @{
#     ReferenceObject = Import-Csv .\baseline\Accounts_Baseline_Old.csv
#     Property        = "name"
#     PassThru        = $true
#   }

#   $current = Import-Csv ".\baseline\Accounts_Baseline_10-23-23.csv" 

#   $diff = ForEach ($ip in $targets){
#     $baseline.DifferenceObject = $current |
#       Where-Object {$_.IP -eq $ip} |
#         Sort-Object -Property name -Unique
#     Compare-Object @baseline |
#       Where-Object {$_.sideindicator -eq "=>"}
#   }

# #   $diff

#
#
#  TEST 3
#
#

$old = Import-Csv ".\baseline\Accounts_Baseline_Old.csv"
$current = Import-Csv ".\baseline\Accounts_Baseline_10-23-23.csv"

Compare-Object $old $current -Property ip,name,account_type,disabled,pw_req,sid,lockout,last_logon,pw_expires,local_groups,localpath |
Select-Object @(
  @{ n = "Left";   e = { if ($_.SideIndicator -in "==","<=") { $_.ip,$_.name,$_.account_type,$_.disabled,$_.pw_req,$_.sid,$_.lockout,$_.last_logon,$_.pw_expires,$_.local_groups,$_.localpath -join "," } } }
  @{ n = "Right";  e = { if ($_.SideIndicator -in "==","=>") { $_.ip,$_.name,$_.account_type,$_.disabled,$_.pw_req,$_.sid,$_.lockout,$_.last_logon,$_.pw_expires,$_.local_groups,$_.localpath -join "," } } }
) | export-csv .\Baseline\test.csv