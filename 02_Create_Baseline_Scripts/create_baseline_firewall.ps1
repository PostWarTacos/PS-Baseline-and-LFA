# import targets list
$targets = Import-Csv .\AllHosts.csv |
  #Where-Object {$_.os -eq "Win10"} |
  Select-Object -ExpandProperty ip

# get date for file name
$filename = "Firewall_Baseline_" + (Get-Date -Format "MM-dd-yy")

# get credentials from the operator
$creds = Get-Credential
# set session options (This is required for out of band connections)
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

# Changed to psobject to allow for expansion of script to allow more artifacts to be extracted and linked to each object.
# Additionally, now extracting IP address vs the computername.

foreach ( $target in $targets ){
    $rules = invoke-command -CN $target -CR $creds -SessionOption $so {
        Get-NetFirewallRule | Where-Object {$_.enabled}
    }
    
    $portfilter = invoke-command -CN $target -CR $creds -SessionOption $so {
        Get-NetFirewallPortFilter
    }

    $addressfilter = invoke-command -CN $target -CR $creds -SessionOption $so {
        Get-NetFirewallAddressFilter
    }

    foreach ( $rule in $rules ){
        $ruleport    = $portfilter | Where-Object {$_.InstanceID -eq $rule.InstanceID}
        $ruleaddress = $addressfilter | Where-Object {$_.InstanceID -eq $rule.InstanceID}
        $OutputObj = [pscustomobject]@{ 
            IP              = $target
            Name            = $rule.DisplayName
            InstanceID      = $rule.InstanceID.ToString()
            Profile         = $rule.Profile
            Owner           = $rule.Owner
            Direction       = $rule.Direction.ToString()
            Action          = $rule.Action.ToString()
            LocalAddress    = $ruleaddress.LocalAddress -join ","
            RemoteAddress   = $ruleaddress.RemoteAddress -join ","
            Protocol        = $ruleport.Protocol.ToString()
            LocalPort       = $ruleport.LocalPort -join ","
            RemotePort      = $ruleport.RemotePort -join ","
        }
        $OutputObj | Export-Csv .\Baseline\$filename.csv -Append
    }
}