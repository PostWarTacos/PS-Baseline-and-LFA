    # global variables
$so                 = New-PSSessionOption  -SkipCACheck -SkipCNCheck -SkipRevocationCheck # set session options (This is required for out of band connections)
$InitialHostsDir    = "$HOME\Documents" # used in Get-Filename function
$CSVTarget          = "$HOME\Documents\Baselines" # location where CSV baselines will be exported to

    $targets = @("192.168.75.130")
    $jobs = @()
    $FinalOutput = @()
    $creds = Get-Credential mal\matt

    <# issues getting this working with Start-Job
    $AccountTypeMap = @{
        256     = 'Temporary duplicate account (256)'
        512     = 'Normal account (512)'
        2048    = 'Interdomain trust account (2048)'
        4096    = 'Workstation trust account (4096)'
        8192    = 'Server trust account (8192)'
    }
    #>

    foreach ( $target in $targets ){
        $jobs += Start-Job { # enable multithreading operations
            param($target,$filename,[PSCredential]$creds,$so)
            $localFinalOutput = @()

            # Info needs to be pull from various places. Pull initial list of accounts with Win32, then use the SIDs found to dig deeper.
            # get local accounts
            $win32accts = Invoke-Command -CN $target -CR $creds -SessionOption $so {
                Get-CimInstance Win32_UserAccount } # Pull Name, SID, AccountType, Disabled, Lockout, PasswordRequired

            # get local profiles
            $acctprofs =  Invoke-Command -CN $target -CR $creds -SessionOption $so {
                Get-CimInstance -ClassName Win32_UserProfile | Where-Object LocalPath -NotLike "C:\Windows*"
            }

            # Start of pulling info about accounts
            foreach ( $win32acct in $win32accts ) {
                
                $lclusr = Invoke-Command -CN $target -CR $creds -SessionOption $so {
                    Get-LocalUser } | Where-Object { $_.SID -eq $win32acct.SID } # Pull PW Expires, LastLogon

                # profile localpath
                $profpath = $acctprofs | Where-Object { $_.SID -eq $win32acct.SID } | Select-Object -ExpandProperty LocalPath

                # local (NOT domain) group membership
                $membership = Invoke-Command -CN $target -CR $creds -SessionOption $so {
                    $result = get-localgroup | foreach-object {
                        $group = $_
                        if ( get-localgroupmember $group | Where-Object SID -EQ $win32acct.SID ){ $group.name }
                    }
                    return $result
                }
                
                # Create PS object and export
                $PSObj = [pscustomobject]@{ 
                    IP              = $target
                    Name            = $win32acct.name
                    #Account_Type    = $AccountTypeMap[[int]$win32acct.AccountType] # not working with Start-Job
                    Account_Type    = $win32acct.AccountType
                    Disabled        = $win32acct.Disabled
                    PW_Req          = $win32acct.PasswordRequired
                    SID             = $win32acct.SID
                    #Lockout         = $win32acct.Lockout # chose to exclude from results
                    Last_Logon      = $lclusr.LastLogon
                    PW_Expires      = $lclusr.PasswordExpires
                    Local_Groups    = (@($membership) -join ',')
                    LocalPath       = $profpath
                }

                $localFinalOutput += $PSObj
            }
            # End pulling info about accounts
            
            # Start pulling info about profiles not linked to accounts
            # This could be domain accounts (because get-ciminstance win32_useraccount and get-localuser do NOT pull domain accounts)
            # This could also include profiles of accounts that were deleted

            #$tmpimport = Import-Csv .\$filename.csv | Where-Object IP -eq $target
            $tmpimport = $localFinalOutput | Where-Object IP -eq $target

            foreach ( $prof in $acctprofs ) {
                if ( $tmpimport -match $prof.SID ) {
                    #do nothing
                }
                else{
                # local (NOT domain) group membership
                $membership = Invoke-Command -CN $target -CR $creds -SessionOption $so {
                    $result = get-localgroup | foreach-object {
                        $group = $_
                        if ( get-localgroupmember $group | Where-Object SID -EQ $prof.SID ){ $group.name }
                    }
                    return $result
                }

                    # Create PS object and export
                    $PSObj = [pscustomobject]@{ 
                        IP              = $target
                        Name            = '-'
                        Account_Type    = '-'
                        Disabled        = '-'
                        PW_Req          = '-'
                        SID             = $prof.SID
                        #Lockout         = '-'
                        Last_Logon      = '-'
                        PW_Expires      = '-'
                        Local_Groups    = (@($membership) -join ',')
                        LocalPath       = $prof.LocalPath
                    }
                    $localFinalOutput += $PSObj
                }
                #$localFinalOutput
            }
            $localFinalOutput

            # End pulling info about profiles not linked to accounts
        } -ArgumentList $target, $filename, $creds, $so
    }
    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

    # remove the jobs
    Remove-Job -Job $jobs

    # update the original variable with the modified output
    $FinalOutput += $results # | Select-Object -Unique

    # export the final output
    $FinalOutput | Export-Csv $CSVTarget\$filename.csv -Append