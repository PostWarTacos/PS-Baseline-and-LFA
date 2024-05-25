# import targets list
$targets = Import-Csv .\AllHosts.csv |
    #Where-Object {$_.os -eq "Win10"} |
    Select-Object -ExpandProperty ip

# relate account type code to term
$AccountType_map = @{
    256 = 'Temporary duplicate account (256)'
    512 = 'Normal account (512)'
   2048 = 'Interdomain trust account (2048)'
   4096 = 'Workstation trust account (4096)'
   8192 = 'Server trust account (8192)'
}

# get date for file name
$filename = "Accounts_Baseline_" + (Get-Date -Format "MM-dd-yy")

# get credentials from operator
$creds = get-credential
# set session options (This is required for out of band connections)
$so = New-PSSessionOption  -SkipCACheck -SkipCNCheck -SkipRevocationCheck

foreach ( $target in $targets ){
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
            if ( get-localgroupmember $group | Where-Object SID -EQ $using:win32acct.SID ){ $group.name }
        }
        return $result
    }
    
    # Create PS object and export
    $OutputObj = [pscustomobject]@{ 
        IP              = $target
        Name            = $win32acct.name
        Account_Type    = $AccountType_map[[int]$win32acct.AccountType]
        Disabled        = $win32acct.Disabled
        PW_Req          = $win32acct.PasswordRequired
        SID             = $win32acct.SID
        Lockout         = $win32acct.Lockout
        Last_Logon      = $lclusr.LastLogon
        PW_Expires      = $lclusr.PasswordExpires
        Local_Groups    = (@($membership) -join ',')
        LocalPath       = $profpath
    }

    $OutputObj | Export-Csv .\Baseline\$filename.csv -Append
  }
  # End pulling info about accounts
  
  # Start pulling info about profiles not linked to accounts
  # This could be domain accounts (because get-ciminstance win32_useraccount and get-localuser do NOT pull domain accounts)
  # This could also include profiles of accounts that were deleted

  $tmpimport = Import-Csv .\Baseline\$filename.csv | Where-Object IP -eq $target

  foreach ( $prof in $acctprofs ) {
      if ( $tmpimport -match $prof.SID ) {
          #do nothing
      }
      else{
      # local (NOT domain) group membership
      $membership = Invoke-Command -CN $target -CR $creds -SessionOption $so {
          $result = get-localgroup | foreach-object {
              $group = $_
              if ( get-localgroupmember $group | Where-Object SID -EQ $using:prof.SID ){ $group.name }
          }
          return $result
      }

          # Create PS object and export
          $OutputObj = [pscustomobject]@{ 
              IP              = $target
              Name            = '-'
              Account_Type    = '-'
              Disabled        = '-'
              PW_Req          = '-'
              SID             = $prof.SID
              Lockout         = '-'
              Last_Logon      = '-'
              PW_Expires      = '-'
              Local_Groups    = (@($membership) -join ',')
              LocalPath       = $prof.LocalPath
          }

          $OutputObj | Export-Csv .\Baseline\$filename.csv -Append
      }
    }
  }

# will replace with function to locate old baseline
$old = Import-Csv .\Baseline\Accounts_Baseline_Old.csv

$current = Import-Csv ".\Baseline\Accounts_Baseline_10-23-23.csv"

# Need to explicitly list each property for the compare cmdlet to compare every property
# Doesn't show difference object (current) in result, only the reference object (old) with side indicator
# Side indicator points towards the file where the object DOES exist. ex: left for old, right for new.
Compare-Object -ReferenceObject $old -DifferenceObject $current -Property ip,name,account_type,disabled,pw_req,sid,last_logon,pw_expires,local_groups,localpath