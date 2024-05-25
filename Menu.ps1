########################################################################################################################################################
#
#   Complete Windows Baseline Script
#   Intent: Complete various types of baselines and compare them as needed with text menu navigation
#   Author: Completely written by Matthew Wurtz
#   Unit: 223 COS / SAIC
#
########################################################################################################################################################

$unixEpochStart = Get-Date "1970-01-01 00:00:00"
$TranscriptFilename = [Math]::Round(( $( get-date ) - $unixEpochStart ).TotalSeconds )
Start-Transcript -Path ~\Documents\Transcript_$TranscriptFilename.txt

# global variables
$so                 = New-PSSessionOption  -SkipCACheck -SkipCNCheck -SkipRevocationCheck # set session options (This is required for out of band connections)
$InitialHostsDir    = "$HOME\Documents" # used in Get-Filename function; starting location for where the GUI will open to
$CSVTarget          = "$HOME\Documents" # location where CSV baselines will be exported to

#
# start functions
#
Function Get-FileName( $InitialDirectory ) { # open GUI to select file. Filepath is saved to variable below
    [System.Reflection.Assembly]::LoadWithPartialName( "System.windows.forms" ) | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.Filter = "All files ( *.* )| *.*"
    $OpenFileDialog.ShowDialog(  ) | Out-Null
    $OpenFileDialog.Filename
}

<# Function Update-ProgressBar { --- IN DEVELOPMENT ---
    param ( 
        [int]$CompletedCount,
        [int]$TotalCount
    )

    $PercentComplete = [math]::Round(( $CompletedCount / $TargetsCount ) * 100)
    $ProgressBarLength = 50
    $CompletedLength = [math]::Round(( $CompletedCount / $TargetsCount ) * $ProgressBarLength )
    $RemainingLength = $ProgressBarLength - $CompletedLength


    # write progress bar to screen
    Write-Host "`rProgress: [$( '#' * $CompletedLength )$( ' ' * $RemainingLength )] $PercentComplete%`n`n" -NoNewline
}#>

Function Compare-Baseline( $baseline1, $baseline2 ){
    Clear-Variable change*, n, addedProperties, deletedProperties, modifiedProperties -ErrorAction SilentlyContinue

    $changes = @()

    for ( $i = 1; $i -lt $baseline1.Count; $i++ ) {
        $baseline1Properties = $baseline1[$i] | Get-Member -MemberType Properties -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
        $baseline2Properties = $baseline2[$i] | Get-Member -MemberType Properties -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

        $addedProperties = Compare-Object $baseline1 $baseline2 | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject
        $deletedProperties = Compare-Object $baseline1 $baseline2 | Where-Object { $_.SideIndicator -eq '<=' } | Select-Object -ExpandProperty InputObject

        $modifiedProperties = @()
        foreach ( $property in $baseline1Properties ) {
            $value1 = $baseline1[$i].$property
            $value2 = $baseline2[$i].$property

            if ( $value1 -ne $value2 ) {
                if ( $baseline1[$i].IP -eq $baseline2[$i].IP ){
                    $modifiedProperties += "$property '$value1' -> '$value2'"
                }
            }
        }
        if (( $modifiedProperties | Measure-Object ).Count -gt 0 ) {
            $changes += @{
                Index = $n+1
                ModifiedProperties = $modifiedProperties
            }
            $n++
        }
    }

    foreach ( $change in $changes ) {
        Write-Host "`nIndex $(  $change.Index  ):"
        if (( $change.ModifiedProperties | Measure-Object ).Count -gt 0 ) {
            Write-Host "  Modified Properties:"
            foreach ( $modifiedProperty in $change.ModifiedProperties ) {
                Write-Host "    $modifiedProperty"
            }
        }
    }

    Write-Host "`n"
    if (( $addedProperties | Measure-Object ).Count -gt 0 ) {
        Write-Host "  Added Properties: $( $addedProperties -join ', ' )"
    }
    if (( $deletedProperties | Measure-Object ).Count -gt 0 ) {
        Write-Host "  Deleted Properties: $( $deletedProperties -join ', ' )"
    }  
}


Function New-AccountsBaseline( $targets,$filename,[PSCredential]$creds,$so ){
	$jobs = @()
    $FinalOutput = @()
    $CompletedJobsCount = 0
    
    $MaxConcurrentJobs = 3 # set the maximum number of concurrent jobs
    $MaxJobDuration = 240  # maximum duration in seconds for a job to run

    # using measure-object to account for older PS versions that are tempermental with .count array property
    $TargetsCount = ( $targets | Measure-Object ).Count
    $CompletedJobsCount = 0

    foreach ( $target in $targets ) {
        
        # throttle the number of concurrent jobs
        # using measure-object to account for older PS versions that are tempermental with .count array property
        while ( $(Get-Job | Measure-Object).Count -ge $MaxConcurrentJobs ) {
            # wait for an active job to complete before starting a new one
            $CompletedJob = Get-Job | Where-Object State -eq "Completed"
            if ( $CompletedJob ) {
                $FinalOutput += Receive-Job $CompletedJob
                Stop-job $CompletedJob
                Remove-Job $CompletedJob
                $CompletedJobsCount++
                #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
                break
            }
            else {
                # no job completed within the timeout period, break out of the loop
                break
            }
            # doesn't work as intended. wanted to loop timer for time spent throttling.
            # $seconds = 0
            # while($true){
            #     $minutes = [math]::Floor($seconds / 60)
            #     $remainingSeconds = $seconds % 60
            #     Write-Host -NoNewline ("`r{0}:{1:D2}" -f $minutes, $remainingSeconds)
            #     Start-Sleep -Seconds 1
            #     $seconds++
            # }
        }

        Write-Host -NoNewline "Job for target "; Write-Host -NoNewline $target -ForegroundColor Green
        Write-Host -NoNewline " has started at "; Write-Host $(Get-Date) -ForegroundColor Green

        $jobs += Start-Job { # enable multithreading operations
            param( $target,$filename,[PSCredential]$creds,$so,$StartTime )
            $LocalFinalOutput = @()

            # Info needs to be pull from various places. Pull initial list of accounts with Win32, then use the SIDs found to dig deeper
            # important to know the difference bettween accounts and profiles to understand why both of these are needed
            # in short, domain accounts don't create an account when they login to a computer, but they do create a profile
            # get local accounts
            $win32accts = Invoke-Command -CN $target -CR $creds -SessionOption $so {
                Get-CimInstance Win32_UserAccount } # Pull Name, SID, AccountType, Disabled, Lockout, PasswordRequired

            # get local profiles
            $acctprofs =  Invoke-Command -CN $target -CR $creds -SessionOption $so {
                Get-CimInstance -ClassName Win32_UserProfile | Where-Object LocalPath -NotLike "C:\Windows*"
            }

            # Start of pulling info about accounts
			foreach ($win32acct in $win32accts) {
				$lclusr = Invoke-Command -ComputerName $target -Credential $creds -ScriptBlock {
					param($sid)
					Get-LocalUser | Where-Object { $_.SID -eq $sid }
				} -ArgumentList $win32acct.SID

				# profile localpath
				$profpath = $acctprofs | Where-Object { $_.SID -eq $win32acct.SID } | Select-Object -ExpandProperty LocalPath

				# local ( NOT domain ) group membership
				$membership = Invoke-Command -ComputerName $target -Credential $creds -ScriptBlock {
					param($sid)
					Get-LocalGroup | ForEach-Object {
						if (Get-LocalGroupMember $_ | Where-Object { $_.SID -eq $sid }) {
							$_.Name
						}
					}
				} -ArgumentList $win32acct.SID

				# Create PS object and export
				$PSObj = [PSCustomObject]@{
					IP              = $target
					Name            = $win32acct.Name
					Account_Type    = $win32acct.AccountType
					Disabled        = $win32acct.Disabled
					PW_Req          = $win32acct.PasswordRequired
					SID             = $win32acct.SID
					Last_Logon      = $lclusr.LastLogon
					PW_Expires      = $lclusr.PasswordExpires
					Local_Groups    = $membership -join ','
					LocalPath       = $profpath
				}

				$LocalFinalOutput += $PSObj
			}

            # End pulling info about accounts
            
            # Start pulling info about profiles not linked to accounts
            # This could be domain accounts ( because get-ciminstance win32_useraccount and get-localuser do NOT pull domain accounts )
            # This could also include profiles of accounts that were deleted

            #$tmpimport = Import-Csv .\$filename.csv | Where-Object IP -eq $target
            $tmpimport = $LocalFinalOutput | Where-Object IP -eq $target

            foreach (  $prof in $acctprofs  ) {
                if (  $tmpimport -match $prof.SID  ) {
                    #do nothing
                }
                else{
                # local ( NOT domain ) group membership
                $membership = Invoke-Command -CN $target -CR $creds -SessionOption $so {
                    $result = get-localgroup | foreach-object {
                        $group = $_
                        if (  get-localgroupmember $group | Where-Object SID -EQ $prof.SID  ){ $group.name }
                    }
                    return $result
                }

                    # Create PS object and export
                    $PSObj = [pscustomobject]@{ 
                        IP              = $target
                        Name            = '-'
                        #Account_Type    = '-'
                        Disabled        = '-'
                        PW_Req          = '-'
                        SID             = $prof.SID
                        #Lockout         = '-'
                        Last_Logon      = '-'
                        PW_Expires      = '-'
                        Local_Groups    = ( @( $membership ) -join ',' )
                        LocalPath       = $prof.LocalPath
                    }
                    $LocalFinalOutput += $PSObj
                }
                #$LocalFinalOutput
            }
            $LocalFinalOutput

            # End pulling info about profiles not linked to accounts
        } -ArgumentList $target, $filename, $creds, $so, $StartTime
    }

    # wait for the runaway jobs to complete or kill them
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Wait-Job -Timeout $MaxJobDuration -ErrorAction SilentlyContinue
        if ( $job -and $job.State -eq 'Running' ) {
            # job has been running for too long, remove it
            Write-Host "Job $( $job.Id ) on $( $targets[$index] ) has been running for too long. Removing..."
            Stop-Job $job
            Remove-Job $job
            # progressbar
            $CompletedJobsCount++
            #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
        } 

    }

    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

    # update the original variable with the modified output
    $FinalOutput += $results

    # export the final output
    $FinalOutput | Select-Object IP,Name,Disabled,PW_Req,SID,Last_Logon,PW_Expires,Local_Groups,LocalPath | Export-Csv "$CSVTarget\$filename.csv" -Append
}

Function New-AutorunBaseline( $targets, $filename, [PSCredential]$creds, $so ) {
    $jobs = @()
    $FinalOutput = @()
    $CompletedJobsCount = 0
    
    $MaxConcurrentJobs = 3 # set the maximum number of concurrent jobs
    $MaxJobDuration = 240  # maximum duration in seconds for a job to run

    # using measure-object to account for older PS versions that are tempermental with .count array property
    $TargetsCount = ( $targets | Measure-Object ).Count
    $CompletedJobsCount = 0

    foreach ( $target in $targets ) {
        
        # throttle the number of concurrent jobs
        # using measure-object to account for older PS versions that are tempermental with .count array property
        while ( $(Get-Job | Measure-Object).Count -ge $MaxConcurrentJobs ) {
            # wait for an active job to complete before starting a new one
            $CompletedJob = Get-Job | Where-Object State -eq "Completed"
            if ( $CompletedJob ) {
                $FinalOutput += Receive-Job $CompletedJob
                Stop-job $CompletedJob
                Remove-Job $CompletedJob
                $CompletedJobsCount++
                #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
                break
            }
            else {
                # no job completed within the timeout period, break out of the loop
                break
            }
            # doesn't work as intended. wanted to loop timer for time spent throttling.
            # $seconds = 0
            # while($true){
            #     $minutes = [math]::Floor($seconds / 60)
            #     $remainingSeconds = $seconds % 60
            #     Write-Host -NoNewline ("`r{0}:{1:D2}" -f $minutes, $remainingSeconds)
            #     Start-Sleep -Seconds 1
            #     $seconds++
            # }
        }

        Write-Host -NoNewline "Job for target "; Write-Host -NoNewline $target -ForegroundColor Green
        Write-Host -NoNewline " has started at "; Write-Host $(Get-Date) -ForegroundColor Green

        $jobs += Start-Job { # enable multithreading operations
            param( $target,$filename,[PSCredential]$creds,$so )
            $LocalFinalOutput = @()

            $autoruns = Invoke-Command -CN $target -Credential $creds -SessionOption $so {
                Get-CimInstance -Class Win32_StartupCommand
            }
            foreach ( $entry in $autoruns ) {
                $PSObj = [pscustomobject]@{ 
                    IP        = $target
                    Name      = $entry.Name
                    Command   = $entry.Command
                    User      = $entry.User
                    UserSID   = $entry.UserSID
                    Location  = $entry.Location
                }
                $LocalFinalOutput += $PSObj
            }
            $LocalFinalOutput
        } -ArgumentList $target, $filename, $creds, $so
    }

    # wait for the runaway jobs to complete or kill them
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Wait-Job -Timeout $MaxJobDuration -ErrorAction SilentlyContinue
        if ( $job -and $job.State -eq 'Running' ) {
            # job has been running for too long, remove it
            Write-Host "Job $( $job.Id ) on $( $targets[$index] ) has been running for too long. Removing..."
            Stop-Job $job
            Remove-Job $job
            # progressbar
            $CompletedJobsCount++
            #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
        } 

    }

    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

    # update the original variable with the modified output
    $FinalOutput += $results

    # export the final output
    $FinalOutput | Select-Object IP,Name,Command,User,UserSID,Location | Export-Csv "$CSVTarget\$filename.csv" -Append
}

<# Files of Interest --- IN DEVELOPMENT ---
Function New-FilesBaseline( $targets,$filename,[PSCredential]$creds,$so ){
    $filePatterns = @( 
        "*.exe",
        "*.dll"
    )
    $folders = @( 
        #"C:\temp",
        "C:\WINDOWS",
        #"\System Volume Information",
        "C:\`$Recycle.Bin",
        #"C:\Program Files",
        #"C:\Program Files ( x86 )",
        "C:\Users\*\AppData"
    )
	$jobs = @()
    $FinalOutput = @()
    $CompletedJobsCount = 0
    
    $MaxConcurrentJobs = 3 # set the maximum number of concurrent jobs
    $MaxJobDuration = 240  # maximum duration in seconds for a job to run

    # using measure-object to account for older PS versions that are tempermental with .count array property
    $TargetsCount = ( $targets | Measure-Object ).Count
    $CompletedJobsCount = 0

    foreach ( $target in $targets ) {
        
        # throttle the number of concurrent jobs
        # using measure-object to account for older PS versions that are tempermental with .count array property
        while ( $(Get-Job | Measure-Object).Count -ge $MaxConcurrentJobs ) {
            # wait for an active job to complete before starting a new one
            $CompletedJob = Get-Job | Where-Object State -eq "Completed"
            if ( $CompletedJob ) {
                $FinalOutput += Receive-Job $CompletedJob
                Stop-job $CompletedJob
                Remove-Job $CompletedJob
                $CompletedJobsCount++
                #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
                break
            }
            else {
                # no job completed within the timeout period, break out of the loop
                break
            }
            # doesn't work as intended. wanted to loop timer for time spent throttling.
            # $seconds = 0
            # while($true){
            #     $minutes = [math]::Floor($seconds / 60)
            #     $remainingSeconds = $seconds % 60
            #     Write-Host -NoNewline ("`r{0}:{1:D2}" -f $minutes, $remainingSeconds)
            #     Start-Sleep -Seconds 1
            #     $seconds++
            # }
        }

        Write-Host -NoNewline "Job for target "; Write-Host -NoNewline $target -ForegroundColor Green
        Write-Host -NoNewline " has started at "; Write-Host $(Get-Date) -ForegroundColor Green

        $jobs += Start-Job { # enable multithreading operations
            param( $target,$filename,[PSCredential]$creds,$so,$StartTime )
            $LocalFinalOutput = @()
          
            $files = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
                param ( $filePatterns, $folders )
                # Get-ChildItem -Path $folders -Recurse -File -include $filePatterns -Force -ErrorAction Continue | get-filehash
                Get-ChildItem C:\Windows\ -Recurse -Include "*.dll", "*.exe" -ErrorAction SilentlyContinue | 
                ForEach-Object {
                    try {
                        $hash = Get-FileHash -Path $_.FullName -Algorithm MD5 -ErrorAction Stop
                        [PSCustomObject]@{
                            LastWriteTime = $_.LastWriteTime
                            Path = $_.FullName
                            Hash = $hash.Hash
                        }
                    } catch {
                        Write-Warning "Failed to process file: $($_.FullName)"
                    }
                } | Select-Object LastWriteTime, Path, Hash
            } -ArgumentList $using:filePatterns, $using:folders
            foreach ( $file in $files ){
                $PSObj = [pscustomobject]@{ 
                    IP              = $target
                    Hash            = $file.hash
                    File            = $file.path
                    LastWriteTime   = $file.LastWriteTime
                    # Name            = $file.Name
                    # ResolvedTarget  = $file.Fullname
                    # Mode            = $file.Mode
                    # Attributes      = $file.Attributes
                    # Extension       = $file.Extension
                    # CreationTime    = $file.CreationTime
                    # LastAccessTime  = $file.LastAccessTime
                    # LastWriteTime   = $file.LastWriteTime
                }
                $LocalFinalOutput += $PSObj
            }
            $LocalFinalOutput
        } -ArgumentList $target, $filename, $creds, $so, $StartTime 
    }

    # wait for the runaway jobs to complete or kill them
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Wait-Job -Timeout $MaxJobDuration -ErrorAction SilentlyContinue
        if ( $job -and $job.State -eq 'Running' ) {
            # job has been running for too long, remove it
            Write-Host "Job $( $job.Id ) on $( $targets[$index] ) has been running for too long. Removing..."
            Stop-Job $job
            Remove-Job $job
            # progressbar
            $CompletedJobsCount++
            #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
        } 

    }

    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

    # update the original variable with the modified output
    $FinalOutput += $results

    # export the final output
    $FinalOutput | Select-Object -ExcludeProperty PSSourceJobInstanceId | Export-Csv "$CSVTarget\$filename.csv" -Append
}
#>

Function New-FirewallBaseline( $targets,$filename,[PSCredential]$creds,$so ){
	$jobs = @()
    $FinalOutput = @()
    $CompletedJobsCount = 0
    
    $MaxConcurrentJobs = 3 # set the maximum number of concurrent jobs
    $MaxJobDuration = 240  # maximum duration in seconds for a job to run

    # using measure-object to account for older PS versions that are tempermental with .count array property
    $TargetsCount = ( $targets | Measure-Object ).Count
    $CompletedJobsCount = 0

    foreach ( $target in $targets ) {
        
        # throttle the number of concurrent jobs
        # using measure-object to account for older PS versions that are tempermental with .count array property
        while ( $(Get-Job | Measure-Object).Count -ge $MaxConcurrentJobs ) {
            # wait for an active job to complete before starting a new one
            $CompletedJob = Get-Job | Where-Object State -eq "Completed"
            if ( $CompletedJob ) {
                $FinalOutput += Receive-Job $CompletedJob
                Stop-job $CompletedJob
                Remove-Job $CompletedJob
                $CompletedJobsCount++
                #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
                break
            }
            else {
                # no job completed within the timeout period, break out of the loop
                break
            }
            # doesn't work as intended. wanted to loop timer for time spent throttling.
            # $seconds = 0
            # while($true){
            #     $minutes = [math]::Floor($seconds / 60)
            #     $remainingSeconds = $seconds % 60
            #     Write-Host -NoNewline ("`r{0}:{1:D2}" -f $minutes, $remainingSeconds)
            #     Start-Sleep -Seconds 1
            #     $seconds++
            # }
        }

        Write-Host -NoNewline "Job for target "; Write-Host -NoNewline $target -ForegroundColor Green
        Write-Host -NoNewline " has started at "; Write-Host $(Get-Date) -ForegroundColor Green
  
        $jobs += Start-Job { # enable multithreading operations
            param( $target,$filename,[PSCredential]$creds,$so,$StartTime )
            $LocalFinalOutput = @()
          
            $rules = invoke-command -CN $using:target -CR $using:creds -SessionOption $using:so {
                Get-NetFirewallRule | Where-Object {$_.enabled}
            }
            
            $portfilter = invoke-command -CN $using:target -CR $using:creds -SessionOption $using:so {
                Get-NetFirewallPortFilter
            }

            $addressfilter = invoke-command -CN $using:target -CR $using:creds -SessionOption $using:so {
                Get-NetFirewallAddressFilter
            }

            foreach ( $rule in $rules ){
                $ruleport    = $portfilter | Where-Object {$_.InstanceID -eq $rule.InstanceID}
                $ruleaddress = $addressfilter | Where-Object {$_.InstanceID -eq $rule.InstanceID}
                $PSObj = [pscustomobject]@{ 
                    IP              = $target
                    Name            = $rule.DisplayName
                    InstanceID      = $rule.InstanceID.ToString( )
                    Profile         = $rule.Profile
                    Owner           = $rule.Owner
                    Direction       = $rule.Direction.ToString( )
                    Action          = $rule.Action.ToString( )
                    LocalAddress    = $ruleaddress.LocalAddress -join ","
                    RemoteAddress   = $ruleaddress.RemoteAddress -join ","
                    Protocol        = $ruleport.Protocol.ToString( )
                    LocalPort       = $ruleport.LocalPort -join ","
                    RemotePort      = $ruleport.RemotePort -join ","
                }
                $LocalFinalOutput += $PSObj
            }
            $LocalFinalOutput
        } -ArgumentList $target, $filename, $creds, $so, $StartTime
    }

    # wait for the runaway jobs to complete or kill them
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Wait-Job -Timeout $MaxJobDuration -ErrorAction SilentlyContinue
        if ( $job -and $job.State -eq 'Running' ) {
            # job has been running for too long, remove it
            Write-Host "Job $( $job.Id ) on $( $targets[$index] ) has been running for too long. Removing..."
            Stop-Job $job
            Remove-Job $job
            # progressbar
            $CompletedJobsCount++
            #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
        } 

    }

    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

    # update the original variable with the modified output
    $FinalOutput += $results

    # export the final output
    $FinalOutput | Select-Object IP,Name,InstanceID,Profile,Owner,Direction,Action,LocalAddress,RemoteAddress,Protocol,LocalPort,RemotePort | Export-Csv "$CSVTarget\$filename.csv" -Append
}

Function New-ProcessesBaseline( $targets,$filename,[PSCredential]$creds,$so ){
	$jobs = @()
    $FinalOutput = @()
    $CompletedJobsCount = 0
    
    $MaxConcurrentJobs = 3 # set the maximum number of concurrent jobs
    $MaxJobDuration = 240  # maximum duration in seconds for a job to run

    # using measure-object to account for older PS versions that are tempermental with .count array property
    $TargetsCount = ( $targets | Measure-Object ).Count
    $CompletedJobsCount = 0

    foreach ( $target in $targets ) {
        
        # throttle the number of concurrent jobs
        # using measure-object to account for older PS versions that are tempermental with .count array property
        while ( $(Get-Job | Measure-Object).Count -ge $MaxConcurrentJobs ) {
            # wait for an active job to complete before starting a new one
            $CompletedJob = Get-Job | Where-Object State -eq "Completed"
            if ( $CompletedJob ) {
                $FinalOutput += Receive-Job $CompletedJob
                Stop-job $CompletedJob
                Remove-Job $CompletedJob
                $CompletedJobsCount++
                #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
                break
            }
            else {
                # no job completed within the timeout period, break out of the loop
                break
            }
            # doesn't work as intended. wanted to loop timer for time spent throttling.
            # $seconds = 0
            # while($true){
            #     $minutes = [math]::Floor($seconds / 60)
            #     $remainingSeconds = $seconds % 60
            #     Write-Host -NoNewline ("`r{0}:{1:D2}" -f $minutes, $remainingSeconds)
            #     Start-Sleep -Seconds 1
            #     $seconds++
            # }
        }

        Write-Host -NoNewline "Job for target "; Write-Host -NoNewline $target -ForegroundColor Green
        Write-Host -NoNewline " has started at "; Write-Host $(Get-Date) -ForegroundColor Green

        $jobs += Start-Job { # enable multithreading operations
            param( $target,$filename,[PSCredential]$creds,$so,$StartTime )
            $LocalFinalOutput = @()
            
            $processes = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
                Get-CimInstance Win32_Process 
            }
            foreach ( $process in $processes ) {
                $PSObj = [pscustomobject]@{
                    IP              = $target
                    Name            = $process.ProcessName
                    ID              = $process.ProcessId
                    CommandLine     = $process.CommandLine
                    ExecutablePath  = $process.ExecutablePath
                }
                $LocalFinalOutput += $PSObj
            }
            $LocalFinalOutput
        } -ArgumentList $target, $filename, $creds, $so, $StartTime
    }

    # wait for the runaway jobs to complete or kill them
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Wait-Job -Timeout $MaxJobDuration -ErrorAction SilentlyContinue
        if ( $job -and $job.State -eq 'Running' ) {
            # job has been running for too long, remove it
            Write-Host "Job $( $job.Id ) on $( $targets[$index] ) has been running for too long. Removing..."
            Stop-Job $job
            Remove-Job $job
            # progressbar
            $CompletedJobsCount++
            #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
        } 

    }

    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

    # update the original variable with the modified output
    $FinalOutput += $results

    # export the final output
    $FinalOutput | Select-Object IP,Name,ID,Commandline,ExecutablePath | export-csv $CSVTarget\$filename.csv -Append
}

Function New-ScheduledTasksBaseline( $targets,$filename,[PSCredential]$creds,$so ){
	$jobs = @()
    $FinalOutput = @()
    $CompletedJobsCount = 0
    
    $MaxConcurrentJobs = 3 # set the maximum number of concurrent jobs
    $MaxJobDuration = 240  # maximum duration in seconds for a job to run

    # using measure-object to account for older PS versions that are tempermental with .count array property
    $TargetsCount = ( $targets | Measure-Object ).Count
    $CompletedJobsCount = 0

    foreach ( $target in $targets ) {
        
        # throttle the number of concurrent jobs
        # using measure-object to account for older PS versions that are tempermental with .count array property
        while ( $(Get-Job | Measure-Object).Count -ge $MaxConcurrentJobs ) {
            # wait for an active job to complete before starting a new one
            $CompletedJob = Get-Job | Where-Object State -eq "Completed"
            if ( $CompletedJob ) {
                $FinalOutput += Receive-Job $CompletedJob
                Stop-job $CompletedJob
                Remove-Job $CompletedJob
                $CompletedJobsCount++
                #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
                break
            }
            else {
                # no job completed within the timeout period, break out of the loop
                break
            }
            # doesn't work as intended. wanted to loop timer for time spent throttling.
            # $seconds = 0
            # while($true){
            #     $minutes = [math]::Floor($seconds / 60)
            #     $remainingSeconds = $seconds % 60
            #     Write-Host -NoNewline ("`r{0}:{1:D2}" -f $minutes, $remainingSeconds)
            #     Start-Sleep -Seconds 1
            #     $seconds++
            # }
        }

        Write-Host -NoNewline "Job for target "; Write-Host -NoNewline $target -ForegroundColor Green
        Write-Host -NoNewline " has started at "; Write-Host $(Get-Date) -ForegroundColor Green
     
        $jobs += Start-Job { # enable multithreading operations
            param( $target,$filename,[PSCredential]$creds,$so,$StartTime )
            $LocalFinalOutput = @()
            
            $scheduledTasks = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
                Get-CimInstance -ClassName MSFT_ScheduledTask -Namespace "Root\Microsoft\Windows\TaskScheduler"
            }

            foreach ( $task in $scheduledTasks ) {
                $PSObj = [pscustomobject]@{
                    IP          = $target
                    TaskName    = $task.TaskName
                    Path        = $task.TaskPath
                    Description = $task.Description
                    Status      = $task.State
                    NextRunTime = $task.NextRunTime
                }
                $LocalFinalOutput += $PSObj
            }
            $LocalFinalOutput
        } -ArgumentList $target, $filename, $creds, $so, $StartTime
    }

    # wait for the runaway jobs to complete or kill them
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Wait-Job -Timeout $MaxJobDuration -ErrorAction SilentlyContinue
        if ( $job -and $job.State -eq 'Running' ) {
            # job has been running for too long, remove it
            Write-Host "Job $( $job.Id ) on $( $targets[$index] ) has been running for too long. Removing..."
            Stop-Job $job
            Remove-Job $job
            # progressbar
            $CompletedJobsCount++
            #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
        } 

    }

    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

    # update the original variable with the modified output
    $FinalOutput += $results

    # export the final output
    $FinalOutput | Select-Object IP,TaskName,Path,Description,Status,NextRunTime | Export-Csv "$CSVTarget\$filename.csv" -Append
}

Function New-ServicesBaseline( $targets,$filename,[PSCredential]$creds,$so ){
	$jobs = @()
    $FinalOutput = @()
    $CompletedJobsCount = 0
    
    $MaxConcurrentJobs = 3 # set the maximum number of concurrent jobs
    $MaxJobDuration = 240  # maximum duration in seconds for a job to run

    # using measure-object to account for older PS versions that are tempermental with .count array property
    $TargetsCount = ( $targets | Measure-Object ).Count
    $CompletedJobsCount = 0

    foreach ( $target in $targets ) {
        
        # throttle the number of concurrent jobs
        # using measure-object to account for older PS versions that are tempermental with .count array property
        while ( $(Get-Job | Measure-Object).Count -ge $MaxConcurrentJobs ) {
            # wait for an active job to complete before starting a new one
            $CompletedJob = Get-Job | Where-Object State -eq "Completed"
            if ( $CompletedJob ) {
                $FinalOutput += Receive-Job $CompletedJob
                Stop-job $CompletedJob
                Remove-Job $CompletedJob
                $CompletedJobsCount++
                #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
                break
            }
            else {
                # no job completed within the timeout period, break out of the loop
                break
            }
            # doesn't work as intended. wanted to loop timer for time spent throttling.
            # $seconds = 0
            # while($true){
            #     $minutes = [math]::Floor($seconds / 60)
            #     $remainingSeconds = $seconds % 60
            #     Write-Host -NoNewline ("`r{0}:{1:D2}" -f $minutes, $remainingSeconds)
            #     Start-Sleep -Seconds 1
            #     $seconds++
            # }
        }

        Write-Host -NoNewline "Job for target "; Write-Host -NoNewline $target -ForegroundColor Green
        Write-Host -NoNewline " has started at "; Write-Host $(Get-Date) -ForegroundColor Green
        
        $jobs += Start-Job { # enable multithreading operations
            param( $target,$filename,[PSCredential]$creds,$so,$StartTime )
            $LocalFinalOutput = @()
            
            $services = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
                Get-CimInstance -Class Win32_Service
            }
            foreach ( $service in $services ) {
                $PSObj = [PSCustomObject]@{
                    IP          = $target
                    ServiceName = $service.Name
                    DisplayName = $service.DisplayName
                    Path        = $service.pathname
                    State       = $service.state
                    Status      = $service.Status
                    StartType   = $service.StartMode
                }
                $LocalFinalOutput += $PSObj
            }
            $LocalFinalOutput
        } -ArgumentList $target, $filename, $creds, $so, $StartTime
    }

    # wait for the runaway jobs to complete or kill them
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Wait-Job -Timeout $MaxJobDuration -ErrorAction SilentlyContinue
        if ( $job -and $job.State -eq 'Running' ) {
            # job has been running for too long, remove it
            Write-Host "Job $( $job.Id ) on $( $targets[$index] ) has been running for too long. Removing..."
            Stop-Job $job
            Remove-Job $job
            # progressbar
            $CompletedJobsCount++
            #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
        } 

    }

    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

    # update the original variable with the modified output
    $FinalOutput += $results

    # export the final output
    $FinalOutput | Select-Object IP,ServiceName,DisplayName,Path,State,Status,StartType | Export-Csv "$CSVTarget\$filename.csv" -Append
}

Function New-SoftwareBaseline( $targets,$filename,[PSCredential]$creds,$so ){
	$jobs = @()
    $FinalOutput = @()
    $CompletedJobsCount = 0
    
    $MaxConcurrentJobs = 3 # set the maximum number of concurrent jobs
    $MaxJobDuration = 240  # maximum duration in seconds for a job to run

    # using measure-object to account for older PS versions that are tempermental with .count array property
    $TargetsCount = ( $targets | Measure-Object ).Count
    $CompletedJobsCount = 0

    foreach ( $target in $targets ) {
        
        # throttle the number of concurrent jobs
        # using measure-object to account for older PS versions that are tempermental with .count array property
        while ( $(Get-Job | Measure-Object).Count -ge $MaxConcurrentJobs ) {
            # wait for an active job to complete before starting a new one
            $CompletedJob = Get-Job | Where-Object State -eq "Completed"
            if ( $CompletedJob ) {
                $FinalOutput += Receive-Job $CompletedJob
                Stop-job $CompletedJob
                Remove-Job $CompletedJob
                $CompletedJobsCount++
                #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
                break
            }
            else {
                # no job completed within the timeout period, break out of the loop
                break
            }
            # doesn't work as intended. wanted to loop timer for time spent throttling.
            # $seconds = 0
            # while($true){
            #     $minutes = [math]::Floor($seconds / 60)
            #     $remainingSeconds = $seconds % 60
            #     Write-Host -NoNewline ("`r{0}:{1:D2}" -f $minutes, $remainingSeconds)
            #     Start-Sleep -Seconds 1
            #     $seconds++
            # }
        }

        Write-Host -NoNewline "Job for target "; Write-Host -NoNewline $target -ForegroundColor Green
        Write-Host -NoNewline " has started at "; Write-Host $(Get-Date) -ForegroundColor Green
        
        $jobs += Start-Job { # enable multithreading operations
            param( $target,$filename,[PSCredential]$creds,$so,$StartTime )
            $LocalFinalOutput = @()

            $SoftwareList = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
                $result = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
                $result += Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
                $result += Get-ItemProperty REGISTRY::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*
                return $result
            }

            foreach ( $software in $SoftwareList ) { 
                <#$LogEntry = Get-WinEvent -LogName "Application" | # get installedby acct/SID --- IN DEVELOPMENT ---
					Where-Object { $_.id -eq 1033 -and $_.message -like "*$software.name*" -or $_.message -like "*$software.pschildname*" }
                if( $LogEntry ){
                    if( $LogEntry.UserID ){ $InstalledBySID = $LogEntry.UserID.value }
                    else { $InstalledBySID = "Unknown" }
                }
                else { $InstalledBySID = "Unknown" }

                # $InstalledBySID = Get-SoftwareInstallUser $software.Name
                if (  $InstalledBySID -ne "Unknown"  ){
                    $InstalledByAcct = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
                        ( Get-CimInstance -ClassName Win32_Useraccount | Where-Object { $_.SID -eq $InstalledBySID } ).name}
                    $InstalledByProf = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
                        ( Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -eq $InstalledBySID } ).LocalPath}
                } #>
                $PSObj = [PSCustomObject]@{
                    IP                  = $target
                    PSParentPath        = $software.PSPath
                    PSChildName         = $software.PSChildName
                    DisplayName         = if (  $software.DisplayName  ) { $software.DisplayName } else { '-' }
                    DisplayVersion      = if (  $software.DisplayVersion  ) { $software.DisplayVersion } else { '-' }
                    InstallDate         = if (  $software.InstallDate  ) { $software.InstallDate } else { '-' }
                    InstallLocation     = if (  $software.InstallLocation  ) { $software.InstallLocation } else { '-' }
                    Publisher           = if (  $software.Publisher  ) { $software.Publisher } else { '-' }
                    UninstallString     = if (  $software.UninstallString  ) { $software.UninstallString } else { '-' }
                    InstalledToProfile  = if (  $software.UninstallString -like "*C:\users\*"  ) {(  $software.UninstallString -split '\\'  )[2] } else { '-' }
                    # in testing env, these three properties were usually blank
                    # the SID may not be recorded on install as often as it should be
                    #InstalledBySID      = $InstalledBySID
                    #InstalledByAcct     = $InstalledByAcct
                    #InstalledByProf     = $InstalledByProf
                }
                $LocalFinalOutput += $PSObj
            }
            $LocalFinalOutput
        } -ArgumentList $target, $filename, $creds, $so, $StartTime
    }

    # wait for the runaway jobs to complete or kill them
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Wait-Job -Timeout $MaxJobDuration -ErrorAction SilentlyContinue
        if ( $job -and $job.State -eq 'Running' ) {
            # job has been running for too long, remove it
            Write-Host "Job $( $job.Id ) on $( $targets[$index] ) has been running for too long. Removing..."
            Stop-Job $job
            Remove-Job $job
            # progressbar
            $CompletedJobsCount++
            #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
        } 

    }

    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

    # update the original variable with the modified output
    $FinalOutput += $results

    # export the final output
    $FinalOutput | Select-Object IP,PSParentPath,PSChildName,DisplayName,DisplayVersion,InstallDate,InstallLocation,Publisher,UninstallString,InstalledToProfile | Export-Csv "$CSVTarget\$filename.csv" -Append
}

<# LFA-Autorun --- IN DEVELOPMENT ---
Function LFA-Autorun( $targets,$filename,[PSCredential]$creds,$so ){
    $jobs = @()
    $FinalOutput = @()
    
    $MaxConcurrentJobs  = 5 # set the maximum number of concurrent jobs
    $MaxJobDuration     = 180  # maximum duration in seconds for a job to run

    foreach ( $target in $targets ) {
        # throttle the number of concurrent jobs
        while ( $jobs.Count -ge $MaxConcurrentJobs ) {
            # wait for an active job to complete before starting a new one
            $CompletedJob = Wait-Job -Any -Timeout 1
            if ( $CompletedJob ) {
                $FinalOutput += Receive-Job $CompletedJob
                Remove-Job $CompletedJob
            }
        }
            
        Write-Host -NoNewline "Job for target "; Write-Host -NoNewline $target -ForegroundColor Green
        Write-Host -NoNewline " has started at "; Write-Host $(Get-Date) -ForegroundColor Green
    
        $jobs += Start-Job { # enable multithreading operations
            param( $target,$filename,[PSCredential]$creds )
            $LocalFinalOutput = @()

            $LFA = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
                Get-CimInstance -Class Win32_StartupCommand
            }

            $LFA | Sort-Object -Property pscomputername, Name -Unique |
                Group-Object Name |
                    Where-Object {$_.count -le 2} |
                        Select-Object -ExpandProperty Group

            foreach ( $entry in $LFA ){
                $PSObj = [pscustomobject]@{ 
                    IP        = $target
                    Name      = $entry.Name
                    Command   = $entry.Command
                    User      = $entry.User
                    UserSID   = $entry.UserSID
                    Location  = $entry.Location
                }
                $LocalFinalOutput += $PSObj
            }
            $LocalFinalOutput
        } -ArgumentList $target, $filename, $creds, $so, $StartTime 
    }

    # wait for the runaway jobs to complete or kill them
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Wait-Job -Timeout $MaxJobDuration -ErrorAction SilentlyContinue
        if ( $job -and $job.State -eq 'Running' ) {
            # job has been running for too long, remove it
            Write-Host "Job $( $job.Id ) on $( $targets[$index] ) has been running for too long. Removing..."
            Stop-Job $job
            Remove-Job $job
            # progressbar
            $CompletedJobsCount++
            #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
        } 

    }

    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

   # update the original variable with the modified output
    $FinalOutput += $results

    # export the final output
    $FinalOutput | Select-Object -ExcludeProperty PSSourceJobInstanceId | Export-Csv $CSVTarget\$filename.csv -Append

    Write-Progress -Activity "BASELINING..." -Status "Finished" -PercentComplete 100
}
#>

<# LFA-Processes --- IN DEVELOPMENT ---
Function LFA-Autorun( $targets,$filename,[PSCredential]$creds,$so ){
    $jobs = @()
    $FinalOutput = @()
    
    $MaxConcurrentJobs  = 5 # set the maximum number of concurrent jobs
    $MaxJobDuration     = 180  # maximum duration in seconds for a job to run

    foreach ( $target in $targets ) {
        # throttle the number of concurrent jobs
        while ( $jobs.Count -ge $MaxConcurrentJobs ) {
            # wait for an active job to complete before starting a new one
            $CompletedJob = Wait-Job -Any -Timeout 1
            if ( $CompletedJob ) {
                $FinalOutput += Receive-Job $CompletedJob
                Remove-Job $CompletedJob
            }
        }
            
        Write-Host -NoNewline "Job for target "; Write-Host -NoNewline $target -ForegroundColor Green
        Write-Host -NoNewline " has started at "; Write-Host $(Get-Date) -ForegroundColor Green
    
        $jobs += Start-Job { # enable multithreading operations
            param( $target,$filename,[PSCredential]$creds )
            $LocalFinalOutput = @()

            $LFA = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
                Get-CimInstance Win32_Process
            }

            $LFA | Sort-Object -Property pscomputername, ProcessName -Unique |
                Group-Object ProcessName |
                    Where-Object {$_.count -le 2} |
                        Select-Object -ExpandProperty Group

            foreach ( $entry in $LFA ){
                $PSObj = [pscustomobject]@{ 
                    IP              = $target
                    Name            = $process.ProcessName
                    ID              = $process.Id
                    CPUUsage        = $process.CPU
                    MemoryUsage     = $process.WorkingSet
                    StartTime       = $process.StartTime
                    CommandLine     = $process.CommandLine
                    ExecutablePath  = $process.ExecutablePath
                }
                $LocalFinalOutput += $PSObj
            }
            $LocalFinalOutput
        } -ArgumentList $target, $filename, $creds, $so, $StartTime 
    }

    # wait for the runaway jobs to complete or kill them
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Wait-Job -Timeout $MaxJobDuration -ErrorAction SilentlyContinue
        if ( $job -and $job.State -eq 'Running' ) {
            # job has been running for too long, remove it
            Write-Host "Job $( $job.Id ) on $( $targets[$index] ) has been running for too long. Removing..."
            Stop-Job $job
            Remove-Job $job
            # progressbar
            $CompletedJobsCount++
            #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
        } 

    }

    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

   # update the original variable with the modified output
    $FinalOutput += $results

    # export the final output
    $FinalOutput | Select-Object -ExcludeProperty PSSourceJobInstanceId | Export-Csv $CSVTarget\$filename.csv -Append

    Write-Progress -Activity "BASELINING..." -Status "Finished" -PercentComplete 100
}
#>

<# LFA-ScheduledTasks --- IN DEVELOPMENT ---
Function LFA-Autorun( $targets,$filename,[PSCredential]$creds,$so ){
    $jobs = @()
    $FinalOutput = @()
    
    $MaxConcurrentJobs  = 5 # set the maximum number of concurrent jobs
    $MaxJobDuration     = 180  # maximum duration in seconds for a job to run

    foreach ( $target in $targets ) {
        # throttle the number of concurrent jobs
        while ( $jobs.Count -ge $MaxConcurrentJobs ) {
            # wait for an active job to complete before starting a new one
            $CompletedJob = Wait-Job -Any -Timeout 1
            if ( $CompletedJob ) {
                $FinalOutput += Receive-Job $CompletedJob
                Remove-Job $CompletedJob
            }
        }
            
        Write-Host -NoNewline "Job for target "; Write-Host -NoNewline $target -ForegroundColor Green
        Write-Host -NoNewline " has started at "; Write-Host $(Get-Date) -ForegroundColor Green
    
        $jobs += Start-Job { # enable multithreading operations
            param( $target,$filename,[PSCredential]$creds )
            $LocalFinalOutput = @()

            $LFA = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
                Get-CimInstance -ClassName MSFT_ScheduledTask -Namespace "Root\Microsoft\Windows\TaskScheduler"
            }

            $LFA | Sort-Object -Property pscomputername, TaskName -Unique |
                Group-Object TaskName |
                    Where-Object {$_.count -le 2} |
                        Select-Object -ExpandProperty Group

            foreach ( $entry in $LFA ){
                $PSObj = [pscustomobject]@{ 
                    IP          = $target
                    TaskName    = $task.TaskName
                    Path        = $task.TaskPath
                    Description = $task.Description
                    Status      = $task.State
                    NextRunTime = $task.NextRunTime
                }
                $LocalFinalOutput += $PSObj
            }
            $LocalFinalOutput
        } -ArgumentList $target, $filename, $creds, $so, $StartTime 
    }

    # wait for the runaway jobs to complete or kill them
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Wait-Job -Timeout $MaxJobDuration -ErrorAction SilentlyContinue
        if ( $job -and $job.State -eq 'Running' ) {
            # job has been running for too long, remove it
            Write-Host "Job $( $job.Id ) on $( $targets[$index] ) has been running for too long. Removing..."
            Stop-Job $job
            Remove-Job $job
            # progressbar
            $CompletedJobsCount++
            #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
        } 

    }

    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

   # update the original variable with the modified output
    $FinalOutput += $results

    # export the final output
    $FinalOutput | Select-Object -ExcludeProperty PSSourceJobInstanceId | Export-Csv $CSVTarget\$filename.csv -Append

    Write-Progress -Activity "BASELINING..." -Status "Finished" -PercentComplete 100
}
#>

<# LFA-Services --- IN DEVELOPMENT ---
Function LFA-Autorun( $targets,$filename,[PSCredential]$creds,$so ){
    $jobs = @()
    $FinalOutput = @()
    
    $MaxConcurrentJobs  = 5 # set the maximum number of concurrent jobs
    $MaxJobDuration     = 180  # maximum duration in seconds for a job to run

    foreach ( $target in $targets ) {
        # throttle the number of concurrent jobs
        while ( $jobs.Count -ge $MaxConcurrentJobs ) {
            # wait for an active job to complete before starting a new one
            $CompletedJob = Wait-Job -Any -Timeout 1
            if ( $CompletedJob ) {
                $FinalOutput += Receive-Job $CompletedJob
                Remove-Job $CompletedJob
            }
        }
            
        Write-Host -NoNewline "Job for target "; Write-Host -NoNewline $target -ForegroundColor Green
        Write-Host -NoNewline " has started at "; Write-Host $(Get-Date) -ForegroundColor Green
    
        $jobs += Start-Job { # enable multithreading operations
            param( $target,$filename,[PSCredential]$creds )
            $LocalFinalOutput = @()

            $LFA = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
                Get-CimInstance -Class Win32_Service
            }

            $LFA | Sort-Object -Property pscomputername, Name -Unique |
                Group-Object Name |
                    Where-Object {$_.count -le 2} |
                        Select-Object -ExpandProperty Group

            foreach ( $entry in $LFA ){
                $PSObj = [pscustomobject]@{ 
                    IP          = $target
                    ServiceName = $service.Name
                    DisplayName = $service.DisplayName
                    Path        = $service.pathname
                    State       = $service.state
                    Status      = $service.Status
                    StartType   = $service.StartType
                }
                $LocalFinalOutput += $PSObj
            }
            $LocalFinalOutput
        } -ArgumentList $target, $filename, $creds, $so, $StartTime 
    }

    # wait for the runaway jobs to complete or kill them
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Wait-Job -Timeout $MaxJobDuration -ErrorAction SilentlyContinue
        if ( $job -and $job.State -eq 'Running' ) {
            # job has been running for too long, remove it
            Write-Host "Job $( $job.Id ) on $( $targets[$index] ) has been running for too long. Removing..."
            Stop-Job $job
            Remove-Job $job
            # progressbar
            $CompletedJobsCount++
            #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
        } 

    }

    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

   # update the original variable with the modified output
    $FinalOutput += $results

    # export the final output
    $FinalOutput | Select-Object -ExcludeProperty PSSourceJobInstanceId | Export-Csv $CSVTarget\$filename.csv -Append

    Write-Progress -Activity "BASELINING..." -Status "Finished" -PercentComplete 100
}
#>

<# LFA-Software --- IN DEVELOPMENT ---
Function LFA-Autorun( $targets,$filename,[PSCredential]$creds,$so ){
    $jobs = @()
    $FinalOutput = @()
    
    $MaxConcurrentJobs  = 5 # set the maximum number of concurrent jobs
    $MaxJobDuration     = 180  # maximum duration in seconds for a job to run

    foreach ( $target in $targets ) {
        # throttle the number of concurrent jobs
        while ( $jobs.Count -ge $MaxConcurrentJobs ) {
            # wait for an active job to complete before starting a new one
            $CompletedJob = Wait-Job -Any -Timeout 1
            if ( $CompletedJob ) {
                $FinalOutput += Receive-Job $CompletedJob
                Remove-Job $CompletedJob
            }
        }
            
        Write-Host -NoNewline "Job for target "; Write-Host -NoNewline $target -ForegroundColor Green
        Write-Host -NoNewline " has started at "; Write-Host $(Get-Date) -ForegroundColor Green
    
        $jobs += Start-Job { # enable multithreading operations
            param( $target,$filename,[PSCredential]$creds )
            $LocalFinalOutput = @()

            $LFA = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
				$result = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
				$result += Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
				$result += Get-ItemProperty REGISTRY::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*
				return $result
            }

            $LFA | Sort-Object -Property pscomputername, Name -Unique |
                Group-Object Name |
                    Where-Object {$_.count -le 2} |
                        Select-Object -ExpandProperty Group

            foreach ( $entry in $LFA ){
				$LogEntry = Get-WinEvent -LogName "Application" | Where-Object { $_.id -eq 1033 -and $_.message -like "*$software.name*" -or $_.message -like "*$software.pschildname*" }
                if( $LogEntry ){
                    if( $LogEntry.UserID ){ $InstalledBySID = $LogEntry.UserID.value }
                    else { $InstalledBySID = "Unknown" }
                }
                else { $InstalledBySID = "Unknown" }

                # $InstalledBySID = Get-SoftwareInstallUser $software.Name
                if (  $InstalledBySID -ne "Unknown"  ){
                    $InstalledByAcct = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
                        ( Get-CimInstance -ClassName Win32_Useraccount | Where-Object { $_.SID -eq $InstalledBySID } ).name}
                    $InstalledByProf = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
                        ( Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -eq $InstalledBySID } ).LocalPath}
                }
                $PSObj = [pscustomobject]@{ 
                    IP                  = $target
                    PSParentPath        = $software.PSPath
                    PSChildName         = $software.PSChildName
                    DisplayName         = if (  $software.DisplayName  ) { $software.DisplayName } else { '-' }
                    DisplayVersion      = if (  $software.DisplayVersion  ) { $software.DisplayVersion } else { '-' }
                    InstallDate         = if (  $software.InstallDate  ) { $software.InstallDate } else { '-' }
                    InstallLocation     = if (  $software.InstallLocation  ) { $software.InstallLocation } else { '-' }
                    Publisher           = if (  $software.Publisher  ) { $software.Publisher } else { '-' }
                    UninstallString     = if (  $software.UninstallString  ) { $software.UninstallString } else { '-' }
                    InstalledToProfile  = if (  $software.UninstallString -like "*C:\users\*"  ) {(  $software.UninstallString -split '\\'  )[2] } else { '-' }
                    # in testing env, these three properties were usually blank
                    # the SID may not be recorded on install as often as it should be
                    InstalledBySID      = $InstalledBySID
                    InstalledByAcct     = $InstalledByAcct
                    InstalledByProf     = $InstalledByProf
                }
                $LocalFinalOutput += $PSObj
            }
            $LocalFinalOutput
        } -ArgumentList $target, $filename, $creds, $so, $StartTime 
    }

    # wait for the runaway jobs to complete or kill them
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Wait-Job -Timeout $MaxJobDuration -ErrorAction SilentlyContinue
        if ( $job -and $job.State -eq 'Running' ) {
            # job has been running for too long, remove it
            Write-Host "Job $( $job.Id ) on $( $targets[$index] ) has been running for too long. Removing..."
            Stop-Job $job
            Remove-Job $job
            # progressbar
            $CompletedJobsCount++
            #Update-ProgressBar -CompletedCount $CompletedJobsCount -TargetsCount $TargetsCount
        } 

    }

    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

   # update the original variable with the modified output
    $FinalOutput += $results

    # export the final output
    $FinalOutput | Select-Object -ExcludeProperty PSSourceJobInstanceId | Export-Csv $CSVTarget\$filename.csv -Append

    Write-Progress -Activity "BASELINING..." -Status "Finished" -PercentComplete 100
}
#>

#
# end functions
#

#
# START MAIN
#

# start header
Clear-Host
Write-Host -ForegroundColor cyan "            COMPLETE WINDOWS BASELINE CREATION AND COMPARISON TOOL"
Write-Host "-------------------------------------------------------------------------------"
# end header

#
# script will restart here
#
do {

    # reset variables; ensure clean slate
    Clear-Variable Answer*,Baseline*,Targets,HostFile,x -ErrorAction SilentlyContinue

    # create directory for baselines if it doesn't exist
    if ( -not ( Test-Path $CSVTarget )){ New-Item -ItemType Directory $CSVTarget }

    # start menu
    Write-Host "`n(1) Create New Baseline`n(2) Compare Baselines"
    $answer1 = Read-Host "Select One"
    if ( $answer1 -eq 1 ){ # create new baseline
        # get targets
        Clear-Host
        write-host -ForegroundColor green "`nSelect file with target IPs`n"; pause
        $HostFile = Get-FileName -initialDirectory "$InitialHostsDir"
        $targets = Get-Content -Path $HostFile
        # select baseline type
        Clear-Host
        Write-Host "What type of baseline?"
            Write-Host "(1) Accounts`n(2) Autoruns`n(3) Scheduled Tasks`n(4) Processes`n(5) Services"
            Write-Host "(6) Windows Firewall`n(7) Files Of Interest (IN DEVELOPMENT)`n(8) Software Inventory`n"
        $answer2 = Read-Host "Select One"
        # get credentials from operator
        [pscredential]$creds = get-credential -Message "Enter domain credentials"

        $targets = foreach ( $target in $targets ){
            if (Test-Connection $target -Count 2 -Quiet) { write-output $target }
        }

        # generate new baseline
        if      ( $answer2 -eq 1 ){ # ACCOUNTS
            Clear-Host
            Write-Host -ForegroundColor cyan "GENERATE NEW ACCOUNTS BASELINE`n"
            # get date for file name
            $filename = "Accounts_Baseline_" + ( Get-Date -Format "MM-dd-yy" )        
            New-AccountsBaseline $targets $filename $creds $so
        }
        elseif  ( $answer2 -eq 2 ){ # AUTORUNS
            Clear-Host
            Write-Host -ForegroundColor cyan "GENERATE NEW AUTORUNS BASELINE`n"
            # get date for file name
            $filename = "Autoruns_Baseline_" + ( Get-Date -Format "MM-dd-yy" )
            New-AutorunBaseline $targets $filename $creds $so
        }
        elseif  ( $answer2 -eq 3 ){ # SCHEDULED TASKS
            Clear-Host
            Write-Host -ForegroundColor cyan "GENERATE NEW SCHEDULED TASKS BASELINE`n"
            # get date for file name
            $filename = "ScheduledTasks_Baseline_" + ( Get-Date -Format "MM-dd-yy" )
            New-ScheduledTasksBaseline $targets $filename $creds $so
        }
        elseif  ( $answer2 -eq 4 ){ # PROCESSES
            Clear-Host
            Write-Host -ForegroundColor cyan "GENERATE NEW PROCESSES BASELINE`n"
            # get date for file name
            $filename = "Processes_Baseline_" + ( Get-Date -Format "MM-dd-yy" )
            New-ProcessesBaseline $targets $filename $creds $so
        }
        elseif  ( $answer2 -eq 5 ){ # SERVICES
            Clear-Host
            Write-Host -ForegroundColor cyan "GENERATE NEW SERVICES BASELINE`n"
            # get date for file name
            $filename = "Services_Baseline_" + ( Get-Date -Format "MM-dd-yy" )
            New-ServicesBaseline $targets $filename $creds $so
        }
        elseif  ( $answer2 -eq 6 ){ # FIREWALL
            Clear-Host
            Write-Host -ForegroundColor cyan "GENERATE NEW FIREWALL BASELINE`n"
            # get date for file name
            $filename = "Firewall_Baseline_" + ( Get-Date -Format "MM-dd-yy" )
            New-FirewallBaseline $targets $filename $creds $so
        }
        elseif  ( $answer2 -eq 7 ){ # FILES OF INTEREST
            Clear-Host
            Write-Host -ForegroundColor cyan "GENERATE NEW FILES OF INTEREST BASELINE`n"
            Write-Host "This feature is still in development"
            # get date for file name
            # $filename = "Files_Baseline_" + ( Get-Date -Format "MM-dd-yy" )
            # New-FilesBaseline $targets $filename $creds $so
        }
        elseif  ( $answer2 -eq 8 ){ # SOFTWARE INVENTORY
            Clear-Host
            Write-Host -ForegroundColor cyan "GENERATE NEW SOFTWARE BASELINE`n"
            # get date for file name
            $filename = "Software_Baseline_" + ( Get-Date -Format "MM-dd-yy" )
            New-SoftwareBaseline $targets $filename $creds $so
        }
    }
    elseif ( $answer1 -eq 2 ){ # compare
        Clear-Host
        Write-Host "Compare existing to a new baseline or compare two existing baselines?"
        Write-Host "(1) Create New`n(2) Compare Two Existing`n"
        $answer3= Read-Host "Select One"
        if ( $answer3 -eq 1 ){ # compare based on new baseline
            # get targets
            Clear-Host
            write-host -ForegroundColor green "`nSelect file with target IPs`n"; pause
            $HostFile = Get-FileName -initialDirectory "$InitialHostsDir"
            $targets = Get-Content -Path $HostFile            
            # select baseline type
            Clear-Host
            Write-Host "What type of baseline?"
            Write-Host "(1) Accounts`n(2) Autoruns`n(3) Scheduled Tasks`n(4) Processes`n(5) Services"
            Write-Host "(6) Windows Firewall`n(7) Files Of Interest (IN DEVELOPMENT)`n(8) Software Inventory`n"
            $answer4 = Read-Host "Select One"
            
            # select existing baseline
            write-host -ForegroundColor green "`nSelect existing baseline`n"; pause
            $baseline1_Path = Get-FileName -InitialDirectory "$InitialHostsDir"
            $baseline1 = Import-Csv $baseline1_Path
            
            # get credentials from operator
            [pscredential]$creds = get-credential -Message "Enter domain credentials"
            
            $targets = foreach ( $target in $targets ){
                if (Test-Connection $target -Count 2 -Quiet) { write-output $target }
            }

            # generate new baseline and compare
            if      ( $answer4 -eq 1 ){ # ACCOUNTS
                Clear-Host
                Write-Host -ForegroundColor cyan "COMPARE BASELINE`n"
                Write-Host -ForegroundColor cyan "GENERATE ACCOUNTS BASELINE FOR COMPARE`n"
                # get date for file name
                $filename = "Accounts_Baseline_" + ( Get-Date -Format "MM-dd-yy" )        
                New-AccountsBaseline $targets $filename $creds $so
                ## COMPARE FUNCTION HERE ##
                $baseline2 = Import-Csv $CSVTarget\$filename.csv
                Compare-Baseline $baseline1 $baseline2
            }
            elseif  ( $answer4 -eq 2 ){ # AUTORUNS
                Clear-Host
                Write-Host -ForegroundColor cyan "COMPARE BASELINE`n"
                Write-Host -ForegroundColor cyan "GENERATE AUTORUNS BASELINE FOR COMPARE`n"
                # get date for file name
                $filename = "Autoruns_Baseline_" + ( Get-Date -Format "MM-dd-yy" )
                New-AutorunBaseline $targets $filename $creds $so
                ## COMPARE FUNCTION HERE ##
                $baseline2 = Import-Csv $CSVTarget\$filename.csv
                Compare-Baseline $baseline1 $baseline2
            }
            elseif  ( $answer4 -eq 3 ){ # SCHEDULED TASKS
                Clear-Host
                Write-Host -ForegroundColor cyan "COMPARE BASELINE`n"
                Write-Host -ForegroundColor cyan "GENERATE SCHEDULED TASKS BASELINE FOR COMPARE`n"
                # get date for file name
                $filename = "ScheduledTasks_Baseline_" + ( Get-Date -Format "MM-dd-yy" )
                New-ScheduledTasksBaseline $targets $filename $creds $so
                ## COMPARE FUNCTION HERE ##
                $baseline2 = Import-Csv $CSVTarget\$filename.csv
                Compare-Baseline $baseline1 $baseline2
            }
            elseif  ( $answer4 -eq 4 ){ # PROCESSES
                Clear-Host
                Write-Host -ForegroundColor cyan "COMPARE BASELINE`n"
                Write-Host -ForegroundColor cyan "GENERATE PROCESSES BASELINE FOR COMPARE`n"
                # get date for file name
                $filename = "Processes_Baseline_" + ( Get-Date -Format "MM-dd-yy" )
                New-ProcessesBaseline $targets $filename $creds $so
                ## COMPARE FUNCTION HERE ##
                $baseline2 = Import-Csv $CSVTarget\$filename.csv
                Compare-Baseline $baseline1 $baseline2
            }
            elseif  ( $answer4 -eq 5 ){ # SERVICES
                Clear-Host
                Write-Host -ForegroundColor cyan "COMPARE BASELINE`n"
                Write-Host -ForegroundColor cyan "GENERATE SERVICES BASELINE FOR COMPARE`n"
                # get date for file name
                $filename = "Services_Baseline_" + ( Get-Date -Format "MM-dd-yy" )
                New-ServicesBaseline $targets $filename $creds $so
                ## COMPARE FUNCTION HERE ##
                $baseline2 = Import-Csv $CSVTarget\$filename.csv
                Compare-Baseline $baseline1 $baseline2
            }
            elseif  ( $answer4 -eq 6 ){ # FIREWALL
                Clear-Host
                Write-Host -ForegroundColor cyan "COMPARE BASELINE`n"
                Write-Host -ForegroundColor cyan "GENERATE FIREWALL BASELINE FOR COMPARE`n"
                # get date for file name
                $filename = "Firewall_Baseline_" + ( Get-Date -Format "MM-dd-yy" )
                New-FirewallBaseline $targets $filename $creds $so
                ## COMPARE FUNCTION HERE ##
                $baseline2 = Import-Csv $CSVTarget\$filename.csv
                Compare-Baseline $baseline1 $baseline2
            }
            elseif  ( $answer4 -eq 7 ){ # FILES OF INTEREST
                Clear-Host
                Write-Host -ForegroundColor cyan "COMPARE BASELINE`n"
                Write-Host -ForegroundColor cyan "GENERATE FILES OF INTEREST BASELINE FOR COMPARE`n"
                Write-Host "This feature is still in development"
                # get date for file name
                # $filename = "Files_Baseline_" + ( Get-Date -Format "MM-dd-yy" )
                # New-FilesBaseline $targets $filename $creds $so
                # ## COMPARE FUNCTION HERE ##
                # $baseline2 = Import-Csv $CSVTarget\$filename.csv
                # Compare-Baseline $baseline1 $baseline2
            }
            elseif  ( $answer4 -eq 8 ){ # SOFTWARE INVENTORY
                Clear-Host
                Write-Host -ForegroundColor cyan "COMPARE BASELINE`n"
                Write-Host -ForegroundColor cyan "GENERATE SOFTWARE BASELINE FOR COMPARE`n"
                # get date for file name
                $filename = "Software_Baseline_" + ( Get-Date -Format "MM-dd-yy" )
                New-SoftwareBaseline $targets $filename $creds $so
                ## COMPARE FUNCTION HERE ##
                $baseline2 = Import-Csv $CSVTarget\$filename.csv
                Compare-Baseline $baseline1 $baseline2
            }
        }
        elseif ( $answer3 -eq 2 ){ # compare two existing baselines
            write-host -ForegroundColor green "`nSelect first existing baseline`n"; pause
            $baseline1_Path = Get-FileName -initialDirectory "$InitialHostsDir"
            $baseline1 = Import-Csv -Path $baseline1_Path
            write-host -ForegroundColor green "`nSelect second existing baseline`n"; pause
            $baseline2_Path = Get-FileName -initialDirectory "$InitialHostsDir"
            $baseline2 = Import-Csv -Path $baseline2_Path
            ## COMPARE FUNCTION HERE ##
            Compare-Baseline $baseline1 $baseline2
        }
    }
    # end menu
    
    Write-Host -ForegroundColor cyan "`nAll results and reports can be found at $CSVTarget`n"

    $x = read-host "Do you want to return to main menu?"
    if ( -not ( $x -eq "yes" -or $x -eq "y" )) {Clear-Host; $x = 1} # exit script
    else { Clear-Host } # restart menu
}
until ( $x -eq 1 )

#
# END MAIN
#

Stop-Transcript
