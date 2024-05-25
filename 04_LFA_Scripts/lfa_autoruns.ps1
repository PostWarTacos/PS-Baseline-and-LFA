Function New-AutorunBaseline($targets,$filename,[PSCredential]$creds,$so){
    $jobs = @()
    $FinalOutput = @()
    $x = 0
    
    $MaxConcurrentJobs  = 5 # set the maximum number of concurrent jobs
    $MaxJobDuration     = 180  # maximum duration in seconds for a job to run

    foreach ($target in $targets) {
        # throttle the number of concurrent jobs
        while ($jobs.Count -ge $MaxConcurrentJobs) {
            # wait for an active job to complete before starting a new one
            $CompletedJob = Wait-Job -Any -Timeout 1
            if ($CompletedJob) {
                $FinalOutput += Receive-Job $CompletedJob
                Remove-Job $CompletedJob
            }
        }
            
        $StartTime = Get-Date
    
        $jobs += Start-Job { # enable multithreading operations
            param($target,$filename,[PSCredential]$creds)
            $localFinalOutput = @()

            # check for runaway jobs
            while (@((Get-Job -State Running) | Measure-Object).Count -ge 1) {
                $now = Get-Date
                Write-Host "Current time: $now"

                foreach ($job in @(Get-Job -State Running)) {
                    $StartTime = (Get-Job -Id $job.Id).PSBeginTime
                    Write-Host "Job ID $($job.Id) started at: $StartTime"

                    if ($now - $StartTime -gt [TimeSpan]::FromMinutes(5)) {
                        Write-Host "Stopping Job ID $($job.Id) because it has been running for more than 5 minutes."
                        Stop-Job $job
                    }
                }
                Start-Sleep -Seconds 2
            }

            $LFA = Invoke-Command -CN $using:target -CR $using:creds -SessionOption $using:so {
                Get-CimInstance -Class Win32_StartupCommand
            }

            $LFA | Sort-Object -Property pscomputername, Name, Command, Location -Unique |
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
                $localFinalOutput += $PSObj
            }
            $localFinalOutput
        } -ArgumentList $target, $filename, $creds, $so, $StartTime 
		$x++
    }

    # wait for the runaway jobs to complete or kill them
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Wait-Job -Timeout $maxJobDuration -ErrorAction SilentlyContinue
        if ($job -and $job.State -eq 'Running') {
            # job has been running for too long, remove it
            Write-Host "Job $($job.Id) on $($targets[$x]) has been running for too long. Removing..."
            Stop-Job $job
            Remove-Job $job
        } elseif ($job) {
            $FinalOutput += Receive-Job $job
            $job | Remove-Job
        }
        Write-Progress -Activity "BASELINING..." -Status " $($x + 1) of $($targets.Count)" -PercentComplete ($x / $targets.Count * 100)
    }

    # wait for all jobs to complete
    $results = Receive-Job -Job $jobs -Wait

    # remove the jobs
    $jobs | ForEach-Object {
        $job = $_
        $null = $job | Stop-Job -PassThru -ErrorAction SilentlyContinue
        $null = $job | Remove-Job -ErrorAction SilentlyContinue
    }

   # update the original variable with the modified output
    $FinalOutput += $results

    # export the final output
    $FinalOutput | Select-Object -ExcludeProperty PSSourceJobInstanceId | Export-Csv $CSVTarget\$filename.csv -Append

    Write-Progress -Activity "BASELINING..." -Status "Finished" -PercentComplete 100
}


