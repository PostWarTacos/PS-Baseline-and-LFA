function Show-Menu
{
     param (
           [string]$Title = ‘Baseline Tasks’
     )
     clear
     Write-Host “================ $Title ================”
    
     Write-Host “1: Press ‘1’ to execute full baseline.”
     Write-Host “2: Press ‘2’ for job status.”
     Write-Host “3: Press ‘3’ for processes.”
     Write-Host “Q: Press ‘Q’ to quit.”
     Write-Host "========================================="
}

do
{
     Show-Menu
     $input = Read-Host “Please make a selection”
     switch ($input)
     {
           ‘1’ {
                Clear-Host
                #Call another script
                Start-Job {.\02_Create_Baseline_Scripts\create_baseline_accounts.ps1}
                Start-Job {.\02_Create_Baseline_Scripts\create_baseline_autoruns.ps1} 
                Start-Job {.\02_Create_Baseline_Scripts\create_baseline_files_of_interest.ps1} 
                Start-Job {.\02_Create_Baseline_Scripts\create_baseline_firewalls.ps1} 
                Start-Job {.\02_Create_Baseline_Scripts\create_baseline_folders_of_interest.ps1} 
                Start-Job {.\02_Create_Baseline_Scripts\create_baseline_interfaces.ps1} 
                Start-Job {.\02_Create_Baseline_Scripts\create_baseline_processes.ps1} 
                Start-Job {.\02_Create_Baseline_Scripts\create_baseline_scheduled_tasks.ps1} 
                Start-Job {.\02_Create_Baseline_Scripts\create_baseline_services.ps1} 
                Start-Job {.\02_Create_Baseline_Scripts\create_baseline_software_inventory.ps1} 
           } ‘2’ {
                Clear-Host
                ping 127.0.0.1
           } ‘3’ {
                Clear-Host
                Get-Process
           } ‘q’ {
                return
           } ‘2’ {
               Clear-Host
               ping 127.0.0.1
          }  ‘2’ {
               Clear-Host
               ping 127.0.0.1
          }  ‘2’ {
               Clear-Host
               ping 127.0.0.1
          }  ‘2’ {
               Clear-Host
               ping 127.0.0.1
          }  ‘2’ {
               Clear-Host
               ping 127.0.0.1
          }  ‘2’ {
               Clear-Host
               ping 127.0.0.1
          }  ‘2’ {
               Clear-Host
               ping 127.0.0.1
          }  ‘2’ {
               Clear-Host
               ping 127.0.0.1
          }  ‘2’ {
               Clear-Host
               ping 127.0.0.1
          }
     }
     wait 10
}
until ($input -eq ‘q’)