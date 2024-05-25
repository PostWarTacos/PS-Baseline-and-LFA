Get-CimInstance -ClassName Win32_Process |
     Select-Object -Property ProcessName,
                             ProcessID,
			     ParentProcessID,
                             Path,
                             CommandLine,
                             @{n="Hash"; e={(Get-FileHash -Path $_.path).hash}} |
                             Export-Csv -Path C:\temp\Outfile.csv -Append