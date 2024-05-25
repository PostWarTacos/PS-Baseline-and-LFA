Get-CimInstance -ClassName Win32_UserAccount |
    Select-Object -Property Name, AccountType, Disabled, PasswordRequired, SID
    Export-Csv C:\temp\Outfile.csv -Append -Force -NoTypeInformation
   