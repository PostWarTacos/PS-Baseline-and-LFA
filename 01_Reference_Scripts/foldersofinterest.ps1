param([string[]] $Folders)

Get-ChildItem -Path $Folders -ErrorAction SilentlyContinue | Select-Object -Property @{n="FileName";e={$_.Name}}, @{n="Path";e={$_.FullName}}, @{n="BornTime";e={$_.CreationTime}}