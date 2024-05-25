param([string[]] $Folders)

Get-ChildItem -Path $Folders -ErrorAction SilentlyContinue | Select-Object Name, FullName, CreationTime