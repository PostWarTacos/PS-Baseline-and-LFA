param([string[]] $patterns)

$patterns | ForEach-Object {gci -Path c:\ -Recurse -File -Force -Filter $_ -ErrorAction SilentlyContinue | Select-Object -Property @{n="FileName";e={$_.Name}}, @{n="Path";e={$_.FullName}}, @{n="BornTime";e={$_.CreationTime}}}