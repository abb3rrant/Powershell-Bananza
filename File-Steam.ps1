<#
.SYNOPSIS
    Stream a file and search for interesting strings.
    Handles ASCII, UTF-8, and UTF-16LE (Unicode strings inside binaries).

.EXAMPLE
    .\Search-Streamed.ps1 -Path 'C:\backup\corp.bak'
    .\Search-Streamed.ps1 -Path .\db.mdb -Patterns 'password\s*=','ConnectionString'
    .\Search-Streamed.ps1 -Path huge.bak -Context 40 -MaxHits 50
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position=0)][string]$Path,
    [string[]]$Patterns = @(
        'password\s*[:=]',
        'passwd\s*[:=]',
        'pwd\s*[:=]',
        'ConnectionString',
        'Server\s*=\s*[^;]+;.*(?:Password|Pwd)\s*=',
        'Data Source\s*=',
        'apikey\s*[:=]',
        'api[_-]?token\s*[:=]',
        'secret\s*[:=]',
        'BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY',
        'AKIA[0-9A-Z]{16}',       # AWS access key ID
        'xox[abpr]-[0-9A-Za-z-]+' # Slack tokens
    ),
    [int]$Context   = 60,      # chars before/after match to print
    [int]$MaxHits   = 200,     # cap total hits
    [int]$BufferKB  = 256      # read buffer size
)

if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }

$compiled = $Patterns | ForEach-Object {
    [regex]::new($_, [Text.RegularExpressions.RegexOptions]'IgnoreCase, Compiled')
}

$fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
$size = $fs.Length
$bufSize = $BufferKB * 1024
$buf = New-Object byte[] $bufSize
$overlap = 256   # bytes carried between chunks so matches don't get split
$carry = ''      # ASCII/UTF-8 carry
$carryUni = ''   # UTF-16LE carry
$offset = 0
$hits = 0

Write-Host ("Scanning {0} ({1:N0} bytes)..." -f $Path, $size) -ForegroundColor Cyan

while ($offset -lt $size -and $hits -lt $MaxHits) {
    $read = $fs.Read($buf, 0, $bufSize)
    if ($read -le 0) { break }

    # Decode this chunk two ways: as UTF-8 and as UTF-16LE.
    # Cheap way to catch both plain text and Unicode strings inside binaries.
    $asAscii = [Text.Encoding]::UTF8.GetString($buf, 0, $read)
    $asUni   = [Text.Encoding]::Unicode.GetString($buf, 0, $read)

    foreach ($mode in @(
        @{ Name='utf8';  Text=$carry    + $asAscii; CarryVar='carry'    },
        @{ Name='utf16'; Text=$carryUni + $asUni;   CarryVar='carryUni' }
    )) {
        foreach ($rx in $compiled) {
            foreach ($m in $rx.Matches($mode.Text)) {
                if ($hits -ge $MaxHits) { break }
                $start  = [Math]::Max(0, $m.Index - $Context)
                $end    = [Math]::Min($mode.Text.Length, $m.Index + $m.Length + $Context)
                $snippet = $mode.Text.Substring($start, $end - $start) -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]',' '
                $approxOffset = $offset + $m.Index
                Write-Host ("  [{0}] @~{1}  /{2}/  {3}" -f $mode.Name, $approxOffset, $rx, $snippet.Trim())
                $hits++
            }
        }
        # Keep the tail so cross-boundary matches survive
        Set-Variable -Name $mode.CarryVar -Value (
            $mode.Text.Substring([Math]::Max(0, $mode.Text.Length - $overlap))
        )
    }
    $offset += $read
}
$fs.Close()

Write-Host ""
Write-Host ("Done. {0} hit(s), scanned {1:N0} of {2:N0} bytes." -f $hits, $offset, $size) -ForegroundColor Cyan
if ($hits -ge $MaxHits) { Write-Host "  (hit cap reached; raise with -MaxHits)" -ForegroundColor Yellow }
