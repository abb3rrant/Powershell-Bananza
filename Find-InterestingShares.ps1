<#
.SYNOPSIS
    Enumerate SMB shares on likely file-server hosts pulled from AD and search
    for files with interesting names. Fault-tolerant per-directory recursion
    with a per-share time budget so no one share can stall the whole scan.

.DESCRIPTION
    Pure PowerShell + net.exe. No modules. Read-only.

    Confidence tiers:
      HIGH  - patterns that almost always mean what they say (*.kdbx, id_rsa,
              *.pfx, LAPS exports, Group Policy Preferences XML). Reported
              by default.
      LOW   - patterns that catch noise too (password.txt, *creds*, *secret*).
              Reported only with -IncludeLowConfidence.

    Traversal: custom BFS with per-directory try/catch and per-share time
    budget. One dead subtree or one huge share cannot stall the scan.
#>
[CmdletBinding()]
param(
    [int]$MaxHosts             = 100,
    [int]$DaysSinceLogon       = 60,
    [int]$MaxDepth             = 5,
    [int]$MaxFilesPerShare     = 30,
    [int]$ShareBudgetSec       = 45,
    [int]$ConnectTimeoutMs     = 1500,
    [switch]$IncludeAdminShares,
    [switch]$IncludeDcShares,
    [switch]$IncludeLowConfidence,
    [string]$OSFilter          = '*Server*',
    [string]$OutputCsv,
    [string]$OutputTxt,
    [string[]]$Hosts,
    [string[]]$SkipDirs        = @(
        'Windows','Program Files','Program Files (x86)','ProgramData',
        '$Recycle.Bin','System Volume Information','node_modules',
        '.git','.svn','.hg','packages','obj','bin','WSUSContent',
        'PerfLogs','Microsoft'
    )
)

# ============================================================================
# Pattern catalog
# ============================================================================

$HighConfPatterns = [ordered]@{
    KeePass         = @('*.kdbx', '*.kdb')
    PasswordSafe    = @('*.psafe3')
    OpenSSHKey      = @('id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519')
    PuttyKey        = @('*.ppk')
    PfxCert         = @('*.pfx', '*.p12')
    LapsExport      = @('LAPS*.txt', 'LAPS*.csv', 'LAPS*.xlsx', 'LAPS-*.csv', 'LAPS-*.xlsx')
    Unattend        = @('unattend.xml', 'autounattend.xml', 'sysprep.xml', 'sysprep.inf')
    GroupPolicyPrefs= @('Groups.xml', 'ScheduledTasks.xml', 'Services.xml', 'DataSources.xml', 'Drives.xml', 'Printers.xml')
    DotEnv          = @('.env', '.env.*')
    Rdp             = @('*.rdp', '*.rdg')
    Bacpac          = @('*.bacpac')
    AccessDb        = @('*.mdb', '*.accdb')
    SqliteDb        = @('*.sqlite', '*.sqlite3', '*.db3')
    PublishSettings = @('*.publishsettings')
    WebConfig       = @('web.config', 'app.config', 'appsettings.json', 'appsettings.*.json')
    OutlookPst      = @('*.pst', '*.ost')
    SqlBackup       = @('*.bak', '*.trn')
}

$LowConfPatterns = [ordered]@{
    PasswordName    = @('password.txt', 'passwords.txt', 'passwords.csv', 'passwords.xlsx',
                        'pass.txt', 'pwd.txt', 'pw.txt')
    CredsName       = @('creds.txt', 'creds.csv', 'credentials.txt', 'credentials.csv',
                        'credentials.xlsx')
    ContainsSecret  = @('*_secret*', '*_secrets*')
    ContainsPrivate = @('*_private*')
    Sensitive       = @('*confidential*', '*payroll*', '*salary*', '*ssn*')
    GenericBackup   = @('*.backup', '*.old', '*.orig')
}

$AdminShareNames = @('ADMIN$', 'IPC$', 'print$', 'PRINT$', 'FAX$')
$DcShareNames    = @('NETLOGON', 'SYSVOL')

# ============================================================================
# Output helpers
# ============================================================================

function Write-Header { param($t) Write-Host ""; Write-Host "=== $t ===" -ForegroundColor Cyan }
function Write-Info   { param($m) Write-Host "  $m" -ForegroundColor Gray }
function Write-Hit    { param($m) Write-Host "    [+] $m" -ForegroundColor Green }
function Write-Hint   { param($m) Write-Host "    [?] $m" -ForegroundColor DarkYellow }
function Write-Warn   { param($m) Write-Host "  [!] $m" -ForegroundColor Yellow }
function Write-Bad    { param($m) Write-Host "  [-] $m" -ForegroundColor Red }

# ============================================================================
# TCP probe
# ============================================================================

function Test-Port {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs)
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($HostName, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $c.EndConnect($iar); return $true
        }
        return $false
    } catch { return $false }
    finally { $c.Close() }
}

# ============================================================================
# Share listing
# ============================================================================

function Get-HostShares {
    param([string]$HostName)
    $out = & cmd.exe /c "net view \\$HostName /all 2>nul"
    if ($LASTEXITCODE -ne 0) { return @() }

    $shares = @()
    $inTable = $false
    foreach ($line in $out) {
        if ($line -match '^-{5,}') { $inTable = $true; continue }
        if (-not $inTable) { continue }
        if ($line -match '^The command completed') { break }
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^(\S+)\s+(Disk|Print|IPC)\s*(.*)$') {
            $shares += [PSCustomObject]@{
                Name    = $matches[1]
                Type    = $matches[2]
                Comment = $matches[3].Trim()
            }
        }
    }
    ,$shares
}

# ============================================================================
# Pattern matching helper
# ============================================================================

function Test-NameAgainstPatterns {
    param([string]$Name, [switch]$IncludeLow)

    foreach ($cat in $HighConfPatterns.Keys) {
        foreach ($pat in $HighConfPatterns[$cat]) {
            if ($Name -like $pat) { return @{ Category = $cat; Confidence = 'HIGH' } }
        }
    }
    if ($IncludeLow) {
        foreach ($cat in $LowConfPatterns.Keys) {
            foreach ($pat in $LowConfPatterns[$cat]) {
                if ($Name -like $pat) { return @{ Category = $cat; Confidence = 'LOW' } }
            }
        }
    }
    return $null
}

# ============================================================================
# Fault-tolerant share walker
# ============================================================================

function Search-ShareTree {
    param(
        [string]$Root,
        [int]$MaxDepth,
        [int]$MaxFiles,
        [int]$BudgetSec,
        [switch]$IncludeLow,
        [string[]]$SkipDirs
    )

    $findings = New-Object System.Collections.Generic.List[PSCustomObject]
    $deadline = (Get-Date).AddSeconds($BudgetSec)
    $skipSet = @{}
    foreach ($d in $SkipDirs) { $skipSet[$d.ToLowerInvariant()] = $true }

    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue(@{ Path = $Root; Depth = 0 })

    $timedOut = $false

    while ($queue.Count -gt 0) {
        if ((Get-Date) -gt $deadline) { $timedOut = $true; break }
        if ($findings.Count -ge $MaxFiles) { break }

        $item = $queue.Dequeue()
        $curPath = $item.Path
        $curDepth = $item.Depth

        # Use lazy .NET enumerator so we can bail out mid-directory when the
        # deadline hits. Get-ChildItem would materialize the whole listing
        # before returning, defeating the budget on huge dirs.
        $enumerator = $null
        try {
            $enumerator = [System.IO.Directory]::EnumerateFileSystemEntries(
                $curPath, '*', [System.IO.SearchOption]::TopDirectoryOnly).GetEnumerator()
        } catch { continue }

        try {
            while ($true) {
                if ((Get-Date) -gt $deadline) { $timedOut = $true; break }
                if ($findings.Count -ge $MaxFiles) { break }

                $moved = $false
                try { $moved = $enumerator.MoveNext() } catch { break }
                if (-not $moved) { break }

                $fullPath = $enumerator.Current
                $name = [System.IO.Path]::GetFileName($fullPath)

                # Attributes tell us dir vs file cheaply
                $attrs = $null
                try { $attrs = [System.IO.File]::GetAttributes($fullPath) } catch { continue }
                $isDir = ($attrs -band [System.IO.FileAttributes]::Directory) -ne 0

                if ($isDir -and $skipSet.ContainsKey($name.ToLowerInvariant())) {
                    if ($name -in '.git','.svn','.hg') {
                        $findings.Add([PSCustomObject]@{
                            Category   = 'VersionControl'
                            Confidence = 'HIGH'
                            Path       = $fullPath
                            Size       = $null
                            Modified   = $null
                            IsDir      = $true
                        })
                    }
                    continue
                }

                $match = Test-NameAgainstPatterns -Name $name -IncludeLow:$IncludeLow
                if ($match) {
                    $size = $null; $modified = $null
                    if (-not $isDir) {
                        try {
                            $fi = New-Object System.IO.FileInfo($fullPath)
                            $size = $fi.Length
                            $modified = $fi.LastWriteTime
                        } catch {}
                    }
                    $findings.Add([PSCustomObject]@{
                        Category   = $match.Category
                        Confidence = $match.Confidence
                        Path       = $fullPath
                        Size       = $size
                        Modified   = $modified
                        IsDir      = $isDir
                    })
                }

                if ($isDir -and $curDepth -lt $MaxDepth) {
                    if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    $queue.Enqueue(@{ Path = $fullPath; Depth = $curDepth + 1 })
                }
            }
        } finally {
            if ($enumerator) { try { $enumerator.Dispose() } catch {} }
        }
    }

    [PSCustomObject]@{ Findings = $findings; TimedOut = $timedOut }
}

# ============================================================================
# Host discovery
# ============================================================================

if (-not $Hosts) {
    Write-Header "Host discovery"
    try {
        $domainDN = [string]([ADSI]"LDAP://RootDSE").defaultNamingContext
    } catch { Write-Bad "Cannot bind to directory: $_"; return }

    $threshold = [DateTime]::UtcNow.AddDays(-$DaysSinceLogon).ToFileTime()
    $filter = "(&(objectCategory=computer)(operatingSystem=$OSFilter)" +
              "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
              "(lastLogonTimestamp>=$threshold))"

    $searcher = New-Object DirectoryServices.DirectorySearcher(
        [ADSI]"LDAP://$domainDN", $filter,
        @('name','dNSHostName','operatingSystem','lastLogonTimestamp'))
    $searcher.PageSize = 500

    $found = @()
    try {
        foreach ($r in $searcher.FindAll()) {
            $name = [string]$r.Properties['dnshostname']
            if (-not $name) { $name = [string]$r.Properties['name'] }
            if (-not $name) { continue }
            $found += [PSCustomObject]@{
                Name = $name
                OS   = [string]$r.Properties['operatingsystem']
                Last = if ($r.Properties['lastlogontimestamp']) {
                    [DateTime]::FromFileTime([int64]$r.Properties['lastlogontimestamp'][0])
                } else { $null }
            }
        }
    } catch { Write-Bad "AD search failed: $_"; return }

    Write-Info "AD returned $($found.Count) candidate host(s)"
    if ($found.Count -gt $MaxHosts) {
        Write-Warn "Capping to most recently active $MaxHosts"
        $found = $found | Sort-Object -Property Last -Descending | Select-Object -First $MaxHosts
    }
    $Hosts = $found | Select-Object -ExpandProperty Name
}

if (-not $Hosts -or $Hosts.Count -eq 0) { Write-Bad "No hosts to scan."; return }
Write-Info "Scanning $($Hosts.Count) host(s)..."
if ($IncludeLowConfidence) { Write-Warn "Low-confidence patterns enabled (expect noise)" }

# Start transcript for full console capture if requested
$transcriptStarted = $false
if ($OutputTxt) {
    try {
        # Stop any prior transcript quietly, then start ours
        try { Stop-Transcript | Out-Null } catch {}
        Start-Transcript -Path $OutputTxt -Force | Out-Null
        $transcriptStarted = $true
        Write-Info "Transcript: $OutputTxt"
    } catch {
        Write-Bad "Failed to start transcript: $_"
    }
}

# ============================================================================
# Main scan
# ============================================================================

$allFindings = New-Object System.Collections.Generic.List[PSCustomObject]
$stats = [PSCustomObject]@{
    HostsProbed=0; HostsReachable=0; HostsWithShares=0
    SharesEnum=0; SharesReadable=0; SharesTimedOut=0; Findings=0
}
$hostIdx = 0

foreach ($h in $Hosts) {
    $hostIdx++
    $stats.HostsProbed++
    if ($hostIdx % 10 -eq 0) {
        Write-Warn "[$hostIdx/$($Hosts.Count)] reachable=$($stats.HostsReachable) shares=$($stats.SharesReadable) findings=$($stats.Findings)"
    }

    if (-not (Test-Port -HostName $h -Port 445 -TimeoutMs $ConnectTimeoutMs)) { continue }
    $stats.HostsReachable++

    $shares = Get-HostShares -HostName $h
    if ($shares.Count -eq 0) { continue }
    $stats.HostsWithShares++

    $hostHeaderPrinted = $false

    foreach ($s in $shares) {
        if ($s.Type -ne 'Disk') { continue }
        if (-not $IncludeAdminShares -and (
            $AdminShareNames -contains $s.Name -or $s.Name -match '^[A-Za-z]\$$'
        )) { continue }
        if (-not $IncludeDcShares -and $DcShareNames -contains $s.Name) { continue }

        $stats.SharesEnum++
        $unc = "\\$h\$($s.Name)"

        try {
            $null = Get-ChildItem -LiteralPath $unc -ErrorAction Stop -Force |
                Select-Object -First 1
        } catch { continue }
        $stats.SharesReadable++

        if (-not $hostHeaderPrinted) {
            Write-Host ""; Write-Host "  \\$h" -ForegroundColor White
            $hostHeaderPrinted = $true
        }
        Write-Info "  $($s.Name)  ($($s.Comment))"

        $r = Search-ShareTree -Root $unc -MaxDepth $MaxDepth -MaxFiles $MaxFilesPerShare `
             -BudgetSec $ShareBudgetSec -IncludeLow:$IncludeLowConfidence -SkipDirs $SkipDirs

        if ($r.TimedOut) {
            $stats.SharesTimedOut++
            Write-Warn "    (share time budget exceeded, partial results)"
        }

        foreach ($hit in $r.Findings) {
            $stats.Findings++
            $tag = if ($hit.IsDir) { '[DIR]' } else { '     ' }
            $sizeStr = if ($hit.Size) { " ({0:N0}b)" -f $hit.Size } else { '' }
            $line = ("{0,-6} {1,-16} {2} {3}{4}" -f $hit.Confidence, $hit.Category, $tag, $hit.Path, $sizeStr)
            if ($hit.Confidence -eq 'HIGH') { Write-Hit $line } else { Write-Hint $line }

            $allFindings.Add([PSCustomObject]@{
                Host       = $h
                Share      = $s.Name
                Category   = $hit.Category
                Confidence = $hit.Confidence
                Path       = $hit.Path
                Size       = $hit.Size
                Modified   = $hit.Modified
                IsDir      = $hit.IsDir
            })
        }
    }
}

# ============================================================================
# Summary + CSV
# ============================================================================

Write-Header "Summary"
Write-Info "Hosts probed          : $($stats.HostsProbed)"
Write-Info "Hosts reachable (445) : $($stats.HostsReachable)"
Write-Info "Hosts with shares     : $($stats.HostsWithShares)"
Write-Info "Shares enumerated     : $($stats.SharesEnum)"
Write-Info "Shares readable       : $($stats.SharesReadable)"
Write-Info "Shares budget-hit     : $($stats.SharesTimedOut)"
Write-Info "Interesting findings  : $($stats.Findings)"

if ($allFindings.Count -gt 0) {
    Write-Host ""; Write-Host "  Findings by confidence + category:" -ForegroundColor Cyan
    $allFindings | Group-Object Confidence, Category | Sort-Object Count -Descending |
        ForEach-Object { Write-Info ("    {0,-30} : {1}" -f $_.Name, $_.Count) }
}

if ($OutputCsv -and $allFindings.Count -gt 0) {
    try {
        $allFindings | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
        Write-Info "CSV written: $OutputCsv"
    } catch { Write-Bad "Failed to write CSV: $_" }
}

if ($transcriptStarted) {
    try { Stop-Transcript | Out-Null } catch {}
}
Write-Host ""
