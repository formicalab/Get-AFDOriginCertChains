<#
.SYNOPSIS
    Enumerates distinct origins across a list of Azure Front Door profiles
    and tests TLS connectivity to each unique origin.

.DESCRIPTION
    1. Reads a CSV with impacted AFD profiles (Subscription Name/ID + Profile names).
    2. Acquires a single Bearer token via the Az.Accounts PowerShell module.
    3. Resolves each profile's resource group via Azure Resource Graph (one call).
    4. For each profile, calls the REST API to list origin groups, then for each
       origin group lists origins — all using native Invoke-RestMethod (fast).
    5. For each distinct hostname, tests TLS connectivity on port 443 and checks
       the certificate chain (DNS resolution, TCP connect, TLS handshake).
    6. Exports a CSV with a TlsStatus column per origin row.

    TlsStatus values (based on raw TLS Certificate message parsing):
      FullChain             - Server sent root + intermediate + leaf (3+ certs)
      ExpiredFullChain      - Same as FullChain but leaf certificate is expired
      PartialChain          - Server sent intermediate + leaf (2 certs)
      ExpiredPartialChain   - Same as PartialChain but leaf certificate is expired
      NoChain               - Server sent only the leaf certificate (1 cert)
      ExpiredNoChain        - Same as NoChain but leaf certificate is expired
      NoCert                - Server sent no certificates (0 certs)
      DnsFailure            - Hostname could not be resolved
      TcpFailure            - TCP connection to port 443 failed or refused
      TlsError: Timeout     - TCP connected but TLS handshake timed out
      TlsError: <msg>       - TLS handshake failed with a specific error

.PARAMETER InputCsvPath
    CSV with columns: "Subscription Name", "Subscription ID", "Profile ID(s)".

.PARAMETER OutputCsvPath
    Output CSV path. Default: afd-impacted-origins.csv in current directory.

.PARAMETER ThrottleLimit
    Parallel ARM enumeration limit. Default: 10.

.PARAMETER TlsThrottleLimit
    Parallel TLS test limit. Default: 40.

.PARAMETER TlsTimeoutMs
    TCP/TLS connection timeout in milliseconds. Default: 5000.

.PARAMETER SkipTls
    Skip TLS testing (only enumerate origins).

.EXAMPLE
    .\Get-AFDOriginCertChains.ps1 -InputCsvPath .\afd-impacted-profiles.csv
.EXAMPLE
    .\Get-AFDOriginCertChains.ps1 -InputCsvPath .\afd-impacted-profiles.csv -TlsThrottleLimit 30
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputCsvPath,

    [string]$OutputCsvPath = (Join-Path (Get-Location) 'afd-impacted-origins.csv'),

    [ValidateRange(1, 50)]
    [int]$ThrottleLimit = 10,

    [ValidateRange(1, 200)]
    [int]$TlsThrottleLimit = 40,

    [ValidateRange(1000, 30000)]
    [int]$TlsTimeoutMs = 5000,

    [switch]$SkipTls
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$apiVersion = '2025-04-15'

try {
    Import-Module Az.Accounts -ErrorAction Stop
}
catch {
    throw "Az.Accounts is required. Install it with 'Install-Module Az.Accounts -Scope CurrentUser' and sign in with Connect-AzAccount."
}

function ConvertTo-PlainText {
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Value
    )

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [securestring]) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            if ($bstr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }

    throw "ConvertTo-PlainText: unexpected type [$($Value.GetType().FullName)]."
}

function Get-ArmBearerToken {
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context -or -not $context.Account) {
        throw "No Azure PowerShell context found. Run Connect-AzAccount first."
    }

    $tokenResponse = Get-AzAccessToken -ResourceUrl 'https://management.azure.com' -ErrorAction Stop
    $rawToken = if ($tokenResponse.PSObject.Properties['Token']) {
        $tokenResponse.Token
    }
    elseif ($tokenResponse.PSObject.Properties['AccessToken']) {
        $tokenResponse.AccessToken
    }
    else {
        $null
    }

    if ([string]::IsNullOrWhiteSpace((ConvertTo-PlainText -Value $rawToken))) {
        throw 'Failed to acquire an Azure access token from Az.Accounts.'
    }

    return [pscustomobject]@{
        Context = $context
        Token   = (ConvertTo-PlainText -Value $rawToken)
    }
}

# Maps a TlsStatus string to a console color for Write-Host output.
function Get-TlsStatusColor([string]$s) {
    switch -Wildcard ($s) {
        'FullChain'    { 'Green' }
        'PartialChain' { 'Green' }
        'NoChain'      { 'Yellow' }
        'NoCert'       { 'DarkYellow' }
        'Expired*'     { 'Magenta' }
        'DnsFailure'   { 'Red' }
        'TcpFailure'   { 'Red' }
        default        { 'DarkYellow' }
    }
}

# Compile C# helpers for TLS inspection.
# 1. TlsHelper.AcceptAll — forces SslStream to complete handshake even when cert validation
#    fails (expired, self-signed, name mismatch), so RemoteCertificate is always populated.
# 2. CapturingStream — wraps NetworkStream to record raw bytes flowing through, so we can
#    parse TLS records AFTER the handshake to count server-sent certificates.
# 3. TlsCertCounter.CountFromCapture — parses raw TLS 1.2 records to find the Certificate
#    handshake message (type 0x0B) and counts the DER-encoded certificates inside it.
#    Returns -1 if the Certificate message isn't found (e.g. TLS 1.3 where it's encrypted).
#
# Why we need raw parsing: X509Chain.Build() and the RemoteCertificateValidationCallback's
# chain parameter both use the Windows intermediate CA cache. Once an intermediate is cached
# from ANY prior connection, Build() will include it even if the server didn't send it.
# This makes it impossible to distinguish "leaf only" from "leaf + intermediate" using .NET's
# chain APIs alone. Parsing the raw TLS Certificate message is the only reliable method.
#
# We force TLS 1.2 via SslClientAuthenticationOptions.EnabledSslProtocols so the Certificate
# message is always in cleartext (in TLS 1.3 it's encrypted and unparseable without key material).
if (-not ([System.Management.Automation.PSTypeName]'TlsHelper').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

public static class TlsHelper {
    public static bool AcceptAll(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
        return true;
    }
}

public class CapturingStream : Stream {
    private readonly Stream _inner;
    private readonly List<byte> _buf = new List<byte>(32768);
    public CapturingStream(Stream inner) { _inner = inner; }
    public byte[] GetCaptured() => _buf.ToArray();

    public override int Read(byte[] buffer, int offset, int count) {
        int n = _inner.Read(buffer, offset, count);
        for (int i = 0; i < n; i++) _buf.Add(buffer[offset + i]);
        return n;
    }
    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) {
        int n = await _inner.ReadAsync(buffer, offset, count, ct);
        for (int i = 0; i < n; i++) _buf.Add(buffer[offset + i]);
        return n;
    }
    public override void Write(byte[] b, int o, int c) => _inner.Write(b, o, c);
    public override Task WriteAsync(byte[] b, int o, int c, CancellationToken ct) => _inner.WriteAsync(b, o, c, ct);
    public override void Flush() => _inner.Flush();
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => 0;
    public override long Position { get => 0; set { } }
    public override long Seek(long o, SeekOrigin s) => 0;
    public override void SetLength(long v) { }
}

public static class TlsCertCounter {
    /// <summary>
    /// Parses raw TLS 1.2 bytes to count certificates in the Certificate handshake message.
    /// TLS record: ContentType(1) + Version(2) + Length(2) + Data
    /// Handshake message: Type(1) + Length(3) + Body
    /// Certificate message (type 0x0B): TotalCertsLength(3) + { CertLength(3) + CertData }*
    /// Returns certificate count, or -1 if Certificate message not found.
    /// </summary>
    public static int CountFromCapture(byte[] data) {
        int pos = 0;
        while (pos + 5 <= data.Length) {
            byte contentType = data[pos];
            int recordLen = (data[pos + 3] << 8) | data[pos + 4];
            if (pos + 5 + recordLen > data.Length) break;

            if (contentType == 22) { // Handshake record
                int h = pos + 5, hEnd = h + recordLen;
                while (h + 4 <= hEnd) {
                    byte hsType = data[h];
                    int hsLen = (data[h+1] << 16) | (data[h+2] << 8) | data[h+3];
                    if (h + 4 + hsLen > data.Length) break;

                    if (hsType == 11) { // Certificate message
                        if (h + 7 > data.Length) return -1;
                        int certsLen = (data[h+4] << 16) | (data[h+5] << 8) | data[h+6];
                        int cp = h + 7, ce = cp + certsLen, count = 0;
                        while (cp + 3 <= ce && cp + 3 <= data.Length) {
                            int certLen = (data[cp] << 16) | (data[cp+1] << 8) | data[cp+2];
                            if (cp + 3 + certLen > data.Length) break;
                            count++;
                            cp += 3 + certLen;
                        }
                        return count;
                    }
                    h += 4 + hsLen;
                }
            }
            pos += 5 + recordLen;
        }
        return -1; // Certificate message not found (TLS 1.3 encrypted, or parse failure)
    }
}
'@
}

# ── 1. Acquire Bearer token (single Az.Accounts call) ────────────────────
Write-Host '[ 1/6 ] Acquiring Bearer token via Az.Accounts...' -ForegroundColor Cyan
$tokenInfo = Get-ArmBearerToken
$token     = $tokenInfo.Token
$headers   = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
$contextLabel = if ($tokenInfo.Context.Subscription.Name) {
    $tokenInfo.Context.Subscription.Name
}
else {
    $tokenInfo.Context.Subscription.Id
}
Write-Host "        Token acquired for $contextLabel" -ForegroundColor Green

# ── 2. Parse input CSV ───────────────────────────────────────────────────
Write-Host '[ 2/6 ] Parsing input CSV...' -ForegroundColor Cyan
if (-not (Test-Path -LiteralPath $InputCsvPath)) { throw "File not found: $InputCsvPath" }

$csvRows = Import-Csv -LiteralPath $InputCsvPath
$targets = @(
    foreach ($row in $csvRows) {
        $subName = $row.'Subscription Name'
        $subId   = $row.'Subscription ID'
        $rawIds  = $row.'Profile ID(s)'
        if ([string]::IsNullOrWhiteSpace($subId) -or [string]::IsNullOrWhiteSpace($rawIds)) { continue }

        foreach ($name in ($rawIds -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            [pscustomobject]@{
                SubscriptionName = $subName
                SubscriptionId   = $subId
                ProfileName      = $name
            }
        }
    }
)
$targets = @($targets | Sort-Object SubscriptionId, ProfileName -Unique)
Write-Host "        $($targets.Count) profile(s) to scan." -ForegroundColor Green

# ── 3. Resolve resource groups via Resource Graph (single REST call) ─────
Write-Host '[ 3/6 ] Resolving resource groups via Resource Graph...' -ForegroundColor Cyan

$subIds       = @($targets | ForEach-Object { $_.SubscriptionId } | Sort-Object -Unique)
$profNames    = @($targets | ForEach-Object { $_.ProfileName }    | Sort-Object -Unique)
$quotedProfs  = ($profNames | ForEach-Object { "'$_'" }) -join ','
$quotedSubs   = ($subIds    | ForEach-Object { "'$_'" }) -join ','

$kql  = "resources | where type =~ 'microsoft.cdn/profiles' | where subscriptionId in~ ($quotedSubs) | where name in~ ($quotedProfs) | project subscriptionId, resourceGroup, name"
$body = @{ subscriptions = $subIds; query = $kql; options = @{ resultFormat = 'objectArray' } } | ConvertTo-Json -Depth 4

$graphUri = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'
$graphRes = Invoke-RestMethod -Uri $graphUri -Method Post -Headers $headers -Body $body

$rgLookup = @{}
foreach ($r in @($graphRes.data)) {
    $rgLookup["$($r.subscriptionId)|$($r.name)".ToLowerInvariant()] = $r.resourceGroup
}

# Enrich targets
$resolved = @(
    foreach ($t in $targets) {
        $rg = $rgLookup["$($t.SubscriptionId)|$($t.ProfileName)".ToLowerInvariant()]
        if (-not $rg) { throw "Cannot resolve RG for profile '$($t.ProfileName)' in sub '$($t.SubscriptionId)'." }

        Write-Host "        $($t.ProfileName) -> RG: $rg" -ForegroundColor DarkGray
        [pscustomobject]@{
            SubscriptionName = $t.SubscriptionName
            SubscriptionId   = $t.SubscriptionId
            ProfileName      = $t.ProfileName
            ResourceGroup    = $rg
        }
    }
)

# ── 4. Enumerate origin groups + origins in parallel ─────────────────────
Write-Host "[ 4/6 ] Enumerating origin groups across $($resolved.Count) profiles (parallel=$ThrottleLimit)..." -ForegroundColor Cyan

$originGroups = $resolved | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
    $profile = $_
    $hdrs    = $using:headers
    $apiVer  = $using:apiVersion
    $base    = "https://management.azure.com/subscriptions/$($profile.SubscriptionId)/resourceGroups/$($profile.ResourceGroup)/providers/Microsoft.Cdn/profiles/$($profile.ProfileName)"

    $ogResp = Invoke-RestMethod -Uri "${base}/originGroups?api-version=${apiVer}" -Headers $hdrs
    $ogs    = @($ogResp.value)
    Write-Host "  $($profile.ProfileName): $($ogs.Count) origin group(s)" -ForegroundColor Yellow

    foreach ($og in $ogs) {
        [pscustomobject]@{
            SubscriptionName = $profile.SubscriptionName
            SubscriptionId   = $profile.SubscriptionId
            ProfileName      = $profile.ProfileName
            ResourceGroup    = $profile.ResourceGroup
            OriginGroupName  = $og.name
        }
    }
}
$originGroups = @($originGroups)

Write-Host "        $($originGroups.Count) origin group(s) discovered. Fetching origins..." -ForegroundColor Green

$allRecords = $originGroups | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
    $group  = $_
    $hdrs   = $using:headers
    $apiVer = $using:apiVersion
    $uri    = "https://management.azure.com/subscriptions/$($group.SubscriptionId)/resourceGroups/$($group.ResourceGroup)/providers/Microsoft.Cdn/profiles/$($group.ProfileName)/originGroups/$($group.OriginGroupName)/origins?api-version=${apiVer}"

    $orResp  = Invoke-RestMethod -Uri $uri -Headers $hdrs
    $origins = @($orResp.value)
    Write-Host "    $($group.ProfileName)/$($group.OriginGroupName): $($origins.Count) origin(s)" -ForegroundColor DarkYellow

    foreach ($origin in $origins) {
        [pscustomobject]@{
            SubscriptionName     = $group.SubscriptionName
            SubscriptionId       = $group.SubscriptionId
            ProfileName          = $group.ProfileName
            ResourceGroup        = $group.ResourceGroup
            OriginGroupName      = $group.OriginGroupName
            OriginName           = $origin.name
            HostName             = $origin.properties.hostName
            OriginHostHeader     = $origin.properties.originHostHeader
            EnabledState         = $origin.properties.enabledState
            HttpPort             = $origin.properties.httpPort
            HttpsPort            = $origin.properties.httpsPort
            Priority             = $origin.properties.priority
            Weight               = $origin.properties.weight
            CertNameCheck        = $origin.properties.enforceCertificateNameCheck
        }
    }
}
$allRecords = @($allRecords)

# ── 5. TLS connectivity test ──────────────────────────────────────────────
# Build unique test targets as (ConnectTo, SniName) pairs.
# When HostName is an IP, we connect to the IP but use OriginHostHeader as SNI.
# When OriginHostHeader differs from HostName (even for FQDNs), prefer OriginHostHeader as SNI.
# This correctly tests what AFD actually does: connect to the origin, present the FQDN via SNI.
$tlsTargets = @($allRecords | Where-Object { $_.HostName } | ForEach-Object {
    $connectTo = $_.HostName
    $sniName   = if ($_.OriginHostHeader -and $_.OriginHostHeader -ne '') { $_.OriginHostHeader } else { $_.HostName }
    [pscustomobject]@{ ConnectTo = $connectTo; SniName = $sniName }
} | Sort-Object ConnectTo, SniName -Unique)

if ($SkipTls) {
    Write-Host "[ 5/6 ] TLS testing SKIPPED (-SkipTls)." -ForegroundColor Yellow
    $tlsLookup = @{}
    foreach ($t in $tlsTargets) { $tlsLookup["$($t.ConnectTo)|$($t.SniName)"] = 'Skipped' }
}
else {
    Write-Host "[ 5/6 ] Testing TLS on $($tlsTargets.Count) distinct (origin, SNI) target(s) (parallel=$TlsThrottleLimit, timeout=${TlsTimeoutMs}ms)..." -ForegroundColor Cyan

    $tlsResults = $tlsTargets | ForEach-Object -ThrottleLimit $TlsThrottleLimit -Parallel {
        $connectTo = $_.ConnectTo
        $sniName   = $_.SniName
        $timeoutMs = $using:TlsTimeoutMs
        $parsedIp  = $null
        $isIp      = [System.Net.IPAddress]::TryParse($connectTo, [ref]$parsedIp)
        $dnsResult = $null

        try {
            # 1. DNS resolution (skip for raw IPs)
            if (-not $isIp) {
                $dnsResult = [System.Net.Dns]::GetHostAddresses($connectTo)
                if (-not $dnsResult -or $dnsResult.Count -eq 0) {
                    $status = 'DnsFailure'
                    Write-Host "    $connectTo (SNI=$sniName) -> $status" -ForegroundColor Red
                    [pscustomobject]@{ ConnectTo = $connectTo; SniName = $sniName; TlsStatus = $status }
                    return
                }
            }

            # 2. TCP connect to port 443
            $tcp = [System.Net.Sockets.TcpClient]::new()
            try {
                $connectTask = if ($isIp) {
                    $tcp.ConnectAsync($parsedIp, 443)
                }
                else {
                    $tcp.ConnectAsync($dnsResult, 443)
                }
                if (-not $connectTask.Wait($timeoutMs)) {
                    $status = 'TcpFailure'
                    Write-Host "    $connectTo (SNI=$sniName) -> $status" -ForegroundColor Red
                    [pscustomobject]@{ ConnectTo = $connectTo; SniName = $sniName; TlsStatus = $status }
                    return
                }
                if ($connectTask.IsFaulted) {
                    $status = 'TcpFailure'
                    Write-Host "    $connectTo (SNI=$sniName) -> $status" -ForegroundColor Red
                    [pscustomobject]@{ ConnectTo = $connectTo; SniName = $sniName; TlsStatus = $status }
                    return
                }

                # 3. TLS handshake using SniName (the FQDN) — NOT the raw IP.
                #    Wrap NetworkStream in CapturingStream to record raw TLS bytes,
                #    then parse the TLS 1.2 Certificate message to count server-sent certs.
                #    Force TLS 1.2 so the Certificate message is in cleartext (TLS 1.3 encrypts it).
                $callback   = [System.Net.Security.RemoteCertificateValidationCallback]([TlsHelper]::AcceptAll)
                $capStream  = [CapturingStream]::new($tcp.GetStream())
                $sslStream  = [System.Net.Security.SslStream]::new($capStream, $false, $callback)
                $sslOptions = [System.Net.Security.SslClientAuthenticationOptions]@{
                    TargetHost                          = $sniName
                    EnabledSslProtocols                 = [System.Security.Authentication.SslProtocols]::Tls12
                    RemoteCertificateValidationCallback = $callback
                }
                try {
                    $authTask = $sslStream.AuthenticateAsClientAsync($sslOptions)
                    if (-not $authTask.Wait($timeoutMs)) {
                        $status = 'TlsError: Timeout'
                        Write-Host "    $connectTo (SNI=$sniName) -> $status" -ForegroundColor DarkYellow
                        [pscustomobject]@{ ConnectTo = $connectTo; SniName = $sniName; TlsStatus = $status }
                        return
                    }
                }
                catch {
                    # AcceptAll handles cert errors; protocol errors may still throw.
                    # Fall through — raw bytes are captured regardless.
                }

                # Parse raw TLS bytes to count certificates the server actually sent
                $rawBytes  = $capStream.GetCaptured()
                $rawCount  = [TlsCertCounter]::CountFromCapture($rawBytes)

                # Check leaf certificate expiry via SslStream.RemoteCertificate
                $leafExpired = $false
                $remoteCert  = $sslStream.RemoteCertificate
                if ($remoteCert) {
                    try {
                        $cert2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($remoteCert)
                        $leafExpired = $cert2.NotAfter -lt [DateTime]::UtcNow
                    } catch {}
                }

                if ($rawCount -ge 3) {
                    $status = if ($leafExpired) { 'ExpiredFullChain' } else { 'FullChain' }
                }
                elseif ($rawCount -eq 2) {
                    $status = if ($leafExpired) { 'ExpiredPartialChain' } else { 'PartialChain' }
                }
                elseif ($rawCount -eq 1) {
                    $status = if ($leafExpired) { 'ExpiredNoChain' } else { 'NoChain' }
                }
                elseif ($rawCount -eq 0) {
                    $status = 'NoCert'
                }
                else {
                    # -1 = Certificate message not found (shouldn't happen with forced TLS 1.2)
                    $status = 'TlsError: CertMsgNotFound'
                }

                $sslStream.Dispose()
            }
            finally {
                $tcp.Dispose()
            }
        }
        catch {
            $innerMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            if ($innerMsg -match 'No such host|could not be resolved|HostNotFound|name or service not known') {
                $status = 'DnsFailure'
            }
            elseif ($innerMsg -match 'refused|No connection|unreachable|TimedOut|timed out') {
                $status = 'TcpFailure'
            }
            else {
                $trimmed = $innerMsg.Substring(0, [Math]::Min($innerMsg.Length, 120))
                $status = "TlsError: $trimmed"
            }
        }

        # Color per status (inline — functions aren't available inside -Parallel runspaces)
        $color = switch -Wildcard ($status) {
            'FullChain'    { 'Green' }
            'PartialChain' { 'Green' }
            'NoChain'      { 'Yellow' }
            'NoCert'       { 'DarkYellow' }
            'Expired*'     { 'Magenta' }
            'DnsFailure'   { 'Red' }
            'TcpFailure'   { 'Red' }
            default        { 'DarkYellow' }
        }
        $label = if ($connectTo -ne $sniName) { "$connectTo (SNI=$sniName)" } else { $connectTo }
        Write-Host "    $label -> $status" -ForegroundColor $color

        [pscustomobject]@{ ConnectTo = $connectTo; SniName = $sniName; TlsStatus = $status }
    }

    $tlsLookup = @{}
    foreach ($r in @($tlsResults)) { $tlsLookup["$($r.ConnectTo)|$($r.SniName)"] = $r.TlsStatus }
}

# Add TlsStatus column to every origin row, keyed on (HostName, OriginHostHeader)
foreach ($rec in $allRecords) {
    $sni = if ($rec.OriginHostHeader -and $rec.OriginHostHeader -ne '') { $rec.OriginHostHeader } else { $rec.HostName }
    $key = "$($rec.HostName)|$sni"
    $rec | Add-Member -NotePropertyName 'TlsStatus' -NotePropertyValue ($tlsLookup[$key] ?? 'N/A') -Force
}

# ── 6. Export CSV and summarize ──────────────────────────────────────────
Write-Host "[ 6/6 ] Exporting results..." -ForegroundColor Cyan

$allRecords | Export-Csv -LiteralPath $OutputCsvPath -NoTypeInformation -Encoding utf8

$distinctByKey  = @($allRecords | Sort-Object SubscriptionId, ProfileName, OriginGroupName, OriginName -Unique)
$distinctByHost = @($allRecords | Where-Object { $_.HostName } | Sort-Object HostName -Unique)

Write-Host ''
Write-Host '================================================================' -ForegroundColor Green
Write-Host '  RESULTS' -ForegroundColor Green
Write-Host '================================================================' -ForegroundColor Green
Write-Host "  Profiles scanned       : $($resolved.Count)"
Write-Host "  Total origin records   : $($allRecords.Count)"
Write-Host "  Distinct origins (key) : $($distinctByKey.Count)"
Write-Host "  Distinct hostnames     : $($distinctByHost.Count)"
Write-Host "  Output CSV             : $OutputCsvPath"

Write-Host "  TLS test targets       : $($tlsTargets.Count)"

$scriptStopwatch.Stop()
$elapsed = $scriptStopwatch.Elapsed
Write-Host ("  Total execution time   : {0:hh\:mm\:ss} ({1:n1}s)" -f $elapsed, $elapsed.TotalSeconds)

if (-not $SkipTls) {
    # Group by unique (HostName, OriginHostHeader) test target
    $tlsGroupData = $allRecords | ForEach-Object {
        $sni = if ($_.OriginHostHeader -and $_.OriginHostHeader -ne '') { $_.OriginHostHeader } else { $_.HostName }
        [pscustomobject]@{ Key = "$($_.HostName)|$sni"; TlsStatus = $_.TlsStatus }
    } | Sort-Object Key -Unique
    $tlsGroups = $tlsGroupData | Group-Object TlsStatus
    Write-Host ''
    Write-Host '  TLS Status breakdown (by distinct origin+SNI target):' -ForegroundColor Cyan
    foreach ($g in ($tlsGroups | Sort-Object Name)) {
        Write-Host ("    {0,-25} : {1}" -f $g.Name, $g.Count) -ForegroundColor (Get-TlsStatusColor $g.Name)
    }
}

Write-Host '================================================================' -ForegroundColor Green

Write-Host "`n  Per-profile breakdown:" -ForegroundColor Cyan
$allRecords | Group-Object ProfileName | Sort-Object Name | ForEach-Object {
    $uniqueHosts = @($_.Group | Where-Object { $_.HostName } | Select-Object -ExpandProperty HostName -Unique).Count
    Write-Host "    $($_.Name): $($_.Count) origin(s), $uniqueHosts distinct host(s)"
}

Write-Host "`nDone." -ForegroundColor Green
