#requires -Version 7.0
<#
.SYNOPSIS
    Enumerates all accessible Azure Front Door Standard/Premium and Classic origins and evaluates
    the TLS certificate chain each distinct origin endpoint presents.

.DESCRIPTION
    1. Requires PowerShell 7+ and the Az.Accounts module.
    2. Acquires one Azure management-plane bearer token via Az.Accounts only.
    3. Uses Azure Resource Graph to discover accessible Front Door Standard/Premium and
       Classic profiles across enabled subscriptions.
    4. Enumerates Standard/Premium origin groups/origins plus Classic backend pools/backends
       via ARM REST in parallel.
    5. Resolves every distinct origin target to IP addresses and maps public IPs back to
       Azure resources when possible.
    6. Tests distinct (HostName, HttpsPort, OriginHostHeader) TLS targets in parallel.
    7. Forces TLS 1.2 and parses the raw TLS Certificate message so chain counts reflect
       what the server actually sent.
    8. Adds DigiCert-issued detection from the leaf certificate issuer.
    9. Always exports CSV and, when ImportExcel is available, also exports a companion
       XLSX workbook as a formatted table without banded rows.

    TlsStatus values:
      FullChain             - Server sent 3 or more certificates.
      ExpiredFullChain      - Same as FullChain, but the leaf certificate is expired.
      PartialChain          - Server sent exactly 2 certificates.
      ExpiredPartialChain   - Same as PartialChain, but the leaf certificate is expired.
      NoChain               - Server sent exactly 1 certificate.
      ExpiredNoChain        - Same as NoChain, but the leaf certificate is expired.
      NoCert                - Server sent a TLS Certificate message with no certificates.
      Skipped               - TLS probing was skipped with -SkipTls.
      DnsFailure[: <msg>]   - The origin hostname could not be resolved.
      <code> (<name>)       - TCP connect failed. Example: '10060 (TimedOut)'.
      TlsError: <message>   - TCP connected but the TLS handshake failed.

.PARAMETER OutputCsvPath
    Output CSV path. If omitted, a timestamped file is created in the current directory.

.PARAMETER ThrottleLimit
    Parallelism for ARM origin-group and origin enumeration. Defaults to a PowerShell 7-
    friendly value derived from processor count and capped to avoid runaway fan-out.

.PARAMETER TlsThrottleLimit
    Parallelism for TLS checks. Defaults to a higher processor-count-based value because
    TLS probing is network-bound.

.PARAMETER TlsTimeoutMs
    Timeout in milliseconds for TCP and TLS operations. Default: 5000.

.PARAMETER SkipTls
    Enumerate origins plus resolved-IP metadata and skip TLS probing.

.EXAMPLE
    .\Get-AFDOriginCertChains.ps1

.EXAMPLE
    .\Get-AFDOriginCertChains.ps1 -OutputCsvPath .\results.csv -ThrottleLimit 32 -TlsThrottleLimit 128

.EXAMPLE
    .\Get-AFDOriginCertChains.ps1 -SkipTls
#>
[CmdletBinding()]
param(
    [string]$OutputCsvPath = (Join-Path (Get-Location) ("afd-impacted-origins-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))),

    [ValidateRange(1, 128)]
    [int]$ThrottleLimit = [Math]::Min([Math]::Max([System.Environment]::ProcessorCount * 4, 16), 64),

    [ValidateRange(1, 512)]
    [int]$TlsThrottleLimit = [Math]::Min([Math]::Max([System.Environment]::ProcessorCount * 16, 64), 256),

    [ValidateRange(1000, 30000)]
    [int]$TlsTimeoutMs = 5000,

    [switch]$SkipTls
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$standardPremiumApiVersion = '2025-04-15'
$classicApiVersion = '2021-06-01'
$totalSteps = 7

# Converts access token values that Az.Accounts may surface as strings or SecureStrings.
function ConvertTo-PlainText {
    param([Parameter(Mandatory)][AllowNull()][object]$Value)

    if ($Value -is [string])       { return $Value }
    if ($Value -is [securestring]) { return ConvertFrom-SecureString -SecureString $Value -AsPlainText }
    throw "ConvertTo-PlainText: unexpected type [$($Value.GetType().FullName)]."
}

# Decodes the payload section of a JWT so the script can surface the token's tenant/user.
function Get-JwtPayload {
    param([Parameter(Mandatory)][string]$Token)

    $segment = ($Token -split '\.')[1]
    if ([string]::IsNullOrWhiteSpace($segment)) { return $null }
    # Base64url -> Base64 with padding.
    $segment = $segment.Replace('-', '+').Replace('_', '/').PadRight([Math]::Ceiling($segment.Length / 4.0) * 4, '=')
    try {
        [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($segment)) | ConvertFrom-Json -ErrorAction Stop
    }
    catch { $null }
}

# Safely reads a property value from any object, returning $null when missing.
# Needed because Set-StrictMode forbids direct access to undefined properties.
function Get-PropValue {
    param([AllowNull()][object]$Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { $prop.Value } else { $null }
}

# Acquires one Azure management-plane token and returns resolved user/tenant metadata.
# Intentionally relies on Az.Accounts / Connect-AzAccount only (no Azure CLI).
function Get-ArmBearerToken {
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context -or -not $context.Account) {
        throw 'No Azure PowerShell context found. Run Connect-AzAccount first.'
    }

    # Handles both older Az (string Token) and newer Az (SecureString AccessToken) shapes.
    $resp  = Get-AzAccessToken -ResourceUrl 'https://management.azure.com' -ErrorAction Stop
    $raw   = (Get-PropValue $resp 'Token') ?? (Get-PropValue $resp 'AccessToken')
    $token = ConvertTo-PlainText -Value $raw
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw 'Failed to acquire an Azure access token from Az.Accounts.'
    }

    $payload  = Get-JwtPayload -Token $token
    $tenantId = (Get-PropValue $payload 'tid') ?? (Get-PropValue $resp 'TenantId') ?? (Get-PropValue $context.Tenant  'Id')
    $userId   = (Get-PropValue $payload 'upn') ?? (Get-PropValue $payload 'unique_name') ?? (Get-PropValue $resp 'UserId') ?? (Get-PropValue $context.Account 'Id')

    [pscustomobject]@{
        Token    = $token
        TenantId = if ([string]::IsNullOrWhiteSpace([string]$tenantId)) { $null } else { [string]$tenantId }
        UserId   = if ([string]::IsNullOrWhiteSpace([string]$userId))   { $null } else { [string]$userId }
    }
}

# Returns every enabled Azure subscription the current identity can enumerate.
function Get-EnabledSubscriptions {
    $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' })
    if (-not $subscriptions) {
        throw 'No enabled Azure subscriptions are accessible for the current identity.'
    }

    return @($subscriptions | Sort-Object Name, Id)
}

# Normalizes the HTTPS port used for probing so blank or invalid values fall back to 443.
function Get-TlsProbePort {
    param([Parameter(Mandatory)][object]$Record)
    $parsed = 0
    if ($null -ne $Record.HttpsPort -and [int]::TryParse([string]$Record.HttpsPort, [ref]$parsed) -and $parsed -gt 0) { $parsed } else { 443 }
}

# Uses OriginHostHeader as SNI when present; otherwise the origin hostname.
function Get-TlsSniName {
    param([Parameter(Mandatory)][object]$Record)
    if ([string]::IsNullOrWhiteSpace($Record.OriginHostHeader)) { $Record.HostName } else { $Record.OriginHostHeader }
}

# Prints a consistent phase banner so long scans remain readable in the console.
function Write-PhaseBanner {
    param(
        [Parameter(Mandatory)]
        [string]$Phase,

        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[ $Phase/$totalSteps ] $Message" -ForegroundColor Cyan
}

# Limits progress chatter by emitting at most about twenty updates for large loops.
function Get-ProgressInterval {
    param([Parameter(Mandatory)][int]$TotalCount)
    if ($TotalCount -le 0) { 1 } else { [Math]::Max([int][Math]::Ceiling($TotalCount / 20.0), 1) }
}

# Executes a Resource Graph query across all target subscriptions and follows skip tokens.
function Invoke-ResourceGraphQueryAllPages {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory)]
        [string]$Query
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $skipToken = $null
    $graphUri = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'

    do {
        $options = @{ resultFormat = 'objectArray'; '$top' = 1000 }
        if ($skipToken) {
            $options['$skipToken'] = $skipToken
        }

        $body = @{
            subscriptions = $SubscriptionIds
            query         = $Query
            options       = $options
        } | ConvertTo-Json -Depth 8

        $response = Invoke-RestMethod -Method Post -Uri $graphUri -Headers $Headers -Body $body -ErrorAction Stop
        foreach ($row in @($response.data)) { $results.Add($row) }
        # ARG may return the continuation token under either name depending on version.
        $skipToken = (Get-PropValue $response '$skipToken') ?? (Get-PropValue $response 'skipToken')
    }
    while ($skipToken)

    @($results)
}

# Normalizes Azure child-resource identifiers (e.g. ipConfigurations) back to the owning
# resource ID. Matches /subscriptions/.../providers/<ns>/<type>/<name> and strips extra child pairs.
function Get-AzureOwningResourceId {
    param([AllowNull()][string]$ResourceId)

    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $null }
    # Capture the first <type>/<name> pair after providers/<ns>/; every subsequent pair is a child.
    if ($ResourceId -match '^(?<owning>/.+?/providers/[^/]+/[^/]+/[^/]+)(/[^/]+/[^/]+)+/?$') {
        return $Matches.owning
    }
    $ResourceId.TrimEnd('/')
}

# Classifies IP literals so the export can distinguish private, public, loopback, and other
# address families before attempting any Azure resource correlation.
function Get-IpAddressKind {
    param([Parameter(Mandatory)][string]$IpAddress)

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($IpAddress, [ref]$parsed)) { return 'InvalidIp' }
    if ([System.Net.IPAddress]::IsLoopback($parsed))                      { return 'Loopback' }

    if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $b = $parsed.GetAddressBytes()
        if ($b[0] -eq 10 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168)) { return 'PrivateIPv4' }
        if ($b[0] -eq 169 -and $b[1] -eq 254)                      { return 'LinkLocalIPv4' }
        if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127)    { return 'CarrierGradeNatIPv4' }
        if ($b[0] -ge 224 -and $b[0] -le 239)                      { return 'MulticastIPv4' }
        if ($b[0] -eq 0)                                           { return 'ReservedIPv4' }
        return 'PublicIPv4'
    }

    if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($parsed.IsIPv6LinkLocal) { return 'LinkLocalIPv6' }
        if ($parsed.IsIPv6Multicast) { return 'MulticastIPv6' }
        if ($parsed.IsIPv6SiteLocal) { return 'SiteLocalIPv6' }
        # fc00::/7 unique-local range.
        if (($parsed.GetAddressBytes()[0] -band 0xFE) -eq 0xFC) { return 'UniqueLocalIPv6' }
        return 'PublicIPv6'
    }

    'UnknownIp'
}

# Batches Azure Resource Graph lookups for resolved public IPs so large scans do not issue
# one ARM/ARG call per origin. ARG allows at most a few hundred literals in an `in~` list,
# so chunk to 200 IPs per query.
function Get-AzurePublicIpResourceLookup {
    param(
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string[]]$SubscriptionIds,
        [AllowEmptyCollection()][string[]]$PublicIpAddresses
    )

    $lookup = @{}
    $ips = @($PublicIpAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if (-not $ips) { return $lookup }

    $chunkSize = 200
    for ($offset = 0; $offset -lt $ips.Count; $offset += $chunkSize) {
        $chunk = @($ips[$offset..([Math]::Min($offset + $chunkSize - 1, $ips.Count - 1))])
        $ipList = ($chunk | ForEach-Object { "'{0}'" -f ($_ -replace "'", "''") }) -join ', '
        $query = @"
resources
| where type =~ 'microsoft.network/publicipaddresses'
| extend ipAddress = tostring(properties.ipAddress)
| where isnotempty(ipAddress)
| where ipAddress in~ ($ipList)
| project ipAddress,
          publicIpResourceId = id,
          ipConfigurationId = tostring(properties.ipConfiguration.id),
          natGatewayId = tostring(properties.natGateway.id),
          linkedPublicIpAddressId = tostring(properties.linkedPublicIpAddress.id),
          privateIpTag = tostring(tags['Private_IP'])
"@

        foreach ($row in @(Invoke-ResourceGraphQueryAllPages -Headers $Headers -SubscriptionIds $SubscriptionIds -Query $query)) {
            $ip = [string]$row.ipAddress
            if ([string]::IsNullOrWhiteSpace($ip)) { continue }

            # Prefer ipConfiguration (VM NIC, AppGW, LB), fall back to NAT gateway then linked PIP.
            $associationSourceId = @([string]$row.ipConfigurationId, [string]$row.natGatewayId, [string]$row.linkedPublicIpAddressId) |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
            $associatedResourceId = Get-AzureOwningResourceId -ResourceId $associationSourceId

            $lookup[$ip] = [pscustomobject]@{
                Kind                 = 'AzurePublicIp'
                ResourceId           = $associatedResourceId ?? [string]$row.publicIpResourceId
                PublicIpResourceId   = [string]$row.publicIpResourceId
                AssociatedResourceId = $associatedResourceId
                PrivateIpTag         = [string]$row.privateIpTag
            }
        }
    }

    $lookup
}

# Builds export-friendly resolved IP metadata: address, kind, and any Azure resource ID.
function Get-ResolvedIpMetadata {
    param(
        [AllowEmptyCollection()][string[]]$IpAddresses,
        [Parameter(Mandatory)][hashtable]$AzurePublicIpLookup
    )

    $addresses = @($IpAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if (-not $addresses) {
        return [pscustomobject]@{ ResolvedAddresses = $null; IpKind = 'DnsFailure'; AzureResourceId = $null; AzurePrivateIpTag = $null }
    }

    $kinds         = [System.Collections.Generic.List[string]]::new()
    $resourceIds   = [System.Collections.Generic.List[string]]::new()
    $privateIpTags = [System.Collections.Generic.List[string]]::new()
    $seenIds       = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seenTags      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($ip in $addresses) {
        if ($AzurePublicIpLookup.ContainsKey($ip)) {
            $entry = $AzurePublicIpLookup[$ip]
            $kinds.Add($entry.Kind)
            if (-not [string]::IsNullOrWhiteSpace($entry.ResourceId) -and $seenIds.Add($entry.ResourceId)) {
                $resourceIds.Add($entry.ResourceId)
            }
            if (-not [string]::IsNullOrWhiteSpace($entry.PrivateIpTag) -and $seenTags.Add($entry.PrivateIpTag)) {
                $privateIpTags.Add($entry.PrivateIpTag)
            }
        }
        else {
            $kinds.Add((Get-IpAddressKind -IpAddress $ip))
        }
    }

    [pscustomobject]@{
        ResolvedAddresses = $addresses -join '; '
        IpKind            = $kinds -join '; '
        AzureResourceId   = if ($resourceIds.Count) { $resourceIds -join '; ' } else { $null }
        AzurePrivateIpTag = if ($privateIpTags.Count) { $privateIpTags -join '; ' } else { $null }
    }
}

# Maps TLS status strings to console colors for the summary breakdown.
# Chain outcomes are categorical; failures carry raw error detail so match them by prefix/shape.
function Get-TlsStatusColor {
    param([Parameter(Mandatory)][string]$TlsStatus)

    switch -Wildcard ($TlsStatus) {
        'FullChain'     { 'Green' }
        'PartialChain'  { 'Green' }
        'NoChain'       { 'Yellow' }
        'NoCert'        { 'DarkYellow' }
        'Expired*'      { 'Magenta' }
        'Skipped'       { 'DarkGray' }
        'DnsFailure*'   { 'Red' }
        'TlsError:*'    { 'Red' }
        default         { 'Red' }   # TCP error code strings like '10060 (TimedOut)' land here.
    }
}

# Writes a consistent TLS status breakdown so row-based and target-based summaries are easy to compare.
function Write-TlsStatusBreakdown {
    param(
        [Parameter(Mandatory)]
        [object[]]$Records,

        [Parameter(Mandatory)]
        [string]$Label
    )

    if (-not $Records -or $Records.Count -eq 0) {
        return
    }

    Write-Host ''
    Write-Host "  TLS status breakdown ($Label):" -ForegroundColor Cyan
    foreach ($group in ($Records | Group-Object TlsStatus | Sort-Object Name)) {
        $statusName = if ([string]::IsNullOrWhiteSpace($group.Name)) { 'N/A' } else { $group.Name }
        Write-Host ("    {0,-25} : {1}" -f $statusName, $group.Count) -ForegroundColor (Get-TlsStatusColor -TlsStatus $statusName)
    }
}

# Export-Excel writes the correct table style and freeze pane metadata when it saves directly,
# but reopening and resaving the workbook through EPPlus in this environment strips that metadata.
# Patch the table XML in place so the workbook keeps Medium2 blue table styling without row banding.
function Set-XlsxTableStyleInfo {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$TableStyleName
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $zip = [System.IO.Compression.ZipFile]::Open($resolvedPath, [System.IO.Compression.ZipArchiveMode]::Update)
    try {
        foreach ($tableEntry in @($zip.Entries | Where-Object { $_.FullName -like 'xl/tables/table*.xml' })) {
            $reader = [System.IO.StreamReader]::new($tableEntry.Open())
            try { $original = $reader.ReadToEnd() } finally { $reader.Dispose() }

            # Rewrite the Table style name and disable column/row banding flags.
            $updated = $original `
                -replace '(<tableStyleInfo\b[^>]*\bname=")[^"]+(")', ('$1{0}$2' -f $TableStyleName) `
                -replace '(showFirstColumn=")[^"]+(")',   '${1}0$2' `
                -replace '(showLastColumn=")[^"]+(")',    '${1}0$2' `
                -replace '(showRowStripes=")[^"]+(")',    '${1}0$2' `
                -replace '(showColumnStripes=")[^"]+(")', '${1}0$2'

            if ($updated -eq $original) { continue }

            $entryPath = $tableEntry.FullName
            $tableEntry.Delete()
            $writer = [System.IO.StreamWriter]::new($zip.CreateEntry($entryPath).Open(), [System.Text.UTF8Encoding]::new($false))
            try { $writer.Write($updated) } finally { $writer.Dispose() }
        }
    }
    finally { $zip.Dispose() }
}

try {
    Import-Module Az.Accounts -ErrorAction Stop
}
catch {
    throw "Az.Accounts is required. Install it with 'Install-Module Az.Accounts -Scope CurrentUser' and sign in with Connect-AzAccount."
}

# Compile helper types once so every parallel runspace can reuse them.
# The parser extracts the raw certificates from the TLS 1.2 Certificate message, which avoids
# false positives from locally cached intermediates that can affect X509Chain-based detection.
if (-not ([System.Management.Automation.PSTypeName]'AfdTlsCaptureParser').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

public static class AfdTlsAcceptAll {
    public static bool Callback(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
        return true;
    }
}

public sealed class AfdCapturingStream : Stream {
    private readonly Stream _inner;
    private readonly List<byte> _buffer = new List<byte>(32768);

    public AfdCapturingStream(Stream inner) {
        _inner = inner;
    }

    public byte[] GetCaptured() {
        return _buffer.ToArray();
    }

    public override int Read(byte[] buffer, int offset, int count) {
        int read = _inner.Read(buffer, offset, count);
        for (int i = 0; i < read; i++) {
            _buffer.Add(buffer[offset + i]);
        }
        return read;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) {
        int read = await _inner.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        for (int i = 0; i < read; i++) {
            _buffer.Add(buffer[offset + i]);
        }
        return read;
    }

    public override void Write(byte[] buffer, int offset, int count) {
        _inner.Write(buffer, offset, count);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) {
        return _inner.WriteAsync(buffer, offset, count, cancellationToken);
    }

    public override void Flush() {
        _inner.Flush();
    }

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => 0;
    public override long Position { get => 0; set { } }
    public override long Seek(long offset, SeekOrigin origin) { return 0; }
    public override void SetLength(long value) { }
}

public static class AfdTlsCaptureParser {
    /// <summary>
    /// Returns the DER-encoded certificates carried by the TLS 1.2 Certificate message.
    /// Returns null when the Certificate message cannot be found.
    /// </summary>
    public static byte[][] ExtractCertificates(byte[] data) {
        int pos = 0;
        while (pos + 5 <= data.Length) {
            byte contentType = data[pos];
            int recordLength = (data[pos + 3] << 8) | data[pos + 4];
            if (pos + 5 + recordLength > data.Length) {
                break;
            }

            if (contentType == 22) {
                int handshakePos = pos + 5;
                int handshakeEnd = handshakePos + recordLength;

                while (handshakePos + 4 <= handshakeEnd) {
                    byte handshakeType = data[handshakePos];
                    int handshakeLength = (data[handshakePos + 1] << 16) | (data[handshakePos + 2] << 8) | data[handshakePos + 3];
                    if (handshakePos + 4 + handshakeLength > data.Length) {
                        break;
                    }

                    if (handshakeType == 11) {
                        if (handshakePos + 7 > data.Length) {
                            return Array.Empty<byte[]>();
                        }

                        int certificateListLength = (data[handshakePos + 4] << 16) | (data[handshakePos + 5] << 8) | data[handshakePos + 6];
                        int certificatePos = handshakePos + 7;
                        int certificateEnd = Math.Min(certificatePos + certificateListLength, data.Length);
                        var certificates = new List<byte[]>();

                        while (certificatePos + 3 <= certificateEnd) {
                            int certificateLength = (data[certificatePos] << 16) | (data[certificatePos + 1] << 8) | data[certificatePos + 2];
                            if (certificatePos + 3 + certificateLength > data.Length) {
                                break;
                            }

                            byte[] certificate = new byte[certificateLength];
                            Buffer.BlockCopy(data, certificatePos + 3, certificate, 0, certificateLength);
                            certificates.Add(certificate);
                            certificatePos += 3 + certificateLength;
                        }

                        return certificates.ToArray();
                    }

                    handshakePos += 4 + handshakeLength;
                }
            }

            pos += 5 + recordLength;
        }

        return null;
    }
}
'@
}

Write-PhaseBanner -Phase '1' -Message 'Acquiring Azure bearer token via Az.Accounts...'
$tokenInfo = Get-ArmBearerToken
$headers = @{ Authorization = "Bearer $($tokenInfo.Token)"; 'Content-Type' = 'application/json' }
$tokenLabelParts = [System.Collections.Generic.List[string]]::new()
if ($tokenInfo.UserId) {
    $tokenLabelParts.Add($tokenInfo.UserId)
}
if ($tokenInfo.TenantId) {
    $tokenLabelParts.Add("tenant $($tokenInfo.TenantId)")
}

if ($tokenLabelParts.Count -gt 0) {
    Write-Host ("        Token acquired for: {0}" -f ($tokenLabelParts -join ' | ')) -ForegroundColor Green
}
else {
    Write-Host '        Token acquired successfully.' -ForegroundColor Green
}

Write-PhaseBanner -Phase '2' -Message 'Resolving enabled subscriptions...'
$subscriptions = Get-EnabledSubscriptions
$subscriptionIds = @($subscriptions | Select-Object -ExpandProperty Id)
$subscriptionLookup = @{}
foreach ($subscription in $subscriptions) {
    $subscriptionLookup[$subscription.Id] = $subscription.Name
}
Write-Host "        $($subscriptions.Count) enabled subscription(s) accessible." -ForegroundColor Green

Write-PhaseBanner -Phase '3' -Message 'Discovering Azure Front Door Standard/Premium and Classic profiles via Resource Graph...'
$profileQuery = @"
resources
| where type in~ ('microsoft.cdn/profiles', 'microsoft.network/frontdoors')
| extend skuName = tostring(sku.name)
| extend deploymentModel = case(type =~ 'microsoft.network/frontdoors', 'Classic', 'Standard/Premium')
| extend normalizedSkuName = case(type =~ 'microsoft.network/frontdoors', 'Classic_AzureFrontDoor', skuName)
| where type =~ 'microsoft.network/frontdoors' or skuName in~ ('Standard_AzureFrontDoor', 'Premium_AzureFrontDoor')
| project resourceType = type, subscriptionId, resourceGroup, profileName = name, profileId = id, skuName = normalizedSkuName, deploymentModel
"@

$profileRows = Invoke-ResourceGraphQueryAllPages -Headers $headers -SubscriptionIds $subscriptionIds -Query $profileQuery
$profiles = @(
    foreach ($row in $profileRows) {
        [pscustomobject]@{
            SubscriptionName = $subscriptionLookup[$row.subscriptionId] ?? $row.subscriptionId
            SubscriptionId   = $row.subscriptionId
            ResourceGroup    = $row.resourceGroup
            ProfileName      = $row.profileName
            ProfileId        = $row.profileId
            ResourceType     = $row.resourceType
            DeploymentModel  = $row.deploymentModel
            SkuName          = $row.skuName
        }
    }
)
$profiles = @($profiles | Sort-Object SubscriptionName, ResourceGroup, ProfileName, ResourceType -Unique)

if (-not $profiles) {
    Write-Host '        No Azure Front Door Standard/Premium or Classic profiles were found in the accessible subscriptions.' -ForegroundColor Yellow
    $scriptStopwatch.Stop()
    return
}

Write-Host "        $($profiles.Count) profile(s) discovered across all subscriptions." -ForegroundColor Green

# Stage 4 is split into two inventory paths:
# - Standard/Premium profiles expose child originGroups/origins resources.
# - Classic profiles expose backendPools/backends directly on the Front Door resource.
# Both paths are normalized into the same origin-record shape before TLS probing.
Write-PhaseBanner -Phase '4' -Message "Enumerating origin groups (parallel=$ThrottleLimit)..."
$standardPremiumProfiles = @($profiles | Where-Object { $_.ResourceType -eq 'microsoft.cdn/profiles' })
$classicProfiles = @($profiles | Where-Object { $_.ResourceType -eq 'microsoft.network/frontdoors' })

$originGroupList = [System.Collections.Generic.List[object]]::new()
$allRecordsList = [System.Collections.Generic.List[object]]::new()

if ($standardPremiumProfiles) {
    $standardOriginGroupInterval = Get-ProgressInterval -TotalCount $standardPremiumProfiles.Count
    $standardOriginGroupCountComplete = 0
    $standardPremiumOriginGroupList = [System.Collections.Generic.List[object]]::new()

    $standardPremiumProfiles | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $profile = $_
        $hdrs = $using:headers
        $apiVer = $using:standardPremiumApiVersion

        # Functions are defined inside the parallel block because runspaces do not inherit helpers.
        # This local helper follows ARM nextLink values so large profiles are fully enumerated.
        function Get-PagedArmCollection {
            param(
                [Parameter(Mandatory)]
                [string]$Uri,

                [Parameter(Mandatory)]
                [hashtable]$Headers
            )

            $items = [System.Collections.Generic.List[object]]::new()
            $nextUri = $Uri
            while ($nextUri) {
                $response = Invoke-RestMethod -Method Get -Uri $nextUri -Headers $Headers -ErrorAction Stop
                foreach ($item in @($response.value)) {
                    $items.Add($item)
                }
                $nextUri = $response.nextLink
            }

            return @($items)
        }

        $baseUri = "https://management.azure.com/subscriptions/$($profile.SubscriptionId)/resourceGroups/$($profile.ResourceGroup)/providers/Microsoft.Cdn/profiles/$($profile.ProfileName)"
        $originGroups = @(Get-PagedArmCollection -Uri "$baseUri/originGroups?api-version=$apiVer" -Headers $hdrs)

        foreach ($originGroup in $originGroups) {
            [pscustomobject]@{
                SubscriptionName = $profile.SubscriptionName
                SubscriptionId   = $profile.SubscriptionId
                ResourceGroup    = $profile.ResourceGroup
                ProfileName      = $profile.ProfileName
                ProfileId        = $profile.ProfileId
                ResourceType     = $profile.ResourceType
                DeploymentModel  = $profile.DeploymentModel
                SkuName          = $profile.SkuName
                OriginGroupName  = $originGroup.name
            }
        }

        [pscustomobject]@{
            __Kind           = 'OriginGroupProgress'
            ProfileName      = $profile.ProfileName
            OriginGroupCount = $originGroups.Count
        }
    } | ForEach-Object {
        if ($_.PSObject.Properties.Match('__Kind').Count -gt 0) {
            $standardOriginGroupCountComplete++
            if (($standardOriginGroupCountComplete % $standardOriginGroupInterval -eq 0) -or ($standardOriginGroupCountComplete -eq $standardPremiumProfiles.Count)) {
                Write-Host ("        Standard/Premium profiles inventoried {0}/{1}; latest {2} -> {3} origin group(s)" -f $standardOriginGroupCountComplete, $standardPremiumProfiles.Count, $_.ProfileName, $_.OriginGroupCount) -ForegroundColor DarkGray
            }
        }
        else {
            $originGroupList.Add($_)
            $standardPremiumOriginGroupList.Add($_)
        }
    }

    Write-Host "        Standard/Premium origin groups discovered: $($standardPremiumOriginGroupList.Count)" -ForegroundColor Green

    if ($standardPremiumOriginGroupList.Count -gt 0) {
        Write-Host "        Enumerating Standard/Premium origins (parallel=$ThrottleLimit)..." -ForegroundColor Cyan
        $originInterval = Get-ProgressInterval -TotalCount $standardPremiumOriginGroupList.Count
        $originGroupsComplete = 0

        $standardPremiumOriginGroupList | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            $group = $_
            $hdrs = $using:headers
            $apiVer = $using:standardPremiumApiVersion

            # This helper mirrors the origin-group pass so origin paging stays correct in each runspace.
            function Get-PagedArmCollection {
                param(
                    [Parameter(Mandatory)]
                    [string]$Uri,

                    [Parameter(Mandatory)]
                    [hashtable]$Headers
                )

                $items = [System.Collections.Generic.List[object]]::new()
                $nextUri = $Uri
                while ($nextUri) {
                    $response = Invoke-RestMethod -Method Get -Uri $nextUri -Headers $Headers -ErrorAction Stop
                    foreach ($item in @($response.value)) {
                        $items.Add($item)
                    }
                    $nextUri = $response.nextLink
                }

                return @($items)
            }

            $uri = "https://management.azure.com/subscriptions/$($group.SubscriptionId)/resourceGroups/$($group.ResourceGroup)/providers/Microsoft.Cdn/profiles/$($group.ProfileName)/originGroups/$($group.OriginGroupName)/origins?api-version=$apiVer"
            $origins = @(Get-PagedArmCollection -Uri $uri -Headers $hdrs)

            foreach ($origin in $origins) {
                [pscustomobject]@{
                    SubscriptionName = $group.SubscriptionName
                    SubscriptionId   = $group.SubscriptionId
                    ResourceGroup    = $group.ResourceGroup
                    ProfileName      = $group.ProfileName
                    ProfileId        = $group.ProfileId
                    ResourceType     = $group.ResourceType
                    DeploymentModel  = $group.DeploymentModel
                    SkuName          = $group.SkuName
                    OriginGroupName  = $group.OriginGroupName
                    OriginName       = $origin.name
                    HostName         = $origin.properties.hostName
                    OriginHostHeader = $origin.properties.originHostHeader
                    EnabledState     = $origin.properties.enabledState
                    HttpPort         = $origin.properties.httpPort
                    HttpsPort        = $origin.properties.httpsPort
                    Priority         = $origin.properties.priority
                    Weight           = $origin.properties.weight
                    CertNameCheck    = $origin.properties.enforceCertificateNameCheck
                }
            }

            [pscustomobject]@{
                __Kind          = 'OriginProgress'
                ProfileName     = $group.ProfileName
                OriginGroupName = $group.OriginGroupName
                OriginCount     = $origins.Count
            }
        } | ForEach-Object {
            if ($_.PSObject.Properties.Match('__Kind').Count -gt 0) {
                $originGroupsComplete++
                if (($originGroupsComplete % $originInterval -eq 0) -or ($originGroupsComplete -eq $standardPremiumOriginGroupList.Count)) {
                    Write-Host ("        Standard/Premium origin groups inventoried {0}/{1}; latest {2}/{3} -> {4} origin(s)" -f $originGroupsComplete, $standardPremiumOriginGroupList.Count, $_.ProfileName, $_.OriginGroupName, $_.OriginCount) -ForegroundColor DarkGray
                }
            }
            else {
                $allRecordsList.Add($_)
            }
        }
    }
}

if ($classicProfiles) {
    Write-Host "        Enumerating Classic backend pools and backends (parallel=$ThrottleLimit)..." -ForegroundColor Cyan
    $classicInterval = Get-ProgressInterval -TotalCount $classicProfiles.Count
    $classicProfilesComplete = 0

    $classicProfiles | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $profile = $_
        $hdrs = $using:headers
        $apiVer = $using:classicApiVersion

        $uri = "https://management.azure.com/subscriptions/$($profile.SubscriptionId)/resourceGroups/$($profile.ResourceGroup)/providers/Microsoft.Network/frontDoors/$($profile.ProfileName)?api-version=$apiVer"
        $frontDoor = Invoke-RestMethod -Method Get -Uri $uri -Headers $hdrs -ErrorAction Stop
        $backendPools = @($frontDoor.properties.backendPools)
        $backendCount = 0

        foreach ($backendPool in $backendPools) {
            [pscustomobject]@{
                SubscriptionName = $profile.SubscriptionName
                SubscriptionId   = $profile.SubscriptionId
                ResourceGroup    = $profile.ResourceGroup
                ProfileName      = $profile.ProfileName
                ProfileId        = $profile.ProfileId
                ResourceType     = $profile.ResourceType
                DeploymentModel  = $profile.DeploymentModel
                SkuName          = $profile.SkuName
                OriginGroupName  = $backendPool.name
            }

            $backendIndex = 0
            foreach ($backend in @($backendPool.properties.backends)) {
                $backendIndex++
                $backendCount++
                $originName = if ([string]::IsNullOrWhiteSpace($backend.address)) {
                    "{0}-backend-{1}" -f $backendPool.name, $backendIndex
                }
                else {
                    $backend.address
                }

                [pscustomobject]@{
                    SubscriptionName = $profile.SubscriptionName
                    SubscriptionId   = $profile.SubscriptionId
                    ResourceGroup    = $profile.ResourceGroup
                    ProfileName      = $profile.ProfileName
                    ProfileId        = $profile.ProfileId
                    ResourceType     = $profile.ResourceType
                    DeploymentModel  = $profile.DeploymentModel
                    SkuName          = $profile.SkuName
                    OriginGroupName  = $backendPool.name
                    OriginName       = $originName
                    HostName         = $backend.address
                    OriginHostHeader = $backend.backendHostHeader
                    EnabledState     = $backend.enabledState
                    HttpPort         = $backend.httpPort
                    HttpsPort        = $backend.httpsPort
                    Priority         = $backend.priority
                    Weight           = $backend.weight
                    CertNameCheck    = $null
                }
            }
        }

        [pscustomobject]@{
            __Kind           = 'ClassicProfileProgress'
            ProfileName      = $profile.ProfileName
            OriginGroupCount = $backendPools.Count
            OriginCount      = $backendCount
        }
    } | ForEach-Object {
        if ($_.PSObject.Properties.Match('__Kind').Count -gt 0) {
            $classicProfilesComplete++
            if (($classicProfilesComplete % $classicInterval -eq 0) -or ($classicProfilesComplete -eq $classicProfiles.Count)) {
                Write-Host ("        Classic profiles inventoried {0}/{1}; latest {2} -> {3} backend pool(s), {4} backend(s)" -f $classicProfilesComplete, $classicProfiles.Count, $_.ProfileName, $_.OriginGroupCount, $_.OriginCount) -ForegroundColor DarkGray
            }
        }
        elseif ($_.PSObject.Properties.Match('HostName').Count -gt 0) {
            $allRecordsList.Add($_)
        }
        else {
            $originGroupList.Add($_)
        }
    }
}

$originGroups = @($originGroupList)

$allRecords = @($allRecordsList)
if (-not $allRecords) {
    Write-Host '        No origins were found under the discovered Front Door profiles.' -ForegroundColor Yellow
    $scriptStopwatch.Stop()
    return
}

Write-Host "        $($originGroups.Count) origin group(s) discovered." -ForegroundColor Green
Write-Host "        $($allRecords.Count) origin record(s) discovered." -ForegroundColor Green

# Build unique network targets as (ConnectTo, Port, SniName) triples.
# Using the configured HTTPS port makes both IP resolution and TLS probing match the actual
# Front Door origin settings.
$tlsTargets = @(
    $allRecords |
        Where-Object { $_.HostName } |
        ForEach-Object {
            [pscustomobject]@{
                ConnectTo = $_.HostName
                Port      = Get-TlsProbePort -Record $_
                SniName   = Get-TlsSniName -Record $_
            }
        } |
        Sort-Object ConnectTo, Port, SniName -Unique
)

$targetResolutionLookup = @{}
if (-not $tlsTargets) {
    Write-PhaseBanner -Phase '5' -Message 'No origin targets were found for IP resolution.'
}
else {
    Write-PhaseBanner -Phase '5' -Message "Resolving IP addresses for $($tlsTargets.Count) distinct target(s) and mapping Azure public IP resources..."
    $resolutionInterval = Get-ProgressInterval -TotalCount $tlsTargets.Count
    $resolutionComplete = 0

    $tlsTargets | ForEach-Object -ThrottleLimit $TlsThrottleLimit -Parallel {
        $target = $_

        # Runspaces do not inherit caller-defined helpers; define the ordering helper locally.
        # Orders addresses IPv4 first, IPv6 second, any other family last, preserving source order
        # within each family and deduplicating by string form.
        function Get-OrderedResolvedAddresses {
            param([Parameter(Mandatory)][System.Net.IPAddress[]]$Addresses)
            $priority = @{
                ([System.Net.Sockets.AddressFamily]::InterNetwork)   = 0
                ([System.Net.Sockets.AddressFamily]::InterNetworkV6) = 1
            }
            @(
                $Addresses |
                    Where-Object { $_ } |
                    Sort-Object -Stable { if ($priority.ContainsKey($_.AddressFamily)) { $priority[$_.AddressFamily] } else { 2 } } |
                    Select-Object -ExpandProperty IPAddressToString -Unique
            )
        }

        $connectTo = $target.ConnectTo
        $port = [int]$target.Port
        $sniName = $target.SniName
        $parsedIp = $null
        $resolvedAddresses = @()
        $resolutionFailure = $null

        try {
            if ([System.Net.IPAddress]::TryParse($connectTo, [ref]$parsedIp)) {
                $resolvedAddresses = @($parsedIp.IPAddressToString)
            }
            else {
                $resolvedAddresses = Get-OrderedResolvedAddresses -Addresses ([System.Net.Dns]::GetHostAddresses($connectTo))
            }
        }
        catch {
            $resolutionFailure = if ($_.Exception.InnerException) {
                $_.Exception.InnerException.Message
            }
            else {
                $_.Exception.Message
            }
        }

        $targetLabel = if ($connectTo -ne $sniName) {
            "{0}:{1} (SNI={2})" -f $connectTo, $port, $sniName
        }
        else {
            "{0}:{1}" -f $connectTo, $port
        }

        [pscustomobject]@{
            ConnectTo          = $connectTo
            Port               = $port
            SniName            = $sniName
            ResolvedAddresses  = @($resolvedAddresses)
            ResolutionFailure  = if ([string]::IsNullOrWhiteSpace($resolutionFailure)) { $null } else { $resolutionFailure.Substring(0, [Math]::Min($resolutionFailure.Length, 200)) }
        }

        [pscustomobject]@{
            __Kind           = 'ResolutionProgress'
            TargetLabel      = $targetLabel
            ResolutionStatus = if ($resolvedAddresses.Count -gt 0) { $resolvedAddresses -join ', ' } else { 'DnsFailure' }
        }
    } | ForEach-Object {
        if ($_.PSObject.Properties.Match('__Kind').Count -gt 0) {
            $resolutionComplete++
            if (($resolutionComplete % $resolutionInterval -eq 0) -or ($resolutionComplete -eq $tlsTargets.Count)) {
                Write-Host ("        IP resolution complete {0}/{1}; latest {2} -> {3}" -f $resolutionComplete, $tlsTargets.Count, $_.TargetLabel, $_.ResolutionStatus) -ForegroundColor DarkGray
            }
        }
        else {
            $targetResolutionLookup["$($_.ConnectTo)|$($_.Port)|$($_.SniName)"] = $_
        }
    }

    $resolvedPublicIpAddresses = @(
        $targetResolutionLookup.Values |
            ForEach-Object { @($_.ResolvedAddresses) } |
            Where-Object { (Get-IpAddressKind -IpAddress $_) -like 'Public*' } |
            Sort-Object -Unique
    )

    $azurePublicIpLookup = @{}
    if ($resolvedPublicIpAddresses.Count -gt 0) {
        try {
            $azurePublicIpLookup = Get-AzurePublicIpResourceLookup -Headers $headers -SubscriptionIds $subscriptionIds -PublicIpAddresses $resolvedPublicIpAddresses
        }
        catch {
            Write-Warning ("Azure public IP lookup failed. Resolved IPs will still be classified, but Azure resource IDs will be omitted. {0}" -f $_.Exception.Message)
            $azurePublicIpLookup = @{}
        }
    }

    foreach ($lookupKey in @($targetResolutionLookup.Keys)) {
        $resolutionResult = $targetResolutionLookup[$lookupKey]
        $resolvedIpMetadata = Get-ResolvedIpMetadata -IpAddresses @($resolutionResult.ResolvedAddresses) -AzurePublicIpLookup $azurePublicIpLookup

        $resolutionResult | Add-Member -NotePropertyName ResolvedAddressesText -NotePropertyValue $resolvedIpMetadata.ResolvedAddresses -Force
        $resolutionResult | Add-Member -NotePropertyName IpKind -NotePropertyValue $resolvedIpMetadata.IpKind -Force
        $resolutionResult | Add-Member -NotePropertyName AzureResourceId -NotePropertyValue $resolvedIpMetadata.AzureResourceId -Force
        $resolutionResult | Add-Member -NotePropertyName AzurePrivateIpTag -NotePropertyValue $resolvedIpMetadata.AzurePrivateIpTag -Force
    }

    $resolvedIpCount = @(
        $targetResolutionLookup.Values |
            ForEach-Object { @($_.ResolvedAddresses) } |
            Sort-Object -Unique
    ).Count
    $matchedAzurePublicIpCount = @(
        $targetResolutionLookup.Values |
            ForEach-Object { @($_.ResolvedAddresses) } |
            Where-Object { $azurePublicIpLookup.ContainsKey($_) } |
            Sort-Object -Unique
    ).Count
    Write-Host ("        Resolved {0} distinct IP address(es); {1} matched Azure public IP resource(s)." -f $resolvedIpCount, $matchedAzurePublicIpCount) -ForegroundColor Green
}

$tlsLookup = @{}
if ($SkipTls) {
    Write-PhaseBanner -Phase '6' -Message 'Skipping TLS checks (-SkipTls).'
    foreach ($target in $tlsTargets) {
        $tlsLookup["$($target.ConnectTo)|$($target.Port)|$($target.SniName)"] = [pscustomobject]@{
            TlsStatus              = 'Skipped'
            ServerCertificateCount = $null
            DigiCertIssued         = $null
            LeafSubject            = $null
            LeafIssuer             = $null
            LeafNotAfterUtc        = $null
        }
    }
}
elseif (-not $tlsTargets) {
    Write-PhaseBanner -Phase '6' -Message 'No TLS targets were found.'
}
else {
    Write-PhaseBanner -Phase '6' -Message "Testing TLS on $($tlsTargets.Count) distinct target(s) (parallel=$TlsThrottleLimit, timeout=${TlsTimeoutMs}ms)..."
    $tlsInterval = Get-ProgressInterval -TotalCount $tlsTargets.Count
    $tlsComplete = 0

    $tlsProbeTargets = foreach ($target in $tlsTargets) {
        $lookupKey = "$($target.ConnectTo)|$($target.Port)|$($target.SniName)"
        $resolutionResult = $targetResolutionLookup[$lookupKey]

        [pscustomobject]@{
            ConnectTo         = $target.ConnectTo
            Port              = $target.Port
            SniName           = $target.SniName
            ResolvedAddresses = if ($resolutionResult) { @($resolutionResult.ResolvedAddresses) } else { @() }
            ResolutionFailure = if ($resolutionResult) { $resolutionResult.ResolutionFailure } else { $null }
        }
    }

    $tlsProbeTargets | ForEach-Object -ThrottleLimit $TlsThrottleLimit -Parallel {
        $target = $_
        $timeoutMs = $using:TlsTimeoutMs

        # Prefer IPv4 first, then IPv6, and retry timed-out addresses once without letting
        # multi-address hostnames turn one TCP probe into an unbounded wait.
        function Get-OrderedProbeAddresses {
            param([Parameter(Mandatory)][System.Net.IPAddress[]]$Addresses)
            $priority = @{
                ([System.Net.Sockets.AddressFamily]::InterNetwork)   = 0
                ([System.Net.Sockets.AddressFamily]::InterNetworkV6) = 1
            }
            @(
                $Addresses |
                    Where-Object { $_ } |
                    Sort-Object -Stable { if ($priority.ContainsKey($_.AddressFamily)) { $priority[$_.AddressFamily] } else { 2 } } |
                    Group-Object IPAddressToString |
                    ForEach-Object { $_.Group[0] }
            )
        }

        # Walks an exception chain to find the first SocketException, including inside AggregateException.
        function Get-SocketException {
            param([AllowNull()][System.Exception]$Exception)
            while ($Exception) {
                if ($Exception -is [System.Net.Sockets.SocketException]) { return $Exception }
                if ($Exception -is [System.AggregateException]) {
                    foreach ($inner in $Exception.InnerExceptions) {
                        $se = Get-SocketException -Exception $inner
                        if ($se) { return $se }
                    }
                    return $null
                }
                if ($Exception.InnerException -and $Exception.InnerException -ne $Exception) {
                    $Exception = $Exception.InnerException
                    continue
                }
                return $null
            }
            $null
        }

        # Maps a socket error code / message to a coarse failure category used by the CSV.
        function Get-TcpFailureKind {
            param([AllowNull()][string]$SocketErrorName, [AllowNull()][string]$ErrorMessage, [bool]$TimedOut)
            if ($TimedOut) { return 'Timeout' }
            $byName = @{
                ConnectionRefused   = 'Refused'
                ConnectionReset     = 'Reset'
                ConnectionAborted   = 'Aborted'
                HostUnreachable     = 'Unreachable'
                NetworkUnreachable  = 'Unreachable'
                AddressNotAvailable = 'Unreachable'
                TimedOut            = 'Timeout'
            }
            if ($SocketErrorName -and $byName.ContainsKey($SocketErrorName)) { return $byName[$SocketErrorName] }
            if ([string]::IsNullOrWhiteSpace($ErrorMessage)) { return 'Error' }
            switch -Regex ($ErrorMessage) {
                'refused'                               { return 'Refused' }
                'reset'                                 { return 'Reset' }
                'aborted'                               { return 'Aborted' }
                'unreachable|no route|not reachable'    { return 'Unreachable' }
                'TimedOut|timed out'                    { return 'Timeout' }
                default                                 { return 'Error' }
            }
        }

        # Turns a FailureKind into a short fallback label when the raw socket error is not available.
        function Get-TcpStatusFallback {
            param([Parameter(Mandatory)][string]$FailureKind)
            @{
                Timeout     = 'TcpTimeout'
                Refused     = 'TcpRefused'
                Reset       = 'TcpReset'
                Unreachable = 'TcpUnreachable'
                Aborted     = 'TcpAborted'
            }[$FailureKind] ?? 'TcpError'
        }

        # ICMP ping as a lightweight reachability probe when a TCP connection fails.
        function Get-PingDiagnostic {
            param([Parameter(Mandatory)][string]$Target, [Parameter(Mandatory)][int]$TimeoutMs)
            $ping = [System.Net.NetworkInformation.Ping]::new()
            try {
                $reply = $ping.Send($Target, [Math]::Min([Math]::Max([int]($TimeoutMs / 2), 500), 2000))
                [pscustomobject]@{
                    PingStatus  = [string]$reply.Status
                    PingAddress = if ($reply.Address) { $reply.Address.IPAddressToString } else { $null }
                }
            }
            catch { [pscustomobject]@{ PingStatus = 'Error'; PingAddress = $null } }
            finally { $ping.Dispose() }
        }

        # Formats the TCP/TLS connection diagnostic into a single CSV-friendly column.
        function Get-ConnectionDetail {
            param([AllowNull()][object]$SocketErrorCode, [AllowNull()][string]$SocketErrorName, [AllowNull()][string]$ErrorMessage)
            if ($null -ne $SocketErrorCode -and -not [string]::IsNullOrWhiteSpace($SocketErrorName)) { return "{0} ({1})" -f [int]$SocketErrorCode, $SocketErrorName }
            if ($null -ne $SocketErrorCode) { return [string][int]$SocketErrorCode }
            if (-not [string]::IsNullOrWhiteSpace($SocketErrorName)) { return $SocketErrorName }
            if (-not [string]::IsNullOrWhiteSpace($ErrorMessage))   { return $ErrorMessage.Substring(0, [Math]::Min($ErrorMessage.Length, 200)) }
            $null
        }

        # Attempts TCP connect across each address with bounded per-address timeouts, then retries once
        # against only the addresses that actually timed out. This avoids multi-A-record hosts turning a
        # single probe into an unbounded wait while still being resilient to transient SYN drops.
        function Connect-TcpWithRetry {
            param(
                [Parameter(Mandatory)][System.Net.IPAddress[]]$Addresses,
                [Parameter(Mandatory)][int]$Port,
                [Parameter(Mandatory)][int]$TimeoutMs
            )

            $buildResult = {
                param($Client, $TimedOut, $FailureKind, $SeName, $SeCode, $Msg, $Attempts, $Attempted, $Connected)
                [pscustomobject]@{
                    Client             = $Client
                    TimedOut           = $TimedOut
                    FailureKind        = $FailureKind
                    SocketErrorName    = $SeName
                    SocketErrorCode    = $SeCode
                    ErrorMessage       = $Msg
                    AttemptCount       = $Attempts
                    AttemptedAddresses = @($Attempted)
                    ConnectedAddress   = $Connected
                }
            }

            $ordered = @(Get-OrderedProbeAddresses -Addresses $Addresses)
            if (-not $ordered) {
                return & $buildResult $null $false 'Error' $null $null 'No candidate IP addresses were available.' 0 @() $null
            }

            # First attempt uses the caller-supplied budget; the retry attempt uses a larger budget but
            # only runs against addresses that timed out in attempt 1.
            $retryTimeoutMs = [Math]::Min([Math]::Max(($TimeoutMs * 2), ($TimeoutMs + 3000)), 15000)
            $attemptBudgets = if ($retryTimeoutMs -gt $TimeoutMs) { @($TimeoutMs, $retryTimeoutMs) } else { @($TimeoutMs) }

            $sawTimeout = $false
            $lastName   = $null
            $lastCode   = $null
            $lastMsg    = $null
            $retryAddrs = @($ordered)
            $attemptCount = 0
            $attempted    = [System.Collections.Generic.List[string]]::new()
            $seen         = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

            for ($ai = 0; $ai -lt $attemptBudgets.Count; $ai++) {
                $budgetMs = $attemptBudgets[$ai]
                $sw       = [System.Diagnostics.Stopwatch]::StartNew()
                $timedOut = [System.Collections.Generic.List[System.Net.IPAddress]]::new()
                $targets  = if ($ai -eq 0) { @($ordered) } else { @($retryAddrs) }
                if (-not $targets) { break }

                for ($i = 0; $i -lt $targets.Count; $i++) {
                    $addr = $targets[$i]
                    $attemptCount++
                    if ($seen.Add($addr.IPAddressToString)) { $attempted.Add($addr.IPAddressToString) }

                    $remaining = [Math]::Max($budgetMs - [int]$sw.ElapsedMilliseconds, 0)
                    if ($remaining -le 0) {
                        $sawTimeout = $true
                        $lastName = 'TimedOut'; $lastCode = [int][System.Net.Sockets.SocketError]::TimedOut; $lastMsg = 'TCP connect timed out.'
                        break
                    }

                    $perAddrMs = [Math]::Max([int][Math]::Ceiling($remaining / ($targets.Count - $i)), 1)
                    $client = [System.Net.Sockets.TcpClient]::new($addr.AddressFamily)
                    try {
                        $client.NoDelay = $true
                        $task = $client.ConnectAsync($addr, $Port)
                        $completed = $task.Wait($perAddrMs)

                        if ($completed -and -not $task.IsFaulted -and $client.Connected) {
                            return & $buildResult $client $false $null $null $null $null $attemptCount $attempted $addr.IPAddressToString
                        }

                        if (-not $completed) {
                            $sawTimeout = $true
                            $lastName = 'TimedOut'; $lastCode = [int][System.Net.Sockets.SocketError]::TimedOut; $lastMsg = 'TCP connect timed out.'
                            $timedOut.Add($addr)
                        }
                        elseif ($task.IsFaulted -and $task.Exception) {
                            $se = Get-SocketException -Exception $task.Exception
                            $lastName = if ($se) { [string]$se.SocketErrorCode } else { $null }
                            $lastCode = if ($se) { [int]$se.ErrorCode } else { $null }
                            $lastMsg  = if ($task.Exception.InnerException) { $task.Exception.InnerException.Message } else { $task.Exception.Message }
                        }
                        else {
                            $lastMsg = 'TCP connect failed.'
                        }
                    }
                    catch {
                        $se = Get-SocketException -Exception $_.Exception
                        $lastName = if ($se) { [string]$se.SocketErrorCode } else { $null }
                        $lastCode = if ($se) { [int]$se.ErrorCode } else { $null }
                        $lastMsg  = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
                        if ($lastMsg -match 'TimedOut|timed out') { $sawTimeout = $true; $timedOut.Add($addr) }
                    }
                    finally {
                        if ($client -and -not $client.Connected) { try { $client.Dispose() } catch { } }
                    }
                }

                if ($timedOut.Count -eq 0) { break }
                $retryAddrs = @($timedOut)
                # Small back-off between attempts so transient ICMP-throttled paths have a chance to clear.
                if ($ai -lt ($attemptBudgets.Count - 1)) { [System.Threading.Tasks.Task]::Delay(250).Wait() }
            }

            & $buildResult $null $sawTimeout (Get-TcpFailureKind -SocketErrorName $lastName -ErrorMessage $lastMsg -TimedOut:$sawTimeout) $lastName $lastCode $lastMsg $attemptCount $attempted $null
        }

        $connectTo = $target.ConnectTo
        $port = [int]$target.Port
        $sniName = $target.SniName
        $status = $null
        $serverCertificateCount = $null
        $digiCertIssued = $false
        $leafSubject = $null
        $leafIssuer = $null
        $leafNotAfterUtc = $null
        $intermediateSubject = $null
        $intermediateIssuer = $null
        $intermediateNotAfterUtc = $null
        $rootSubject = $null
        $rootIssuer = $null
        $rootNotAfterUtc = $null
        $handshakeFailure = $null
        $leafExpired = $false
        $probeAddresses = $null
        $tcpAttemptedAddresses = $null
        $tcpConnectedAddress = $null
        $tcpSocketErrorName = $null
        $tcpSocketErrorCode = $null
        $pingStatus = $null
        $pingAddress = $null

        $tcpClient = $null
        $capturingStream = $null
        $sslStream = $null
        $fallbackLeafCertificate = $null
        $certificateObjects = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()

        try {
            $probeAddressesList = [System.Collections.Generic.List[System.Net.IPAddress]]::new()
            foreach ($resolvedAddress in @($target.ResolvedAddresses)) {
                $parsedResolvedAddress = $null
                if ([System.Net.IPAddress]::TryParse($resolvedAddress, [ref]$parsedResolvedAddress)) {
                    $probeAddressesList.Add($parsedResolvedAddress)
                }
            }

            if ($probeAddressesList.Count -eq 0) {
                # DNS failed upstream. Use the resolver message when available so the row self-describes.
                $status = if ($target.ResolutionFailure) { 'DnsFailure: ' + $target.ResolutionFailure } else { 'DnsFailure' }
            }
            else {
                $probeAddresses = @($probeAddressesList)
            }

            if (-not $status) {
                $tcpConnectResult = Connect-TcpWithRetry -Addresses $probeAddresses -Port $port -TimeoutMs $timeoutMs
                $tcpClient = $tcpConnectResult.Client
                $tcpAttemptedAddresses = if ($tcpConnectResult.AttemptedAddresses.Count -gt 0) { $tcpConnectResult.AttemptedAddresses -join ', ' } else { $null }
                $tcpConnectedAddress = $tcpConnectResult.ConnectedAddress
                $tcpSocketErrorName = $tcpConnectResult.SocketErrorName
                $tcpSocketErrorCode = $tcpConnectResult.SocketErrorCode

                if (-not $tcpClient) {
                    # Surface the raw error directly in TlsStatus so the CSV column is self-describing
                    # (e.g. '10060 (TimedOut)'). Fall back to a short category when no detail is available.
                    $status = (Get-ConnectionDetail -SocketErrorCode $tcpSocketErrorCode -SocketErrorName $tcpSocketErrorName -ErrorMessage $tcpConnectResult.ErrorMessage) ??
                              (Get-TcpStatusFallback -FailureKind $tcpConnectResult.FailureKind)
                    $pingDiagnostic = Get-PingDiagnostic -Target $connectTo -TimeoutMs $timeoutMs
                    $pingStatus = $pingDiagnostic.PingStatus
                    $pingAddress = $pingDiagnostic.PingAddress
                }
            }

            if (-not $status) {
                $callback = [System.Net.Security.RemoteCertificateValidationCallback]([AfdTlsAcceptAll]::Callback)
                $capturingStream = [AfdCapturingStream]::new($tcpClient.GetStream())
                $sslStream = [System.Net.Security.SslStream]::new($capturingStream, $false, $callback)
                $sslOptions = [System.Net.Security.SslClientAuthenticationOptions]@{
                    TargetHost                          = $sniName
                    EnabledSslProtocols                 = [System.Security.Authentication.SslProtocols]::Tls12
                    RemoteCertificateValidationCallback = $callback
                }

                try {
                    $authenticateTask = $sslStream.AuthenticateAsClientAsync($sslOptions)
                    if (-not $authenticateTask.Wait($timeoutMs)) {
                        $status = 'TlsError: TLS handshake timed out.'
                    }
                }
                catch {
                    $innerMessage = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
                    $handshakeFailure = $innerMessage.Substring(0, [Math]::Min($innerMessage.Length, 120))
                }

                $rawCertificates = [AfdTlsCaptureParser]::ExtractCertificates($capturingStream.GetCaptured())
                if ($null -ne $rawCertificates) {
                    $serverCertificateCount = $rawCertificates.Length

                    foreach ($rawCertificate in $rawCertificates) {
                        try {
                            $certificateObjects.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate))
                        }
                        catch {
                        }
                    }

                    $leafCertificate = $null
                    if ($certificateObjects.Count -gt 0) {
                        $leafCertificate = $certificateObjects[0]
                    }
                    elseif ($sslStream.RemoteCertificate) {
                        $fallbackLeafCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($sslStream.RemoteCertificate)
                        $leafCertificate = $fallbackLeafCertificate
                    }

                    if ($leafCertificate) {
                        $leafSubject = $leafCertificate.Subject
                        $leafIssuer = $leafCertificate.Issuer
                        $leafNotAfterUtc = $leafCertificate.NotAfter.ToUniversalTime()
                        $leafExpired = $leafNotAfterUtc -lt [DateTime]::UtcNow
                        $digiCertIssued = $leafIssuer -match '\bDigiCert\b'
                    }

                    # Intermediate CA cert that signed the leaf (chain position #2).
                    $intermediateCertificate = if ($certificateObjects.Count -ge 2) { $certificateObjects[1] } else { $null }
                    if ($intermediateCertificate) {
                        $intermediateSubject     = $intermediateCertificate.Subject
                        $intermediateIssuer      = $intermediateCertificate.Issuer
                        $intermediateNotAfterUtc = $intermediateCertificate.NotAfter.ToUniversalTime()
                    }

                    $rootCertificate = if ($certificateObjects.Count -ge 3) { $certificateObjects[$certificateObjects.Count - 1] } else { $null }
                    if ($rootCertificate) {
                        $rootSubject = $rootCertificate.Subject
                        $rootIssuer = $rootCertificate.Issuer
                        $rootNotAfterUtc = $rootCertificate.NotAfter.ToUniversalTime()
                    }

                    if ($serverCertificateCount -ge 3) {
                        $status = if ($leafExpired) { 'ExpiredFullChain' } else { 'FullChain' }
                    }
                    elseif ($serverCertificateCount -eq 2) {
                        $status = if ($leafExpired) { 'ExpiredPartialChain' } else { 'PartialChain' }
                    }
                    elseif ($serverCertificateCount -eq 1) {
                        $status = if ($leafExpired) { 'ExpiredNoChain' } else { 'NoChain' }
                    }
                    elseif ($serverCertificateCount -eq 0) {
                        $status = 'NoCert'
                    }
                    elseif (-not $status) {
                        $status = 'TlsError: CertMsgNotFound'
                    }
                }
                elseif (-not $status) {
                    $status = if ($handshakeFailure) { "TlsError: $handshakeFailure" } else { 'TlsError: CertMsgNotFound' }
                }
            }
        }
        catch {
            $socketException = Get-SocketException -Exception $_.Exception
            $innerMessage = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            if ($innerMessage -match 'No such host|could not be resolved|HostNotFound|name or service not known') {
                $status = 'DnsFailure: ' + $innerMessage.Substring(0, [Math]::Min($innerMessage.Length, 200))
            }
            elseif ($innerMessage -match 'refused|reset|aborted|No connection|unreachable|TimedOut|timed out') {
                if (-not $tcpSocketErrorName -and $socketException) { $tcpSocketErrorName = [string]$socketException.SocketErrorCode }
                if (-not $tcpSocketErrorCode -and $socketException) { $tcpSocketErrorCode = [int]$socketException.ErrorCode }
                if (-not $tcpAttemptedAddresses -and $probeAddresses) {
                    $tcpAttemptedAddresses = (@($probeAddresses | ForEach-Object { $_.IPAddressToString }) -join ', ')
                }
                if (-not $pingStatus) {
                    $pingDiagnostic = Get-PingDiagnostic -Target $connectTo -TimeoutMs $timeoutMs
                    $pingStatus = $pingDiagnostic.PingStatus
                    $pingAddress = $pingDiagnostic.PingAddress
                }

                $status = (Get-ConnectionDetail -SocketErrorCode $tcpSocketErrorCode -SocketErrorName $tcpSocketErrorName -ErrorMessage $innerMessage) ??
                          (Get-TcpStatusFallback -FailureKind (Get-TcpFailureKind -SocketErrorName $tcpSocketErrorName -ErrorMessage $innerMessage -TimedOut:$false))
            }
            else {
                $status = 'TlsError: ' + $innerMessage.Substring(0, [Math]::Min($innerMessage.Length, 120))
            }
        }
        finally {
            # Dispose all probe objects in one pass; certificates first, then transport streams, last the socket.
            $disposables = [System.Collections.Generic.List[object]]::new()
            if ($fallbackLeafCertificate) { $disposables.Add($fallbackLeafCertificate) }
            foreach ($cert in $certificateObjects) { $disposables.Add($cert) }
            if ($sslStream)       { $disposables.Add($sslStream) }
            if ($capturingStream) { $disposables.Add($capturingStream) }
            if ($tcpClient)       { $disposables.Add($tcpClient) }
            foreach ($d in $disposables) { try { $d.Dispose() } catch { } }
        }

        $targetLabel = if ($connectTo -ne $sniName) {
            "{0}:{1} (SNI={2})" -f $connectTo, $port, $sniName
        }
        else {
            "{0}:{1}" -f $connectTo, $port
        }

        [pscustomobject]@{
            ConnectTo              = $connectTo
            Port                   = $port
            SniName                = $sniName
            TlsStatus              = $status ?? 'TlsError: Unknown'
            TcpAttemptedAddresses  = $tcpAttemptedAddresses
            TcpConnectedAddress    = $tcpConnectedAddress
            PingStatus             = $pingStatus
            PingAddress            = $pingAddress
            ServerCertificateCount = $serverCertificateCount
            DigiCertIssued         = $digiCertIssued
            LeafSubject            = $leafSubject
            LeafIssuer             = $leafIssuer
            LeafNotAfterUtc        = $leafNotAfterUtc
            IntermediateSubject     = $intermediateSubject
            IntermediateIssuer      = $intermediateIssuer
            IntermediateNotAfterUtc = $intermediateNotAfterUtc
            RootSubject            = $rootSubject
            RootIssuer             = $rootIssuer
            RootNotAfterUtc        = $rootNotAfterUtc
        }

        [pscustomobject]@{
            __Kind      = 'TlsProgress'
            TargetLabel = $targetLabel
            TlsStatus   = $status ?? 'TlsError: Unknown'
        }
    } | ForEach-Object {
        if ($_.PSObject.Properties.Match('__Kind').Count -gt 0) {
            $tlsComplete++
            if (($tlsComplete % $tlsInterval -eq 0) -or ($tlsComplete -eq $tlsTargets.Count)) {
                Write-Host ("        TLS complete {0}/{1}; latest {2} -> {3}" -f $tlsComplete, $tlsTargets.Count, $_.TargetLabel, $_.TlsStatus) -ForegroundColor DarkGray
            }
        }
        else {
            $tlsLookup["$($_.ConnectTo)|$($_.Port)|$($_.SniName)"] = $_
        }
    }
}

# Stamp the resolved-IP details and TLS findings back onto every origin row so the CSV remains
# one row per origin. Missing lookups (e.g. -SkipTls) yield $null for every appended column.
$stampFromResolution = @('ResolvedAddressesText|ResolvedAddresses', 'IpKind', 'AzureResourceId', 'AzurePrivateIpTag')
$stampFromTls        = @(
    'TlsStatus',
    'TcpAttemptedAddresses',  'TcpConnectedAddress',
    'PingStatus',             'PingAddress',
    'ServerCertificateCount', 'DigiCertIssued',
    'LeafSubject',   'LeafIssuer',   'LeafNotAfterUtc',
    'IntermediateSubject', 'IntermediateIssuer', 'IntermediateNotAfterUtc',
    'RootSubject',   'RootIssuer',   'RootNotAfterUtc'
)

foreach ($record in $allRecords) {
    $tlsPort   = Get-TlsProbePort -Record $record
    $sniName   = Get-TlsSniName   -Record $record
    $lookupKey = "$($record.HostName)|$tlsPort|$sniName"
    $resolutionResult = $targetResolutionLookup[$lookupKey]
    $tlsResult        = $tlsLookup[$lookupKey]

    $record | Add-Member -NotePropertyName TlsPort -NotePropertyValue $tlsPort -Force

    foreach ($pair in $stampFromResolution) {
        $parts = $pair -split '\|', 2
        $sourceName = $parts[0]
        $targetName = if ($parts.Count -eq 2) { $parts[1] } else { $parts[0] }
        $record | Add-Member -NotePropertyName $targetName -NotePropertyValue (Get-PropValue $resolutionResult $sourceName) -Force
    }

    $defaultTlsStatus = if ($tlsResult) { $null } else { 'N/A' }
    foreach ($name in $stampFromTls) {
        $value = Get-PropValue $tlsResult $name
        if ($name -eq 'TlsStatus' -and -not $value) { $value = $defaultTlsStatus }
        $record | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force
    }
}

Write-PhaseBanner -Phase '7' -Message 'Exporting results...'
$allRecords = @($allRecords | Sort-Object SubscriptionName, ResourceGroup, ProfileName, OriginGroupName, OriginName, HostName)
$allRecords | Export-Csv -LiteralPath $OutputCsvPath -NoTypeInformation -Encoding utf8

# CSV remains the guaranteed output. When ImportExcel is available, emit a companion workbook
# with the same data as a formatted Excel table so the file is immediately filterable in Excel.
$xlsxOutputPath = [System.IO.Path]::ChangeExtension($OutputCsvPath, '.xlsx')
$xlsxWasExported = $false
$importExcelModule = Get-Module -ListAvailable -Name ImportExcel | Sort-Object Version -Descending | Select-Object -First 1
if ($importExcelModule) {
    try {
        Import-Module $importExcelModule.Path -ErrorAction Stop | Out-Null
        $xlsxTextColumns = @('OriginName', 'HostName', 'OriginHostHeader', 'ResolvedAddresses', 'IpKind', 'AzureResourceId', 'AzurePrivateIpTag', 'TlsStatus', 'TcpAttemptedAddresses', 'TcpConnectedAddress', 'PingAddress')
        $worksheetName = [System.IO.Path]::GetFileNameWithoutExtension($xlsxOutputPath)
        $worksheetName = $worksheetName -replace '[\\/\?\*\[\]:]', '_'
        if ([string]::IsNullOrWhiteSpace($worksheetName)) {
            $worksheetName = 'afd-origins'
        }
        if ($worksheetName.Length -gt 31) {
            $worksheetName = $worksheetName.Substring(0, 31)
        }

        # ImportExcel attempts CurrentCulture numeric parsing on string values by default.
        # Keep host-related columns as literal text so IPv4 addresses are never coerced into numbers.
        $allRecords | Export-Excel -Path $xlsxOutputPath -WorksheetName $worksheetName -TableName Table1 -TableStyle Medium2 -NoNumberConversion $xlsxTextColumns -AutoFilter -AutoSize -FreezeTopRow -ClearSheet | Out-Null
        Set-XlsxTableStyleInfo -Path $xlsxOutputPath -TableStyleName 'TableStyleMedium2'
        $xlsxWasExported = $true
    }
    catch {
        Write-Host "        ImportExcel is installed but XLSX export failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}
else {
    Write-Host '        ImportExcel module not found. Skipping XLSX export and keeping CSV only.' -ForegroundColor DarkYellow
}

$distinctOrigins = @($allRecords | Sort-Object SubscriptionName, ResourceGroup, ProfileName, OriginGroupName, OriginName, HostName -Unique)
$distinctHosts = @($allRecords | Where-Object { $_.HostName } | Sort-Object HostName -Unique)

Write-Host ''
Write-Host '================================================================' -ForegroundColor Green
Write-Host '  RESULTS' -ForegroundColor Green
Write-Host '================================================================' -ForegroundColor Green
Write-Host "  Subscriptions scanned   : $($subscriptions.Count)"
Write-Host "  Profiles scanned        : $($profiles.Count)"
Write-Host "  Origin groups scanned   : $($originGroups.Count)"
Write-Host "  Total origin records    : $($allRecords.Count)"
Write-Host "  Distinct origins        : $($distinctOrigins.Count)"
Write-Host "  Distinct hostnames      : $($distinctHosts.Count)"
Write-Host "  TLS test targets        : $($tlsTargets.Count)"
Write-Host "  Output CSV              : $OutputCsvPath"
if ($xlsxWasExported) {
    Write-Host "  Output XLSX             : $xlsxOutputPath"
}

$scriptStopwatch.Stop()
$elapsed = $scriptStopwatch.Elapsed
Write-Host ("  Total execution time    : {0:hh\:mm\:ss} ({1:n1}s)" -f $elapsed, $elapsed.TotalSeconds)

if (-not $SkipTls -and $tlsLookup.Count -gt 0) {
    Write-TlsStatusBreakdown -Records $allRecords -Label 'by origin records / CSV rows'
    Write-TlsStatusBreakdown -Records @($tlsLookup.Values) -Label 'by distinct TLS targets (HostName+TlsPort+SNI)'

    $digiCertOriginCount = @($allRecords | Where-Object { $_.DigiCertIssued }).Count
    $digiCertTargetCount = @($tlsLookup.Values | Where-Object { $_.DigiCertIssued }).Count
    Write-Host ''
    Write-Host "  DigiCert-issued leaf certs (origin rows)     : $digiCertOriginCount" -ForegroundColor Cyan
    Write-Host "  DigiCert-issued leaf certs (distinct targets): $digiCertTargetCount" -ForegroundColor Cyan
}

Write-Host '================================================================' -ForegroundColor Green

Write-Host "`n  Per-profile breakdown:" -ForegroundColor Cyan
$allRecords | Group-Object ProfileName | Sort-Object Name | ForEach-Object {
    $uniqueTargets = @(
        $_.Group | ForEach-Object {
            $sniName = Get-TlsSniName -Record $_
            "{0}|{1}|{2}" -f $_.HostName, $_.TlsPort, $sniName
        } | Sort-Object -Unique
    ).Count

    Write-Host "    $($_.Name): $($_.Count) origin(s), $uniqueTargets distinct TLS target(s)"
}

Write-Host "`nDone." -ForegroundColor Green
