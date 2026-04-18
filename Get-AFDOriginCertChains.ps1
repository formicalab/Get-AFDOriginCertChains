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
        DnsFailure            - The origin hostname could not be resolved.
        TcpTimeout            - TCP connection attempts timed out after bounded retries.
        TcpRefused            - The remote host actively refused the TCP connection.
        TcpReset              - The remote host reset the TCP connection during setup.
        TcpUnreachable        - The host or network was unreachable for the TCP connection.
        TcpAborted            - The TCP connection attempt was aborted.
        TcpError              - Another TCP failure occurred; inspect ConnectionDetail for the raw error.
      TlsError: Timeout     - TCP connected, but the TLS handshake timed out.
      TlsError: <message>   - TLS failed for another reason.

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

# Converts access token values that Az.Accounts can surface either as strings or SecureStrings.
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

# Decodes the payload section of a JWT so the script can report the actual token tenant.
function Get-JwtPayload {
    param(
        [Parameter(Mandatory)]
        [string]$Token
    )

    $parts = $Token -split '\.'
    if ($parts.Count -lt 2 -or [string]::IsNullOrWhiteSpace($parts[1])) {
        return $null
    }

    $payloadSegment = $parts[1]
    switch ($payloadSegment.Length % 4) {
        2 { $payloadSegment += '==' }
        3 { $payloadSegment += '=' }
        0 { }
        default { return $null }
    }

    try {
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payloadSegment.Replace('-', '+').Replace('_', '/')))
        return $json | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return $null
    }
}

# Acquires one Azure management-plane token and returns resolved user and tenant metadata.
# This script intentionally relies on Az.Accounts / Connect-AzAccount only.
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

    $token = ConvertTo-PlainText -Value $rawToken
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw 'Failed to acquire an Azure access token from Az.Accounts.'
    }

    $tokenPayload = Get-JwtPayload -Token $token
    $tenantId = if ($tokenPayload -and $tokenPayload.PSObject.Properties['tid']) {
        [string]$tokenPayload.tid
    }
    elseif ($tokenResponse.PSObject.Properties['TenantId'] -and $tokenResponse.TenantId) {
        [string]$tokenResponse.TenantId
    }
    elseif ($context.Tenant -and $context.Tenant.Id) {
        [string]$context.Tenant.Id
    }
    else {
        $null
    }

    $userId = if ($tokenPayload -and $tokenPayload.PSObject.Properties['upn'] -and $tokenPayload.upn) {
        [string]$tokenPayload.upn
    }
    elseif ($tokenPayload -and $tokenPayload.PSObject.Properties['unique_name'] -and $tokenPayload.unique_name) {
        [string]$tokenPayload.unique_name
    }
    elseif ($tokenResponse.PSObject.Properties['UserId'] -and $tokenResponse.UserId) {
        [string]$tokenResponse.UserId
    }
    elseif ($context.Account -and $context.Account.Id) {
        [string]$context.Account.Id
    }
    else {
        $null
    }

    return [pscustomobject]@{
        Token    = $token
        TenantId = $tenantId
        UserId   = $userId
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
    param(
        [Parameter(Mandatory)]
        [object]$Record
    )

    $port = 443
    try {
        if ($null -ne $Record.HttpsPort -and [int]$Record.HttpsPort -gt 0) {
            $port = [int]$Record.HttpsPort
        }
    }
    catch {
        $port = 443
    }

    return $port
}

# Uses OriginHostHeader as SNI when present; otherwise the origin hostname.
function Get-TlsSniName {
    param(
        [Parameter(Mandatory)]
        [object]$Record
    )

    if ([string]::IsNullOrWhiteSpace($Record.OriginHostHeader)) {
        return $Record.HostName
    }

    return $Record.OriginHostHeader
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
    param(
        [Parameter(Mandatory)]
        [int]$TotalCount
    )

    if ($TotalCount -le 0) {
        return 1
    }

    return [Math]::Max([int][Math]::Ceiling($TotalCount / 20.0), 1)
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
        foreach ($row in @($response.data)) {
            $results.Add($row)
        }

        $skipToken = $null
        foreach ($propertyName in '$skipToken', 'skipToken') {
            $property = $response.PSObject.Properties[$propertyName]
            if ($property -and $property.Value) {
                $skipToken = [string]$property.Value
                break
            }
        }
    }
    while ($skipToken)

    return @($results)
}

# Normalizes Azure child-resource identifiers such as ipConfigurations back to the owning
# resource ID so public IP associations are easier to interpret in the export.
function Get-AzureOwningResourceId {
    param(
        [AllowNull()]
        [string]$ResourceId
    )

    if ([string]::IsNullOrWhiteSpace($ResourceId)) {
        return $null
    }

    $segments = $ResourceId.Trim().Trim('/') -split '/'
    if ($segments.Count -lt 8) {
        return '/' + ($segments -join '/')
    }

    $providersIndex = -1
    for ($index = 0; $index -lt $segments.Count; $index++) {
        if ($segments[$index] -ieq 'providers') {
            $providersIndex = $index
            break
        }
    }

    if ($providersIndex -lt 0 -or $segments.Count -le ($providersIndex + 3)) {
        return '/' + ($segments -join '/')
    }

    $segmentsAfterProviderNamespace = $segments.Count - ($providersIndex + 2)
    if (($segmentsAfterProviderNamespace % 2) -eq 0 -and $segmentsAfterProviderNamespace -gt 2) {
        $segments = $segments[0..($segments.Count - 3)]
    }

    return '/' + ($segments -join '/')
}

# Classifies IP literals so the export can distinguish private, public, loopback, and other
# address families before attempting any Azure resource correlation.
function Get-IpAddressKind {
    param(
        [Parameter(Mandatory)]
        [string]$IpAddress
    )

    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse($IpAddress, [ref]$parsedIp)) {
        return 'InvalidIp'
    }

    if ([System.Net.IPAddress]::IsLoopback($parsedIp)) {
        return 'Loopback'
    }

    switch ($parsedIp.AddressFamily) {
        ([System.Net.Sockets.AddressFamily]::InterNetwork) {
            $bytes = $parsedIp.GetAddressBytes()

            if (
                $bytes[0] -eq 10 -or
                ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
                ($bytes[0] -eq 192 -and $bytes[1] -eq 168)
            ) {
                return 'PrivateIPv4'
            }

            if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) {
                return 'LinkLocalIPv4'
            }

            if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) {
                return 'CarrierGradeNatIPv4'
            }

            if ($bytes[0] -ge 224 -and $bytes[0] -le 239) {
                return 'MulticastIPv4'
            }

            if ($bytes[0] -eq 0) {
                return 'ReservedIPv4'
            }

            return 'PublicIPv4'
        }

        ([System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            $bytes = $parsedIp.GetAddressBytes()

            if ($parsedIp.IsIPv6LinkLocal) {
                return 'LinkLocalIPv6'
            }

            if ($parsedIp.IsIPv6Multicast) {
                return 'MulticastIPv6'
            }

            if ($parsedIp.IsIPv6SiteLocal) {
                return 'SiteLocalIPv6'
            }

            if (($bytes[0] -band 0xFE) -eq 0xFC) {
                return 'UniqueLocalIPv6'
            }

            return 'PublicIPv6'
        }

        default {
            return 'UnknownIp'
        }
    }
}

# Batches Azure Resource Graph lookups for resolved public IPs so large scans do not issue
# one ARM or ARG call per origin.
function Get-AzurePublicIpResourceLookup {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [string[]]$SubscriptionIds,

        [AllowEmptyCollection()]
        [string[]]$PublicIpAddresses
    )

    $lookup = @{}
    $normalizedIpAddresses = @(
        $PublicIpAddresses |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )

    if (-not $normalizedIpAddresses) {
        return $lookup
    }

    $chunkSize = 200
    for ($offset = 0; $offset -lt $normalizedIpAddresses.Count; $offset += $chunkSize) {
        $chunkEnd = [Math]::Min($offset + $chunkSize - 1, $normalizedIpAddresses.Count - 1)
        $chunk = if ($chunkEnd -eq $offset) {
            @($normalizedIpAddresses[$offset])
        }
        else {
            @($normalizedIpAddresses[$offset..$chunkEnd])
        }

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
          linkedPublicIpAddressId = tostring(properties.linkedPublicIpAddress.id)
"@

        foreach ($row in @(Invoke-ResourceGraphQueryAllPages -Headers $Headers -SubscriptionIds $SubscriptionIds -Query $query)) {
            $ipAddress = [string]$row.ipAddress
            if ([string]::IsNullOrWhiteSpace($ipAddress)) {
                continue
            }

            $associationSourceId = @(
                [string]$row.ipConfigurationId,
                [string]$row.natGatewayId,
                [string]$row.linkedPublicIpAddressId
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1

            $associatedResourceId = Get-AzureOwningResourceId -ResourceId $associationSourceId
            $resourceId = if ($associatedResourceId) {
                $associatedResourceId
            }
            else {
                [string]$row.publicIpResourceId
            }

            $lookup[$ipAddress] = [pscustomobject]@{
                Kind                 = 'AzurePublicIp'
                ResourceId           = $resourceId
                PublicIpResourceId   = [string]$row.publicIpResourceId
                AssociatedResourceId = $associatedResourceId
            }
        }
    }

    return $lookup
}

# Builds export-friendly resolved IP metadata, including separate columns for address, kind,
# and Azure resource ID.
function Get-ResolvedIpMetadata {
    param(
        [AllowEmptyCollection()]
        [string[]]$IpAddresses,

        [Parameter(Mandatory)]
        [hashtable]$AzurePublicIpLookup
    )

    $normalizedIpAddresses = @($IpAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if (-not $normalizedIpAddresses) {
        return [pscustomobject]@{
            ResolvedAddresses = $null
            IpKind            = 'DnsFailure'
            AzureResourceId   = $null
        }
    }

    $resolvedAddresses = [System.Collections.Generic.List[string]]::new()
    $ipKinds = [System.Collections.Generic.List[string]]::new()
    $azureResourceIds = [System.Collections.Generic.List[string]]::new()
    $seenAzureResourceIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($ipAddress in $normalizedIpAddresses) {
        $kind = Get-IpAddressKind -IpAddress $ipAddress
        $resolvedAddresses.Add($ipAddress)

        if ($AzurePublicIpLookup.ContainsKey($ipAddress)) {
            $resolvedKind = $AzurePublicIpLookup[$ipAddress].Kind
            $resourceId = $AzurePublicIpLookup[$ipAddress].ResourceId
            $ipKinds.Add($resolvedKind)

            if (-not [string]::IsNullOrWhiteSpace($resourceId) -and $seenAzureResourceIds.Add($resourceId)) {
                $azureResourceIds.Add($resourceId)
            }
        }
        elseif ($kind -like 'Public*') {
            $ipKinds.Add($kind)
        }
        else {
            $ipKinds.Add($kind)
        }
    }

    return [pscustomobject]@{
        ResolvedAddresses = $resolvedAddresses -join '; '
        IpKind            = $ipKinds -join '; '
        AzureResourceId   = if ($azureResourceIds.Count -gt 0) { $azureResourceIds -join '; ' } else { $null }
    }
}

# Maps TLS status strings to console colors for the summary breakdown.
function Get-TlsStatusColor {
    param(
        [Parameter(Mandatory)]
        [string]$TlsStatus
    )

    switch -Wildcard ($TlsStatus) {
        'FullChain'    { 'Green' }
        'PartialChain' { 'Green' }
        'NoChain'      { 'Yellow' }
        'NoCert'       { 'DarkYellow' }
        'Expired*'     { 'Magenta' }
        'DnsFailure'   { 'Red' }
        'Tcp*'         { 'Red' }
        'Skipped'      { 'DarkGray' }
        default        { 'DarkYellow' }
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
# Patch the table XML in place so the workbook keeps the sample file's Medium2 blue table with no row banding.
function Set-XlsxTableStyleInfo {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$TableStyleName
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $zip = [System.IO.Compression.ZipFile]::Open($resolvedPath, [System.IO.Compression.ZipArchiveMode]::Update)
    try {
        $tableEntries = @($zip.Entries | Where-Object { $_.FullName -like 'xl/tables/table*.xml' })
        foreach ($tableEntry in $tableEntries) {
            $reader = [System.IO.StreamReader]::new($tableEntry.Open())
            try {
                $tableXmlText = [System.String]::Copy($reader.ReadToEnd())
            }
            finally {
                $reader.Dispose()
            }

            $updatedTableXmlText = $tableXmlText
            $updatedTableXmlText = $updatedTableXmlText -replace '(<tableStyleInfo\b[^>]*\bname=")[^"]+(")', ('$1{0}$2' -f $TableStyleName)
            $updatedTableXmlText = $updatedTableXmlText -replace '(showFirstColumn=")[^"]+(")', '${1}0$2'
            $updatedTableXmlText = $updatedTableXmlText -replace '(showLastColumn=")[^"]+(")', '${1}0$2'
            $updatedTableXmlText = $updatedTableXmlText -replace '(showRowStripes=")[^"]+(")', '${1}0$2'
            $updatedTableXmlText = $updatedTableXmlText -replace '(showColumnStripes=")[^"]+(")', '${1}0$2'

            if ($updatedTableXmlText -eq $tableXmlText) {
                continue
            }

            $tableEntryPath = $tableEntry.FullName
            $tableEntry.Delete()
            $newTableEntry = $zip.CreateEntry($tableEntryPath)
            $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
            $writer = [System.IO.StreamWriter]::new($newTableEntry.Open(), $utf8NoBom)
            try {
                $writer.Write($updatedTableXmlText)
            }
            finally {
                $writer.Dispose()
            }
        }
    }
    finally {
        $zip.Dispose()
    }
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

        function Get-OrderedResolvedAddresses {
            param(
                [Parameter(Mandatory)]
                [System.Net.IPAddress[]]$Addresses
            )

            $orderedAddresses = [System.Collections.Generic.List[string]]::new()
            $seenAddresses = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $preferredFamilies = @(
                [System.Net.Sockets.AddressFamily]::InterNetwork,
                [System.Net.Sockets.AddressFamily]::InterNetworkV6
            )

            foreach ($family in $preferredFamilies) {
                foreach ($address in @($Addresses | Where-Object { $_ -and $_.AddressFamily -eq $family })) {
                    if ($seenAddresses.Add($address.IPAddressToString)) {
                        $orderedAddresses.Add($address.IPAddressToString)
                    }
                }
            }

            foreach ($address in @($Addresses | Where-Object { $_ })) {
                if ($seenAddresses.Add($address.IPAddressToString)) {
                    $orderedAddresses.Add($address.IPAddressToString)
                }
            }

            return @($orderedAddresses)
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
            param(
                [Parameter(Mandatory)]
                [System.Net.IPAddress[]]$Addresses
            )

            $orderedAddresses = [System.Collections.Generic.List[System.Net.IPAddress]]::new()
            $seenAddresses = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $preferredFamilies = @(
                [System.Net.Sockets.AddressFamily]::InterNetwork,
                [System.Net.Sockets.AddressFamily]::InterNetworkV6
            )

            foreach ($family in $preferredFamilies) {
                foreach ($address in @($Addresses | Where-Object { $_ -and $_.AddressFamily -eq $family })) {
                    if ($seenAddresses.Add($address.IPAddressToString)) {
                        $orderedAddresses.Add($address)
                    }
                }
            }

            foreach ($address in @($Addresses | Where-Object {
                $_ -and
                $_.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -and
                $_.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6
            })) {
                if ($seenAddresses.Add($address.IPAddressToString)) {
                    $orderedAddresses.Add($address)
                }
            }

            return @($orderedAddresses)
        }

        function Get-SocketException {
            param(
                [AllowNull()]
                [System.Exception]$Exception
            )

            if (-not $Exception) {
                return $null
            }

            if ($Exception -is [System.Net.Sockets.SocketException]) {
                return $Exception
            }

            if ($Exception -is [System.AggregateException]) {
                foreach ($innerException in $Exception.InnerExceptions) {
                    $socketException = Get-SocketException -Exception $innerException
                    if ($socketException) {
                        return $socketException
                    }
                }
            }

            if ($Exception.InnerException -and $Exception.InnerException -ne $Exception) {
                return Get-SocketException -Exception $Exception.InnerException
            }

            return $null
        }

        function Get-TcpFailureKind {
            param(
                [AllowNull()]
                [string]$SocketErrorName,

                [AllowNull()]
                [string]$ErrorMessage,

                [bool]$TimedOut
            )

            if ($TimedOut) {
                return 'Timeout'
            }

            switch ($SocketErrorName) {
                'ConnectionRefused' { return 'Refused' }
                'ConnectionReset' { return 'Reset' }
                'ConnectionAborted' { return 'Aborted' }
                'HostUnreachable' { return 'Unreachable' }
                'NetworkUnreachable' { return 'Unreachable' }
                'AddressNotAvailable' { return 'Unreachable' }
                'TimedOut' { return 'Timeout' }
            }

            if ([string]::IsNullOrWhiteSpace($ErrorMessage)) {
                return 'Error'
            }

            switch -Regex ($ErrorMessage) {
                'refused' { return 'Refused' }
                'reset' { return 'Reset' }
                'aborted' { return 'Aborted' }
                'unreachable|no route|not reachable' { return 'Unreachable' }
                'TimedOut|timed out' { return 'Timeout' }
                default { return 'Error' }
            }
        }

        function Get-TcpStatusFromFailureKind {
            param(
                [Parameter(Mandatory)]
                [string]$FailureKind
            )

            switch ($FailureKind) {
                'Timeout' { return 'TcpTimeout' }
                'Refused' { return 'TcpRefused' }
                'Reset' { return 'TcpReset' }
                'Unreachable' { return 'TcpUnreachable' }
                'Aborted' { return 'TcpAborted' }
                default { return 'TcpError' }
            }
        }

        function Get-PingDiagnostic {
            param(
                [Parameter(Mandatory)]
                [string]$Target,

                [Parameter(Mandatory)]
                [int]$TimeoutMs
            )

            $ping = [System.Net.NetworkInformation.Ping]::new()
            try {
                $pingTimeoutMs = [Math]::Min([Math]::Max([int]($TimeoutMs / 2), 500), 2000)
                $reply = $ping.Send($Target, $pingTimeoutMs)

                return [pscustomobject]@{
                    PingStatus  = [string]$reply.Status
                    PingAddress = if ($reply.Address) { $reply.Address.IPAddressToString } else { $null }
                }
            }
            catch {
                return [pscustomobject]@{
                    PingStatus  = 'Error'
                    PingAddress = $null
                }
            }
            finally {
                $ping.Dispose()
            }
        }

        function Get-ConnectionDetail {
            param(
                [AllowNull()]
                [object]$SocketErrorCode,

                [AllowNull()]
                [string]$SocketErrorName,

                [AllowNull()]
                [string]$ErrorMessage
            )

            if ($null -ne $SocketErrorCode -and -not [string]::IsNullOrWhiteSpace($SocketErrorName)) {
                return "{0} ({1})" -f [int]$SocketErrorCode, $SocketErrorName
            }

            if ($null -ne $SocketErrorCode) {
                return [string][int]$SocketErrorCode
            }

            if (-not [string]::IsNullOrWhiteSpace($SocketErrorName)) {
                return $SocketErrorName
            }

            if (-not [string]::IsNullOrWhiteSpace($ErrorMessage)) {
                return $ErrorMessage.Substring(0, [Math]::Min($ErrorMessage.Length, 200))
            }

            return $null
        }

        function Connect-TcpWithRetry {
            param(
                [Parameter(Mandatory)]
                [System.Net.IPAddress[]]$Addresses,

                [Parameter(Mandatory)]
                [int]$Port,

                [Parameter(Mandatory)]
                [int]$TimeoutMs
            )

            $orderedAddresses = @(Get-OrderedProbeAddresses -Addresses $Addresses)
            if (-not $orderedAddresses) {
                return [pscustomobject]@{
                    Client             = $null
                    TimedOut           = $false
                    FailureKind        = 'Error'
                    SocketErrorName    = $null
                    SocketErrorCode    = $null
                    ErrorMessage       = 'No candidate IP addresses were available.'
                    AttemptCount       = 0
                    AttemptedAddresses = @()
                    ConnectedAddress   = $null
                }
            }

            $attemptBudgets = [System.Collections.Generic.List[int]]::new()
            $attemptBudgets.Add($TimeoutMs)

            $retryTimeoutMs = [Math]::Min([Math]::Max(($TimeoutMs * 2), ($TimeoutMs + 3000)), 15000)
            if ($retryTimeoutMs -gt $TimeoutMs) {
                $attemptBudgets.Add($retryTimeoutMs)
            }

            $lastErrorMessage = $null
            $lastSocketErrorName = $null
            $lastSocketErrorCode = $null
            $sawTimeout = $false
            $retryAddresses = @($orderedAddresses)
            $attemptCount = 0
            $attemptedAddresses = [System.Collections.Generic.List[string]]::new()
            $seenAttemptedAddresses = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

            for ($attemptIndex = 0; $attemptIndex -lt $attemptBudgets.Count; $attemptIndex++) {
                $attemptBudgetMs = $attemptBudgets[$attemptIndex]
                $attemptStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $timedOutAddresses = [System.Collections.Generic.List[System.Net.IPAddress]]::new()
                $addressesForAttempt = if ($attemptIndex -eq 0) { @($orderedAddresses) } else { @($retryAddresses) }

                if (-not $addressesForAttempt) {
                    break
                }

                for ($addressIndex = 0; $addressIndex -lt $addressesForAttempt.Count; $addressIndex++) {
                    $address = $addressesForAttempt[$addressIndex]
                    $attemptCount++
                    $attemptedAddress = $address.IPAddressToString
                    if ($seenAttemptedAddresses.Add($attemptedAddress)) {
                        $attemptedAddresses.Add($attemptedAddress)
                    }

                    $remainingBudgetMs = [Math]::Max($attemptBudgetMs - [int]$attemptStopwatch.ElapsedMilliseconds, 0)
                    if ($remainingBudgetMs -le 0) {
                        $sawTimeout = $true
                        $lastSocketErrorName = 'TimedOut'
                        $lastSocketErrorCode = [int][System.Net.Sockets.SocketError]::TimedOut
                        $lastErrorMessage = 'TCP connect timed out.'
                        break
                    }

                    $remainingAddressCount = $addressesForAttempt.Count - $addressIndex
                    $perAddressTimeoutMs = [Math]::Max([int][Math]::Ceiling($remainingBudgetMs / $remainingAddressCount), 1)

                    $probeClient = [System.Net.Sockets.TcpClient]::new($address.AddressFamily)
                    try {
                        $probeClient.NoDelay = $true
                        $connectTask = $probeClient.ConnectAsync($address, $Port)
                        $completed = $connectTask.Wait($perAddressTimeoutMs)

                        if ($completed -and -not $connectTask.IsFaulted -and $probeClient.Connected) {
                            return [pscustomobject]@{
                                Client             = $probeClient
                                TimedOut           = $false
                                FailureKind        = $null
                                SocketErrorName    = $null
                                SocketErrorCode    = $null
                                ErrorMessage       = $null
                                AttemptCount       = $attemptCount
                                AttemptedAddresses = @($attemptedAddresses)
                                ConnectedAddress   = $address.IPAddressToString
                            }
                        }

                        if (-not $completed) {
                            $sawTimeout = $true
                            $lastSocketErrorName = 'TimedOut'
                            $lastSocketErrorCode = [int][System.Net.Sockets.SocketError]::TimedOut
                            $lastErrorMessage = 'TCP connect timed out.'
                            $timedOutAddresses.Add($address)
                        }
                        elseif ($connectTask.IsFaulted -and $connectTask.Exception) {
                            $socketException = Get-SocketException -Exception $connectTask.Exception
                            $lastSocketErrorName = if ($socketException) { [string]$socketException.SocketErrorCode } else { $null }
                            $lastSocketErrorCode = if ($socketException) { [int]$socketException.ErrorCode } else { $null }
                            $lastErrorMessage = if ($connectTask.Exception.InnerException) {
                                $connectTask.Exception.InnerException.Message
                            }
                            else {
                                $connectTask.Exception.Message
                            }
                        }
                        else {
                            $lastErrorMessage = 'TCP connect failed.'
                        }
                    }
                    catch {
                        $socketException = Get-SocketException -Exception $_.Exception
                        $lastSocketErrorName = if ($socketException) { [string]$socketException.SocketErrorCode } else { $null }
                        $lastSocketErrorCode = if ($socketException) { [int]$socketException.ErrorCode } else { $null }
                        $lastErrorMessage = if ($_.Exception.InnerException) {
                            $_.Exception.InnerException.Message
                        }
                        else {
                            $_.Exception.Message
                        }

                        if ($lastErrorMessage -match 'TimedOut|timed out') {
                            $sawTimeout = $true
                            $timedOutAddresses.Add($address)
                        }
                    }
                    finally {
                        if ($probeClient -and -not $probeClient.Connected) {
                            try {
                                $probeClient.Dispose()
                            }
                            catch {
                            }
                        }
                    }
                }

                if ($timedOutAddresses.Count -eq 0) {
                    break
                }

                $retryAddresses = @($timedOutAddresses)

                if ($attemptIndex -lt ($attemptBudgets.Count - 1) -and $retryAddresses.Count -gt 0) {
                    [System.Threading.Tasks.Task]::Delay(250).Wait()
                }
            }

            return [pscustomobject]@{
                Client             = $null
                TimedOut           = $sawTimeout
                FailureKind        = Get-TcpFailureKind -SocketErrorName $lastSocketErrorName -ErrorMessage $lastErrorMessage -TimedOut:$sawTimeout
                SocketErrorName    = $lastSocketErrorName
                SocketErrorCode    = $lastSocketErrorCode
                ErrorMessage       = $lastErrorMessage
                AttemptCount       = $attemptCount
                AttemptedAddresses = @($attemptedAddresses)
                ConnectedAddress   = $null
            }
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
        $issuerSubject = $null
        $issuerIssuer = $null
        $issuerNotAfterUtc = $null
        $rootSubject = $null
        $rootIssuer = $null
        $rootNotAfterUtc = $null
        $handshakeFailure = $null
        $leafExpired = $false
        $probeAddresses = $null
        $connectionDetail = $null
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
                $status = 'DnsFailure'
                if ($target.ResolutionFailure) {
                    $connectionDetail = $target.ResolutionFailure
                }
            }
            else {
                $probeAddresses = @($probeAddressesList)
            }

            if (-not $status) {
                $tcpConnectResult = Connect-TcpWithRetry -Addresses $probeAddresses -Port $port -TimeoutMs $timeoutMs
                $tcpClient = $tcpConnectResult.Client
                $connectionDetail = Get-ConnectionDetail -SocketErrorCode $tcpConnectResult.SocketErrorCode -SocketErrorName $tcpConnectResult.SocketErrorName -ErrorMessage $tcpConnectResult.ErrorMessage
                $tcpAttemptedAddresses = if ($tcpConnectResult.AttemptedAddresses.Count -gt 0) { $tcpConnectResult.AttemptedAddresses -join ', ' } else { $null }
                $tcpConnectedAddress = $tcpConnectResult.ConnectedAddress
                $tcpSocketErrorName = $tcpConnectResult.SocketErrorName
                $tcpSocketErrorCode = $tcpConnectResult.SocketErrorCode

                if (-not $tcpClient) {
                    $status = Get-TcpStatusFromFailureKind -FailureKind $tcpConnectResult.FailureKind
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
                        $status = 'TlsError: Timeout'
                        $connectionDetail = 'TLS handshake timed out.'
                    }
                }
                catch {
                    $innerMessage = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
                    $handshakeFailure = $innerMessage.Substring(0, [Math]::Min($innerMessage.Length, 120))
                    $connectionDetail = $handshakeFailure
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

                    $issuerCertificate = if ($certificateObjects.Count -ge 2) { $certificateObjects[1] } else { $null }
                    if ($issuerCertificate) {
                        $issuerSubject = $issuerCertificate.Subject
                        $issuerIssuer = $issuerCertificate.Issuer
                        $issuerNotAfterUtc = $issuerCertificate.NotAfter.ToUniversalTime()
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
                    if ($handshakeFailure) {
                        $status = "TlsError: $handshakeFailure"
                    }
                    else {
                        $status = 'TlsError: CertMsgNotFound'
                        $connectionDetail = 'TLS certificate message not found.'
                    }
                }
            }
        }
        catch {
            $socketException = Get-SocketException -Exception $_.Exception
            $innerMessage = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            if ($innerMessage -match 'No such host|could not be resolved|HostNotFound|name or service not known') {
                $status = 'DnsFailure'
                $connectionDetail = $innerMessage.Substring(0, [Math]::Min($innerMessage.Length, 200))
            }
            elseif ($innerMessage -match 'refused|reset|aborted|No connection|unreachable|TimedOut|timed out') {
                if (-not $tcpSocketErrorName -and $socketException) {
                    $tcpSocketErrorName = [string]$socketException.SocketErrorCode
                }
                if (-not $tcpSocketErrorCode -and $socketException) {
                    $tcpSocketErrorCode = [int]$socketException.ErrorCode
                }
                if (-not $tcpAttemptedAddresses -and $probeAddresses) {
                    $tcpAttemptedAddresses = (@($probeAddresses | ForEach-Object { $_.IPAddressToString }) -join ', ')
                }
                if (-not $pingStatus) {
                    $pingDiagnostic = Get-PingDiagnostic -Target $connectTo -TimeoutMs $timeoutMs
                    $pingStatus = $pingDiagnostic.PingStatus
                    $pingAddress = $pingDiagnostic.PingAddress
                }

                $connectionDetail = Get-ConnectionDetail -SocketErrorCode $tcpSocketErrorCode -SocketErrorName $tcpSocketErrorName -ErrorMessage $innerMessage

                $status = Get-TcpStatusFromFailureKind -FailureKind (Get-TcpFailureKind -SocketErrorName $tcpSocketErrorName -ErrorMessage $innerMessage -TimedOut:$false)
            }
            else {
                $trimmed = $innerMessage.Substring(0, [Math]::Min($innerMessage.Length, 120))
                $status = "TlsError: $trimmed"
                $connectionDetail = $trimmed
            }
        }

        if (-not $connectionDetail -and $status -like 'TlsError:*') {
            $connectionDetail = $status.Substring('TlsError: '.Length)
        }

        if (-not $connectionDetail -and $status -eq 'DnsFailure' -and $target.ResolutionFailure) {
            $connectionDetail = $target.ResolutionFailure
        }

        if (-not $connectionDetail -and ($status -like 'Tcp*')) {
            $connectionDetail = Get-ConnectionDetail -SocketErrorCode $tcpSocketErrorCode -SocketErrorName $tcpSocketErrorName -ErrorMessage $null
        }
        finally {
            if ($fallbackLeafCertificate) {
                try {
                    $fallbackLeafCertificate.Dispose()
                }
                catch {
                }
            }

            foreach ($certificate in $certificateObjects) {
                try {
                    $certificate.Dispose()
                }
                catch {
                }
            }

            if ($sslStream) {
                try {
                    $sslStream.Dispose()
                }
                catch {
                }
            }

            if ($capturingStream) {
                try {
                    $capturingStream.Dispose()
                }
                catch {
                }
            }

            if ($tcpClient) {
                try {
                    $tcpClient.Dispose()
                }
                catch {
                }
            }
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
            ConnectionDetail       = $connectionDetail
            TcpAttemptedAddresses  = $tcpAttemptedAddresses
            TcpConnectedAddress    = $tcpConnectedAddress
            PingStatus             = $pingStatus
            PingAddress            = $pingAddress
            ServerCertificateCount = $serverCertificateCount
            DigiCertIssued         = $digiCertIssued
            LeafSubject            = $leafSubject
            LeafIssuer             = $leafIssuer
            LeafNotAfterUtc        = $leafNotAfterUtc
            IssuerSubject          = $issuerSubject
            IssuerIssuer           = $issuerIssuer
            IssuerNotAfterUtc      = $issuerNotAfterUtc
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
# one row per origin.
foreach ($record in $allRecords) {
    $tlsPort = Get-TlsProbePort -Record $record
    $sniName = Get-TlsSniName -Record $record
    $lookupKey = "$($record.HostName)|$tlsPort|$sniName"
    $resolutionResult = $targetResolutionLookup[$lookupKey]
    $tlsResult = $tlsLookup[$lookupKey]

    $record | Add-Member -NotePropertyName TlsPort -NotePropertyValue $tlsPort -Force
    $record | Add-Member -NotePropertyName ResolvedAddresses -NotePropertyValue ($resolutionResult.ResolvedAddressesText ?? $null) -Force
    $record | Add-Member -NotePropertyName IpKind -NotePropertyValue ($resolutionResult.IpKind ?? $null) -Force
    $record | Add-Member -NotePropertyName AzureResourceId -NotePropertyValue ($resolutionResult.AzureResourceId ?? $null) -Force
    $record | Add-Member -NotePropertyName TlsStatus -NotePropertyValue ($tlsResult.TlsStatus ?? 'N/A') -Force
    $record | Add-Member -NotePropertyName ConnectionDetail -NotePropertyValue ($tlsResult.ConnectionDetail ?? $null) -Force
    $record | Add-Member -NotePropertyName TcpAttemptedAddresses -NotePropertyValue ($tlsResult.TcpAttemptedAddresses ?? $null) -Force
    $record | Add-Member -NotePropertyName TcpConnectedAddress -NotePropertyValue ($tlsResult.TcpConnectedAddress ?? $null) -Force
    $record | Add-Member -NotePropertyName PingStatus -NotePropertyValue ($tlsResult.PingStatus ?? $null) -Force
    $record | Add-Member -NotePropertyName PingAddress -NotePropertyValue ($tlsResult.PingAddress ?? $null) -Force
    $record | Add-Member -NotePropertyName ServerCertificateCount -NotePropertyValue ($tlsResult.ServerCertificateCount ?? $null) -Force
    $record | Add-Member -NotePropertyName DigiCertIssued -NotePropertyValue ($tlsResult.DigiCertIssued ?? $null) -Force
    $record | Add-Member -NotePropertyName LeafSubject -NotePropertyValue ($tlsResult.LeafSubject ?? $null) -Force
    $record | Add-Member -NotePropertyName LeafIssuer -NotePropertyValue ($tlsResult.LeafIssuer ?? $null) -Force
    $record | Add-Member -NotePropertyName LeafNotAfterUtc -NotePropertyValue ($tlsResult.LeafNotAfterUtc ?? $null) -Force
    $record | Add-Member -NotePropertyName IssuerSubject -NotePropertyValue ($tlsResult.IssuerSubject ?? $null) -Force
    $record | Add-Member -NotePropertyName IssuerIssuer -NotePropertyValue ($tlsResult.IssuerIssuer ?? $null) -Force
    $record | Add-Member -NotePropertyName IssuerNotAfterUtc -NotePropertyValue ($tlsResult.IssuerNotAfterUtc ?? $null) -Force
    $record | Add-Member -NotePropertyName RootSubject -NotePropertyValue ($tlsResult.RootSubject ?? $null) -Force
    $record | Add-Member -NotePropertyName RootIssuer -NotePropertyValue ($tlsResult.RootIssuer ?? $null) -Force
    $record | Add-Member -NotePropertyName RootNotAfterUtc -NotePropertyValue ($tlsResult.RootNotAfterUtc ?? $null) -Force
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
        $xlsxTextColumns = @('OriginName', 'HostName', 'OriginHostHeader', 'ResolvedAddresses', 'IpKind', 'AzureResourceId', 'ConnectionDetail', 'TcpAttemptedAddresses', 'TcpConnectedAddress', 'PingAddress')
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
