#requires -Version 7.0
<#
.SYNOPSIS
    Enumerates all accessible Azure Front Door Standard/Premium and Classic origins and evaluates
    the TLS certificate chain each distinct origin endpoint presents.

.DESCRIPTION
    1. Requires PowerShell 7+ and the Az.Accounts module.
    2. Acquires a single Azure management-plane bearer token via Az.Accounts.
     3. Uses Azure Resource Graph to discover every accessible Front Door Standard/Premium
         and Classic profile in every enabled subscription the current identity can read.
     4. Enumerates Standard/Premium origin groups and origins plus Classic backend pools
         and backends via ARM REST in parallel.
    5. Tests distinct (HostName, HttpsPort, OriginHostHeader) TLS targets in parallel.
    6. Forces TLS 1.2 and parses the raw TLS Certificate message so chain counts reflect
       the certificates the server actually sent, not locally cached intermediates.
     7. Adds DigiCert-issued detection based on the leaf certificate issuer.
     8. Always exports CSV and, when the ImportExcel module is available, also exports
         a companion XLSX workbook with a formatted Excel table.

    TlsStatus values:
      FullChain             - Server sent 3 or more certificates.
      ExpiredFullChain      - Same as FullChain, but the leaf certificate is expired.
      PartialChain          - Server sent exactly 2 certificates.
      ExpiredPartialChain   - Same as PartialChain, but the leaf certificate is expired.
      NoChain               - Server sent exactly 1 certificate.
      ExpiredNoChain        - Same as NoChain, but the leaf certificate is expired.
      NoCert                - Server sent a TLS Certificate message with no certificates.
      DnsFailure            - The origin hostname could not be resolved.
      TcpFailure            - TCP connection to the HTTPS port failed or timed out.
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
    Enumerate origins only and skip TLS probing.

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
$totalSteps = 6

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

# Acquires one Azure management-plane token and returns the current Az context alongside it.
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

    return [pscustomobject]@{
        Context = $context
        Token   = $token
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
        'TcpFailure'   { 'Red' }
        'Skipped'      { 'DarkGray' }
        default        { 'DarkYellow' }
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
$contextLabel = if ($tokenInfo.Context.Subscription.Name) {
    $tokenInfo.Context.Subscription.Name
}
else {
    $tokenInfo.Context.Subscription.Id
}
Write-Host "        Token acquired from context: $contextLabel" -ForegroundColor Green

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

# Build unique TLS targets as (ConnectTo, Port, SniName) triples.
# Using the configured HTTPS port makes the probe match the actual Front Door origin settings.
$tlsTargets = @(
    $allRecords |
        Where-Object { $_.HostName } |
        ForEach-Object {
            $port = 443
            try {
                if ($null -ne $_.HttpsPort -and [int]$_.HttpsPort -gt 0) {
                    $port = [int]$_.HttpsPort
                }
            }
            catch {
                $port = 443
            }

            [pscustomobject]@{
                ConnectTo = $_.HostName
                Port      = $port
                SniName   = if ([string]::IsNullOrWhiteSpace($_.OriginHostHeader)) { $_.HostName } else { $_.OriginHostHeader }
            }
        } |
        Sort-Object ConnectTo, Port, SniName -Unique
)

$tlsLookup = @{}
if ($SkipTls) {
    Write-PhaseBanner -Phase '5' -Message 'Skipping TLS checks (-SkipTls).'
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
    Write-PhaseBanner -Phase '5' -Message 'No TLS targets were found.'
}
else {
    Write-PhaseBanner -Phase '5' -Message "Testing TLS on $($tlsTargets.Count) distinct target(s) (parallel=$TlsThrottleLimit, timeout=${TlsTimeoutMs}ms)..."
    $tlsInterval = Get-ProgressInterval -TotalCount $tlsTargets.Count
    $tlsComplete = 0

    $tlsTargets | ForEach-Object -ThrottleLimit $TlsThrottleLimit -Parallel {
        $target = $_
        $timeoutMs = $using:TlsTimeoutMs

        $connectTo = $target.ConnectTo
        $port = [int]$target.Port
        $sniName = $target.SniName
        $status = $null
        $serverCertificateCount = $null
        $digiCertIssued = $false
        $leafSubject = $null
        $leafIssuer = $null
        $leafNotAfterUtc = $null
        $handshakeFailure = $null
        $leafExpired = $false
        $resolvedAddresses = $null
        $parsedIp = $null

        $tcpClient = $null
        $capturingStream = $null
        $sslStream = $null
        $fallbackLeafCertificate = $null
        $certificateObjects = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()

        try {
            $isIpAddress = [System.Net.IPAddress]::TryParse($connectTo, [ref]$parsedIp)

            if (-not $isIpAddress) {
                $resolvedAddresses = [System.Net.Dns]::GetHostAddresses($connectTo)
                if (-not $resolvedAddresses -or $resolvedAddresses.Count -eq 0) {
                    $status = 'DnsFailure'
                }
            }

            if (-not $status) {
                $tcpClient = [System.Net.Sockets.TcpClient]::new()
                $connectTask = if ($isIpAddress) {
                    $tcpClient.ConnectAsync($parsedIp, $port)
                }
                else {
                    $tcpClient.ConnectAsync($resolvedAddresses, $port)
                }

                if (-not $connectTask.Wait($timeoutMs) -or $connectTask.IsFaulted) {
                    $status = 'TcpFailure'
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
                    }
                }
            }
        }
        catch {
            $innerMessage = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            if ($innerMessage -match 'No such host|could not be resolved|HostNotFound|name or service not known') {
                $status = 'DnsFailure'
            }
            elseif ($innerMessage -match 'refused|No connection|unreachable|TimedOut|timed out') {
                $status = 'TcpFailure'
            }
            else {
                $trimmed = $innerMessage.Substring(0, [Math]::Min($innerMessage.Length, 120))
                $status = "TlsError: $trimmed"
            }
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
            ServerCertificateCount = $serverCertificateCount
            DigiCertIssued         = $digiCertIssued
            LeafSubject            = $leafSubject
            LeafIssuer             = $leafIssuer
            LeafNotAfterUtc        = $leafNotAfterUtc
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

# Stamp the TLS findings back onto every origin row so the CSV remains one row per origin.
foreach ($record in $allRecords) {
    $tlsPort = 443
    try {
        if ($null -ne $record.HttpsPort -and [int]$record.HttpsPort -gt 0) {
            $tlsPort = [int]$record.HttpsPort
        }
    }
    catch {
        $tlsPort = 443
    }

    $sniName = if ([string]::IsNullOrWhiteSpace($record.OriginHostHeader)) { $record.HostName } else { $record.OriginHostHeader }
    $lookupKey = "$($record.HostName)|$tlsPort|$sniName"
    $tlsResult = $tlsLookup[$lookupKey]

    $record | Add-Member -NotePropertyName TlsPort -NotePropertyValue $tlsPort -Force
    $record | Add-Member -NotePropertyName TlsStatus -NotePropertyValue ($tlsResult.TlsStatus ?? 'N/A') -Force
    $record | Add-Member -NotePropertyName ServerCertificateCount -NotePropertyValue ($tlsResult.ServerCertificateCount ?? $null) -Force
    $record | Add-Member -NotePropertyName DigiCertIssued -NotePropertyValue ($tlsResult.DigiCertIssued ?? $null) -Force
    $record | Add-Member -NotePropertyName LeafSubject -NotePropertyValue ($tlsResult.LeafSubject ?? $null) -Force
    $record | Add-Member -NotePropertyName LeafIssuer -NotePropertyValue ($tlsResult.LeafIssuer ?? $null) -Force
    $record | Add-Member -NotePropertyName LeafNotAfterUtc -NotePropertyValue ($tlsResult.LeafNotAfterUtc ?? $null) -Force
}

Write-PhaseBanner -Phase '6' -Message 'Exporting results...'
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
        $worksheetName = [System.IO.Path]::GetFileNameWithoutExtension($xlsxOutputPath)
        $worksheetName = $worksheetName -replace '[\\/\?\*\[\]:]', '_'
        if ([string]::IsNullOrWhiteSpace($worksheetName)) {
            $worksheetName = 'afd-origins'
        }
        if ($worksheetName.Length -gt 31) {
            $worksheetName = $worksheetName.Substring(0, 31)
        }

        $allRecords | Export-Excel -Path $xlsxOutputPath -WorksheetName $worksheetName -TableName Table1 -TableStyle Medium3 -AutoFilter -AutoSize -FreezeTopRow -ClearSheet
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
    Write-Host ''
    Write-Host '  TLS status breakdown (by distinct origin+port+SNI target):' -ForegroundColor Cyan
    foreach ($group in ($tlsLookup.Values | Group-Object TlsStatus | Sort-Object Name)) {
        Write-Host ("    {0,-25} : {1}" -f $group.Name, $group.Count) -ForegroundColor (Get-TlsStatusColor -TlsStatus $group.Name)
    }

    $digiCertCount = @($tlsLookup.Values | Where-Object { $_.DigiCertIssued }).Count
    Write-Host ''
    Write-Host "  DigiCert-issued leaf certs: $digiCertCount" -ForegroundColor Cyan
}

Write-Host '================================================================' -ForegroundColor Green

Write-Host "`n  Per-profile breakdown:" -ForegroundColor Cyan
$allRecords | Group-Object ProfileName | Sort-Object Name | ForEach-Object {
    $uniqueTargets = @(
        $_.Group | ForEach-Object {
            $sniName = if ([string]::IsNullOrWhiteSpace($_.OriginHostHeader)) { $_.HostName } else { $_.OriginHostHeader }
            "{0}|{1}|{2}" -f $_.HostName, $_.TlsPort, $sniName
        } | Sort-Object -Unique
    ).Count

    Write-Host "    $($_.Name): $($_.Count) origin(s), $uniqueTargets distinct TLS target(s)"
}

Write-Host "`nDone." -ForegroundColor Green
