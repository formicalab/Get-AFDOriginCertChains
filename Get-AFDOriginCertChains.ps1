#requires -Version 7.0
<#
.SYNOPSIS
    Enumerates all accessible Azure Front Door Standard/Premium and Classic origins and evaluates
    the TLS certificate chain each distinct origin endpoint presents.

.DESCRIPTION
    1. Requires PowerShell 7+ and the Az.Accounts module.
    2. Acquires one Azure management-plane bearer token via Az.Accounts only.
    3. Uses Azure Resource Graph to discover accessible Front Door Standard/Premium and
       Classic profiles across enabled subscriptions, retaining migrated backends as unassessed.
    4. Enumerates Standard/Premium origin groups/origins plus Classic backend pools/backends
       via ARM REST in parallel.
    5. Resolves each eligible distinct origin hostname once and maps public IPs back to
       Azure resources when possible. Migrated Classic, disabled, and Microsoft-managed
       origins remain in inventory without DNS/TCP/TLS probing, in that precedence order.
    6. Investigates Application Gateway subnet NSGs and WAF policies for resolved origins.
    7. Tests distinct (HostName, HttpsPort, OriginHostHeader) TLS targets in parallel.
    7b. When the public-IP probe fails to retrieve certificates and the resolved public
        IP carries a Private_IP tag, falls back to probing the private IP directly.
        The private probe results replace the public-IP results, even if both probes fail.
        TcpAttemptedAddresses shows both IPs when both were tested.
        TLS 1.2 is forced and the raw TLS Certificate message is parsed so chain counts
        reflect what the server actually sent. DigiCert issuance is detected from the
        leaf certificate issuer.
    8. Always exports CSV and, when ImportExcel is available, also exports a companion
       XLSX workbook with diagnostics and a summary, without banded table rows.
       Percentages use all inventoried origin rows, including unassessed rows.
       Chain labels describe server-sent certificate counts, not trust or completeness.

    TlsStatus values:
      FullChain             - Server sent 3 or more certificates.
      ExpiredFullChain      - Same as FullChain, but the leaf certificate is expired.
      PartialChain          - Server sent exactly 2 certificates.
      ExpiredPartialChain   - Same as PartialChain, but the leaf certificate is expired.
      NoChain               - Server sent exactly 1 certificate.
      ExpiredNoChain        - Same as NoChain, but the leaf certificate is expired.
      NoCert                - Server sent a TLS Certificate message with no certificates.
      Skipped               - TLS probing was skipped with -SkipTls.
      Disabled              - Origin is disabled; DNS/TCP/TLS probing is skipped.
      MigratedClassic       - Origin belongs to a migrated Classic profile; probing is skipped.
      MSFT                  - Origin host name belongs to a Microsoft-owned Azure PaaS
                              public DNS suffix (see https://learn.microsoft.com/azure/private-link/private-endpoint-dns).
                              The TLS chain for these endpoints is managed by Microsoft, so
                              the scan skips DNS, TCP and TLS probing entirely.
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
$totalSteps = 8

# Converts access token values that Az.Accounts may surface as strings or SecureStrings.
function ConvertTo-PlainText {
    param([Parameter(Mandatory)][AllowNull()][object]$Value)

    if ($Value -is [string])       { return $Value }
    if ($Value -is [securestring]) { return ConvertFrom-SecureString -SecureString $Value -AsPlainText }
    throw "ConvertTo-PlainText: unexpected type [$($Value.GetType().FullName)]."
}

# Decodes JWT claims for display only; this does not validate the token's signature.
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

# Only completed Classic migrations suppress probing; other profile types/states remain eligible.
function Test-IsMigratedClassicProfile {
    param([string]$ResourceType, [AllowNull()][string]$ResourceState)

    $ResourceType -eq 'microsoft.network/frontdoors' -and ([string]$ResourceState).Trim() -eq 'Migrated'
}

# Keep inventory rows while assigning the strongest skip reason: migrated before disabled.
# Callers use this before DNS/TLS selection and again when stamping shared-target results.
function Get-OriginSkipStatus {
    param([Parameter(Mandatory)][object]$Record)

    if (Test-IsMigratedClassicProfile -ResourceType (Get-PropValue $Record 'ResourceType') -ResourceState (Get-PropValue $Record 'ProfileResourceState')) {
        return 'MigratedClassic'
    }
    if (([string](Get-PropValue $Record 'EnabledState')).Trim() -eq 'Disabled') {
        return 'Disabled'
    }
}

# One endpoint may serve multiple inventory rows: active > disabled > migrated for target totals.
# "Active" here includes errors and other unassessed outcomes, not just successful handshakes.
function Get-TlsTargetResultPriority {
    param([AllowNull()][object]$Record)

    switch ([string](Get-PropValue $Record 'TlsStatus')) {
        'MigratedClassic' { return 0 }
        'Disabled'        { return 1 }
        default           { return 2 }
    }
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

    # Service principals and token versions expose different identity claims; fall back to Az metadata.
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

# Uses the configured positive integer HTTPS port; blank, noninteger, or nonpositive values use 443.
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

# Public DNS zone forwarders for first-party Azure PaaS services. Sourced from the
# 'Public DNS zone forwarders' column of the tables at
# https://learn.microsoft.com/azure/private-link/private-endpoint-dns (Commercial,
# Government, China). Region/regionCode/dnsPrefix placeholders are reduced to their
# parent suffix because Test-IsMicrosoftManagedHost matches on a dot boundary, which
# naturally covers region-prefixed forms such as eastus.batch.azure.com.
$script:MicrosoftPublicDnsSuffixes = @(
    # Commercial
    'api.azureml.ms', 'instances.azureml.ms', 'notebooks.azure.net', 'aznbcontent.net', 'inference.ml.azure.com',
    'cognitiveservices.azure.com', 'openai.azure.com', 'services.ai.azure.com',
    'directline.botframework.com', 'token.botframework.com',
    'sql.azuresynapse.net', 'dev.azuresynapse.net', 'azuresynapse.net',
    'servicebus.windows.net',
    'datafactory.azure.net', 'adf.azure.com',
    'azurehdinsight.net',
    'kusto.windows.net',
    'blob.core.windows.net', 'queue.core.windows.net', 'table.core.windows.net',
    'file.core.windows.net', 'web.core.windows.net', 'dfs.core.windows.net',
    'analysis.windows.net', 'pbidedicated.windows.net', 'prod.powerquery.microsoft.com',
    'azuredatabricks.net', 'fabric.microsoft.com',
    'batch.azure.com', 'service.batch.azure.com',
    'wvd.microsoft.com',
    'azmk8s.io', 'azurecontainerapps.io',
    'azurecr.io', 'data.azurecr.io',
    'database.windows.net',
    'documents.azure.com', 'mongo.cosmos.azure.com', 'cassandra.cosmos.azure.com',
    'gremlin.cosmos.azure.com', 'table.cosmos.azure.com', 'analytics.cosmos.azure.com',
    'postgres.cosmos.azure.com', 'mongocluster.cosmos.azure.com',
    'postgres.database.azure.com', 'mysql.database.azure.com', 'mariadb.database.azure.com',
    'redis.cache.windows.net', 'redisenterprise.cache.azure.net', 'redis.azure.net',
    'his.arc.azure.com', 'guestconfiguration.azure.com', 'dp.kubernetesconfiguration.azure.com',
    'eventgrid.azure.net', 'azure-api.net',
    'azurehealthcareapis.com',
    'azure-devices.net', 'azure-devices-provisioning.net', 'api.adu.microsoft.com',
    'azureiotcentral.com', 'digitaltwins.azure.net',
    'media.azure.net', 'api.videoindexer.ai',
    'azure-automation.net', 'agentsvc.azure-automation.net',
    'backup.windowsazure.com', 'siterecovery.windowsazure.com',
    'monitor.azure.com', 'oms.opinsights.azure.com', 'ods.opinsights.azure.com',
    'services.visualstudio.com', 'applicationinsights.azure.com',
    'purview.azure.com', 'purviewstudio.azure.com', 'purview-service.microsoft.com',
    'prod.migration.windowsazure.com',
    'grafana.azure.com', 'prometheus.monitor.azure.com',
    'vault.azure.net', 'vaultcore.azure.net', 'managedhsm.azure.net',
    'azconfig.io', 'attest.azure.net',
    'afs.azure.net', 'blob.storage.azure.net',
    'search.windows.net',
    'azurewebsites.net', 'scm.azurewebsites.net',
    'service.signalr.net', 'azurestaticapps.net',
    'account.maps.azure.com', 'webpubsub.azure.com',

    # Government (US Gov)
    'cognitiveservices.azure.us', 'api.ml.azure.us', 'notebooks.usgovcloudapi.net',
    'instances.azureml.us', 'inference.ml.azure.us',
    'servicebus.usgovcloudapi.net',
    'sql.azuresynapse.usgovcloudapi.net', 'dev.azuresynapse.usgovcloudapi.net', 'azuresynapse.usgovcloudapi.net',
    'datafactory.azure.us', 'adf.azure.us',
    'azurehdinsight.us', 'databricks.azure.us',
    'batch.usgovcloudapi.net', 'service.batch.usgovcloudapi.net',
    'wvd.azure.us', 'azurecr.us',
    'database.usgovcloudapi.net',
    'documents.azure.us', 'mongo.cosmos.azure.us', 'cassandra.cosmos.azure.us',
    'gremlin.cosmos.azure.us', 'table.cosmos.azure.us',
    'postgres.database.usgovcloudapi.net', 'mysql.database.usgovcloudapi.net', 'mariadb.database.usgovcloudapi.net',
    'redis.cache.usgovcloudapi.net',
    'eventgrid.azure.us',
    'azurehealthcareapis.us',
    'azure-devices.us', 'azure-devices-provisioning.us',
    'azure-automation.us', 'agentsvc.azure-automation.us',
    'backup.windowsazure.us', 'siterecovery.windowsazure.us', 'prod.migration.windowsazure.us',
    'monitor.azure.us', 'adx.monitor.azure.us', 'oms.opinsights.azure.us', 'ods.opinsights.azure.us',
    'purview.azure.us', 'purviewstudio.azure.us',
    'vault.usgovcloudapi.net', 'vaultcore.usgovcloudapi.net',
    'azconfig.azure.us',
    'blob.core.usgovcloudapi.net', 'table.core.usgovcloudapi.net', 'queue.core.usgovcloudapi.net',
    'file.core.usgovcloudapi.net', 'web.core.usgovcloudapi.net', 'dfs.core.usgovcloudapi.net',
    'search.azure.us',
    'azurewebsites.us', 'scm.azurewebsites.us',

    # China
    'api.ml.azure.cn', 'notebooks.chinacloudapi.cn', 'instances.azureml.cn', 'inference.ml.azure.cn',
    'datafactory.azure.cn', 'adf.azure.cn',
    'azurehdinsight.cn', 'kusto.windows.cn',
    'batch.chinacloudapi.cn', 'wvd.azure.cn',
    'database.chinacloudapi.cn',
    'documents.azure.cn', 'mongo.cosmos.azure.cn', 'cassandra.cosmos.azure.cn',
    'gremlin.cosmos.azure.cn', 'table.cosmos.azure.cn',
    'postgres.database.chinacloudapi.cn', 'mysql.database.chinacloudapi.cn', 'mariadb.database.chinacloudapi.cn',
    'redis.cache.chinacloudapi.cn',
    'servicebus.chinacloudapi.cn',
    'azure-devices.cn', 'azure-devices-provisioning.cn',
    'azure-automation.cn',
    'vaultcore.azure.cn',
    'blob.core.chinacloudapi.cn', 'table.core.chinacloudapi.cn', 'queue.core.chinacloudapi.cn',
    'file.core.chinacloudapi.cn', 'web.core.chinacloudapi.cn', 'dfs.core.chinacloudapi.cn',
    'afs.azure.cn',
    'chinacloudsites.cn', 'service.signalr.azure.cn'
) | Sort-Object -Unique

# Returns $true when the supplied origin host name belongs to a Microsoft-owned Azure PaaS
# public DNS suffix. Match is case-insensitive and anchored on a dot boundary so that, for
# example, 'foo.blob.core.windows.net' matches but 'notazurewebsites.net' does not.
function Test-IsMicrosoftManagedHost {
    param([AllowNull()][string]$HostName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $false }
    $hostLower = $HostName.Trim().TrimEnd('.').ToLowerInvariant()
    foreach ($suffix in $script:MicrosoftPublicDnsSuffixes) {
        $s = $suffix.ToLowerInvariant()
        if ($hostLower -eq $s) { return $true }
        if ($hostLower.EndsWith('.' + $s)) { return $true }
    }
    return $false
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

# Source text for the ARM retry and paging helpers. Stored as a string so they can be re-defined inside
# ForEach-Object -Parallel runspaces (which do not inherit caller-defined helper functions)
# via Invoke-Expression $using:ArmRetryFuncText. Also dot-evaluated at script scope below.
$script:ArmRetryFuncText = @'
# Wraps Invoke-RestMethod with retry/backoff for transient ARM failures.
# Retries on HTTP 408/429/500/502/503/504 and on HTML "outage interstitial" bodies
# (some ARM edges return an HTML page with AzureResourceManager / Ref A / Ref B / Ref C
# tokens instead of JSON during regional incidents or throttling).
# Also retries recognized network/DNS errors. Successful responses are returned without body inspection.
# Caps Retry-After or exponential delay before adding jitter (at least a 50 ms jitter range).
function Invoke-ArmRequestWithRetry {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][ValidateSet('Get','Post')][string]$Method,
        [Parameter(Mandatory)][hashtable]$Headers,
        [string]$Body,
        [int]$MaxAttempts = 6,
        [int]$BaseDelayMs = 500,
        [int]$MaxDelayMs  = 30000
    )

    $retriableStatus = @(408, 429, 500, 502, 503, 504)
    $attempt = 0

    while ($true) {
        $attempt++
        try {
            $irmParams = @{
                Method      = $Method
                Uri         = $Uri
                Headers     = $Headers
                ErrorAction = 'Stop'
            }
            if ($PSBoundParameters.ContainsKey('Body') -and $Body) {
                $irmParams['Body']        = $Body
                $irmParams['ContentType'] = 'application/json'
            }
            return Invoke-RestMethod @irmParams
        }
        catch {
            # HTTP and transport failures expose different exception shapes; missing headers are normal.
            $statusCode   = $null
            $retryAfterMs = $null
            $responseProperty = $_.Exception.PSObject.Properties['Response']
            $resp = if ($responseProperty) { $responseProperty.Value } else { $null }
            if ($resp) {
                try { $statusCode = [int]$resp.StatusCode } catch { }
                try {
                    $ra = $resp.Headers.RetryAfter
                    if ($ra) {
                        if ($ra.Delta)     { $retryAfterMs = [int]$ra.Delta.TotalMilliseconds }
                        elseif ($ra.Date)  { $retryAfterMs = [int]([Math]::Max(0, ($ra.Date - [DateTimeOffset]::UtcNow).TotalMilliseconds)) }
                    }
                } catch { }
            }

            # ARM outages may surface HTML instead of a useful status, so inspect error text as well.
            $bodyText = $null
            if ($_.ErrorDetails) { $bodyText = $_.ErrorDetails.Message }
            if (-not $bodyText)  { $bodyText = $_.Exception.Message }

            $bodyLooksTransientHtml = $false
            if ($bodyText -and (
                    $bodyText -match 'AzureResourceManager' -or
                    $bodyText -match "services aren't available" -or
                    $bodyText -match '<html' -or
                    $bodyText -match 'Ref A:.*Ref B:'
                )) {
                $bodyLooksTransientHtml = $true
            }

            $networkLooksTransient = $bodyText -and (
                $bodyText -match 'No such host is known' -or
                $bodyText -match 'Name or service not known' -or
                $bodyText -match 'Temporary failure in name resolution' -or
                $bodyText -match 'connection.*(closed|reset|timed out)' -or
                $bodyText -match 'The operation has timed out' -or
                $bodyText -match 'HttpClient\.Timeout.*elaps' -or
                $bodyText -match '(task|operation|request) (was|has been) canceled'
            )
            # Without an HTTP response, unwrap transport exceptions rather than relying only on wording.
            if (-not $statusCode) {
                $currentException = $_.Exception
                while ($currentException -and -not $networkLooksTransient) {
                    if ($currentException -is [System.TimeoutException] -or
                        $currentException -is [System.Threading.Tasks.TaskCanceledException] -or
                        $currentException -is [System.Net.Sockets.SocketException] -or
                        $currentException -is [System.IO.IOException]) {
                        $networkLooksTransient = $true
                    }
                    $currentException = $currentException.InnerException
                }
            }

            # Preserve permanent failures and the final exception instead of returning partial inventory.
            $isRetriable = ($statusCode -and ($retriableStatus -contains $statusCode)) -or $bodyLooksTransientHtml -or $networkLooksTransient
            if (-not $isRetriable -or $attempt -ge $MaxAttempts) { throw }

            if ($retryAfterMs -and $retryAfterMs -gt 0) {
                $delay = [Math]::Min($retryAfterMs, $MaxDelayMs)
            }
            else {
                $delay = [Math]::Min([int]($BaseDelayMs * [Math]::Pow(2, $attempt - 1)), $MaxDelayMs)
            }
            # Desynchronize parallel workers so throttled requests do not all resume together.
            $jitterBound = [int][Math]::Max(50, $delay * 0.2)
            $delay = [Math]::Max(100, [int]($delay + (Get-Random -Minimum (-$jitterBound) -Maximum ($jitterBound + 1))))

            $statusLabel = if ($statusCode) { "status=$statusCode" } elseif ($bodyLooksTransientHtml) { 'status=HTML interstitial' } elseif ($networkLooksTransient) { 'status=network/DNS' } else { 'status=unknown' }
            Write-Host ("        ARM transient failure ({0}) on attempt {1}/{2}; retrying in {3} ms..." -f $statusLabel, $attempt, $MaxAttempts, $delay) -ForegroundColor DarkYellow

            Start-Sleep -Milliseconds $delay
        }
    }
}

# Follows ARM nextLink values so large collections are fully enumerated, tolerating transient
# ARM failures via Invoke-ArmRequestWithRetry. Defined alongside the retry wrapper so a single
# Invoke-Expression $using:ArmRetryFuncText makes both available inside parallel runspaces.
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
        $response = Invoke-ArmRequestWithRetry -Method Get -Uri $nextUri -Headers $Headers
        foreach ($item in @($response.value)) {
            $items.Add($item)
        }
        # Follow the service-provided URL verbatim, including its continuation parameters.
        $nextUri = $response.nextLink
    }

    return @($items)
}
'@
Invoke-Expression $script:ArmRetryFuncText

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

    # ARG paging is a repeated POST with an opaque token, unlike ARM collection nextLink paging.
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

        $response = Invoke-ArmRequestWithRetry -Method Post -Uri $graphUri -Headers $Headers -Body $body
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
            $applicationGatewayResourceId = if ($associatedResourceId -match '(?i)/providers/Microsoft\.Network/applicationGateways/[^/]+$') {
                $associatedResourceId
            }
            else {
                $null
            }

            $lookup[$ip] = [pscustomobject]@{
                Kind                                    = 'AzurePublicIp'
                ResourceId                              = $associatedResourceId ?? [string]$row.publicIpResourceId
                PublicIpResourceId                      = [string]$row.publicIpResourceId
                IpConfigurationId                       = [string]$row.ipConfigurationId
                AssociatedResourceId                    = $associatedResourceId
                ApplicationGatewayResourceId            = $applicationGatewayResourceId
                ApplicationGatewayFrontendIpConfigId    = if ($applicationGatewayResourceId) { [string]$row.ipConfigurationId } else { $null }
                PrivateIpTag                            = ([string]$row.privateIpTag).Trim()
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
        return [pscustomobject]@{
            ResolvedAddresses                       = $null
            IpKind                                  = 'DnsFailure'
            AzureResourceId                         = $null
            ApplicationGatewayResourceId            = $null
            ApplicationGatewayFrontendIpConfigId    = $null
            ApplicationGatewayUnverifiedPublicIps   = $null
            AzurePrivateIpTag                       = $null
        }
    }

    $kinds                      = [System.Collections.Generic.List[string]]::new()
    $resourceIds                = [System.Collections.Generic.List[string]]::new()
    $applicationGatewayIds      = [System.Collections.Generic.List[string]]::new()
    $applicationGatewayFrontends = [System.Collections.Generic.List[string]]::new()
    $unverifiedPublicIps         = [System.Collections.Generic.List[string]]::new()
    $privateIpTags              = [System.Collections.Generic.List[string]]::new()
    $seenIds                    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seenApplicationGatewayIds  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seenApplicationGatewayFrontends = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seenUnverifiedPublicIps     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seenTags                   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # Keep one kind per address while deduplicating shared Azure IDs/tags for readable export cells.
    foreach ($ip in $addresses) {
        $ipKind = Get-IpAddressKind -IpAddress $ip
        if ($AzurePublicIpLookup.ContainsKey($ip)) {
            $entry = $AzurePublicIpLookup[$ip]
            $kinds.Add($entry.Kind)
            if (-not [string]::IsNullOrWhiteSpace($entry.ResourceId) -and $seenIds.Add($entry.ResourceId)) {
                $resourceIds.Add($entry.ResourceId)
            }
            if (-not [string]::IsNullOrWhiteSpace($entry.ApplicationGatewayResourceId) -and $seenApplicationGatewayIds.Add($entry.ApplicationGatewayResourceId)) {
                $applicationGatewayIds.Add($entry.ApplicationGatewayResourceId)
            }
            if (-not [string]::IsNullOrWhiteSpace($entry.ApplicationGatewayFrontendIpConfigId) -and $seenApplicationGatewayFrontends.Add($entry.ApplicationGatewayFrontendIpConfigId)) {
                $applicationGatewayFrontends.Add($entry.ApplicationGatewayFrontendIpConfigId)
            }
            if (-not [string]::IsNullOrWhiteSpace($entry.PrivateIpTag) -and $seenTags.Add($entry.PrivateIpTag)) {
                $privateIpTags.Add($entry.PrivateIpTag)
            }
            # A matching PIP alone does not prove that this address belongs to an analyzed gateway.
            if ($ipKind -like 'Public*' -and [string]::IsNullOrWhiteSpace($entry.ApplicationGatewayResourceId) -and $seenUnverifiedPublicIps.Add($ip)) {
                $unverifiedPublicIps.Add($ip)
            }
        }
        else {
            $kinds.Add($ipKind)
            if ($ipKind -like 'Public*' -and $seenUnverifiedPublicIps.Add($ip)) {
                $unverifiedPublicIps.Add($ip)
            }
        }
    }

    [pscustomobject]@{
        ResolvedAddresses                       = $addresses -join '; '
        IpKind                                  = $kinds -join '; '
        AzureResourceId                         = if ($resourceIds.Count) { $resourceIds -join '; ' } else { $null }
        ApplicationGatewayResourceId            = if ($applicationGatewayIds.Count) { $applicationGatewayIds -join '; ' } else { $null }
        ApplicationGatewayFrontendIpConfigId    = if ($applicationGatewayFrontends.Count) { $applicationGatewayFrontends -join '; ' } else { $null }
        ApplicationGatewayUnverifiedPublicIps   = if ($unverifiedPublicIps.Count) { $unverifiedPublicIps -join '; ' } else { $null }
        AzurePrivateIpTag                       = if ($privateIpTags.Count) { $privateIpTags -join '; ' } else { $null }
    }
}

# Retrieves a deduplicated set of Azure resources by ARM resource ID using batched ARG queries.
function Get-AzureResourcesById {
    param(
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string[]]$SubscriptionIds,
        [AllowEmptyCollection()][string[]]$ResourceIds
    )

    $lookup = @{}
    $ids = @($ResourceIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if (-not $ids) { return $lookup }

    # Bound query size and escape Kusto string literals without altering the returned resource IDs.
    $chunkSize = 100
    for ($offset = 0; $offset -lt $ids.Count; $offset += $chunkSize) {
        $chunk = @($ids[$offset..([Math]::Min($offset + $chunkSize - 1, $ids.Count - 1))])
        $idList = ($chunk | ForEach-Object { "'{0}'" -f ($_ -replace "'", "''") }) -join ', '
        $query = @"
resources
| where id in~ ($idList)
| project id, type, name, location, sku, properties
"@

        foreach ($row in @(Invoke-ResourceGraphQueryAllPages -Headers $Headers -SubscriptionIds $SubscriptionIds -Query $query)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$row.id)) {
                $lookup[[string]$row.id] = $row
            }
        }
    }

    $lookup
}

# Returns all non-empty string values exposed through singular and plural ARM properties.
function Get-ArmStringValues {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory)][string[]]$PropertyNames
    )

    $values = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($propertyName in $PropertyNames) {
        foreach ($value in @((Get-PropValue $Object $propertyName))) {
            $text = [string]$value
            if (-not [string]::IsNullOrWhiteSpace($text) -and $seen.Add($text)) {
                $values.Add($text)
            }
        }
    }
    @($values)
}

# Checks an IP literal against an exact IP or CIDR prefix for both IPv4 and IPv6.
function Test-IpAddressInPrefix {
    param(
        [Parameter(Mandatory)][string]$IpAddress,
        [Parameter(Mandatory)][string]$Prefix
    )

    if ($Prefix -in @('*', 'Any')) { return $true }

    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($IpAddress, [ref]$ip)) { return $false }

    $parts = $Prefix -split '/', 2
    $network = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$network)) { return $false }
    if ($ip.AddressFamily -ne $network.AddressFamily) { return $false }
    if ($parts.Count -eq 1) { return $ip.Equals($network) }

    $prefixLength = 0
    $maxBits = $ip.GetAddressBytes().Length * 8
    if (-not [int]::TryParse($parts[1], [ref]$prefixLength) -or $prefixLength -lt 0 -or $prefixLength -gt $maxBits) {
        return $false
    }

    $ipBytes = $ip.GetAddressBytes()
    $networkBytes = $network.GetAddressBytes()
    $wholeBytes = [int][Math]::Floor($prefixLength / 8)
    $remainingBits = $prefixLength % 8

    # Compare complete prefix bytes, then mask only the significant bits of the partial byte.
    for ($i = 0; $i -lt $wholeBytes; $i++) {
        if ($ipBytes[$i] -ne $networkBytes[$i]) { return $false }
    }
    if ($remainingBits -gt 0) {
        $mask = (0xFF -shl (8 - $remainingBits)) -band 0xFF
        if (($ipBytes[$wholeBytes] -band $mask) -ne ($networkBytes[$wholeBytes] -band $mask)) { return $false }
    }
    return $true
}

# Same-family CIDR ranges overlap when either range contains the other's base address.
function Test-IpPrefixesOverlap {
    param(
        [Parameter(Mandatory)][string]$FirstPrefix,
        [Parameter(Mandatory)][string]$SecondPrefix
    )

    $firstAddress = ($FirstPrefix -split '/', 2)[0]
    $secondAddress = ($SecondPrefix -split '/', 2)[0]
    $parsedFirst = $null
    $parsedSecond = $null
    if (-not [System.Net.IPAddress]::TryParse($firstAddress, [ref]$parsedFirst) -or
        -not [System.Net.IPAddress]::TryParse($secondAddress, [ref]$parsedSecond) -or
        $parsedFirst.AddressFamily -ne $parsedSecond.AddressFamily) {
        return $false
    }

    (Test-IpAddressInPrefix -IpAddress $firstAddress -Prefix $SecondPrefix) -or
        (Test-IpAddressInPrefix -IpAddress $secondAddress -Prefix $FirstPrefix)
}

# Supports ARM's wildcard, single-port, and inclusive port-range forms.
function Test-PortRangeContains {
    param(
        [Parameter(Mandatory)][string]$PortRange,
        [Parameter(Mandatory)][int]$Port
    )

    if ($PortRange -in @('*', 'Any')) { return $true }
    $singlePort = 0
    if ([int]::TryParse($PortRange, [ref]$singlePort)) { return $singlePort -eq $Port }

    if ($PortRange -match '^(?<start>\d+)-(?<end>\d+)$') {
        return $Port -ge [int]$Matches.start -and $Port -le [int]$Matches.end
    }
    return $false
}

# Basic listeners match any host; host-scoped listeners use case-insensitive wildcard matching.
function Test-ApplicationGatewayListenerHost {
    param(
        [AllowNull()][string]$HostName,
        [AllowEmptyCollection()][string[]]$ListenerHosts
    )

    $configuredHosts = @($ListenerHosts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if (-not $configuredHosts) { return $true }
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $false }

    foreach ($configuredHost in $configuredHosts) {
        # Escape literal regex syntax before enabling only the listener's '*' and '?' wildcards.
        $pattern = '^' + [regex]::Escape($configuredHost).Replace('\*', '.*').Replace('\?', '.') + '$'
        if ([regex]::IsMatch($HostName, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) { return $true }
    }
    return $false
}

# Loads Application Gateway resources and their dependent VNets, NSGs, and WAF policies in
# set-based ARG queries. The returned object is reused for every origin row.
function Get-ApplicationGatewaySecurityInventory {
    param(
        [Parameter(Mandatory)][hashtable]$Headers,
        [Parameter(Mandatory)][string[]]$SubscriptionIds,
        [AllowEmptyCollection()][string[]]$ApplicationGatewayIds
    )

    $gatewayResources = Get-AzureResourcesById -Headers $Headers -SubscriptionIds $SubscriptionIds -ResourceIds $ApplicationGatewayIds
    $subnetIds = [System.Collections.Generic.List[string]]::new()
    $vnetIds = [System.Collections.Generic.List[string]]::new()
    $seenSubnetIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seenVnetIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $wafPolicyIds = [System.Collections.Generic.List[string]]::new()
    $seenWafPolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # Discover dependency IDs first, including listener/path overrides of the global WAF policy.
    foreach ($gateway in $gatewayResources.Values) {
        $properties = Get-PropValue $gateway 'properties'
        foreach ($gatewayIpConfiguration in @((Get-PropValue $properties 'gatewayIPConfigurations'))) {
            $gatewayIpProperties = Get-PropValue $gatewayIpConfiguration 'properties'
            $subnetId = [string](Get-PropValue (Get-PropValue $gatewayIpProperties 'subnet') 'id')
            if (-not [string]::IsNullOrWhiteSpace($subnetId) -and $seenSubnetIds.Add($subnetId)) {
                $subnetIds.Add($subnetId)
                $vnetId = Get-AzureOwningResourceId -ResourceId $subnetId
                if ($vnetId -and $seenVnetIds.Add($vnetId)) { $vnetIds.Add($vnetId) }
            }
        }

        $policyCandidates = [System.Collections.Generic.List[string]]::new()
        $globalPolicyId = [string](Get-PropValue (Get-PropValue $properties 'firewallPolicy') 'id')
        if ($globalPolicyId) { $policyCandidates.Add($globalPolicyId) }

        foreach ($listener in @((Get-PropValue $properties 'httpListeners'))) {
            $policyId = [string](Get-PropValue (Get-PropValue (Get-PropValue $listener 'properties') 'firewallPolicy') 'id')
            if ($policyId) { $policyCandidates.Add($policyId) }
        }
        foreach ($urlPathMap in @((Get-PropValue $properties 'urlPathMaps'))) {
            $urlPathProperties = Get-PropValue $urlPathMap 'properties'
            $defaultPolicyId = [string](Get-PropValue (Get-PropValue (Get-PropValue $urlPathProperties 'defaultPathRule') 'firewallPolicy') 'id')
            if ($defaultPolicyId) { $policyCandidates.Add($defaultPolicyId) }
            foreach ($pathRule in @((Get-PropValue $urlPathProperties 'pathRules'))) {
                $pathPolicyId = [string](Get-PropValue (Get-PropValue (Get-PropValue $pathRule 'properties') 'firewallPolicy') 'id')
                if ($pathPolicyId) { $policyCandidates.Add($pathPolicyId) }
            }
        }

        foreach ($policyId in $policyCandidates) {
            if (-not [string]::IsNullOrWhiteSpace($policyId) -and $seenWafPolicyIds.Add($policyId)) {
                $wafPolicyIds.Add($policyId)
            }
        }
    }

    $vnetResources = Get-AzureResourcesById -Headers $Headers -SubscriptionIds $SubscriptionIds -ResourceIds @($vnetIds)
    $subnetLookup = @{}
    $nsgIds = [System.Collections.Generic.List[string]]::new()
    $seenNsgIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # Subnets are embedded in VNet properties; retain only those referenced by gateway IP configs.
    foreach ($vnet in $vnetResources.Values) {
        foreach ($subnet in @((Get-PropValue (Get-PropValue $vnet 'properties') 'subnets'))) {
            $subnetId = [string](Get-PropValue $subnet 'id')
            if ([string]::IsNullOrWhiteSpace($subnetId) -or -not $seenSubnetIds.Contains($subnetId)) { continue }

            $subnetProperties = Get-PropValue $subnet 'properties'
            $nsgId = [string](Get-PropValue (Get-PropValue $subnetProperties 'networkSecurityGroup') 'id')
            $addressPrefixes = Get-ArmStringValues -Object $subnetProperties -PropertyNames @('addressPrefix', 'addressPrefixes')
            $subnetLookup[$subnetId] = [pscustomobject]@{
                Id                     = $subnetId
                AddressPrefixes        = @($addressPrefixes)
                NetworkSecurityGroupId = if ([string]::IsNullOrWhiteSpace($nsgId)) { $null } else { $nsgId }
            }
            if ($nsgId -and $seenNsgIds.Add($nsgId)) { $nsgIds.Add($nsgId) }
        }
    }

    [pscustomobject]@{
        Gateways    = $gatewayResources
        Subnets     = $subnetLookup
        Nsgs        = Get-AzureResourcesById -Headers $Headers -SubscriptionIds $SubscriptionIds -ResourceIds @($nsgIds)
        WafPolicies = Get-AzureResourcesById -Headers $Headers -SubscriptionIds $SubscriptionIds -ResourceIds @($wafPolicyIds)
    }
}

# Restrict evaluation to inbound TCP rules for the origin port and a matching frontend/subnet.
function Test-NsgRuleAppliesToOrigin {
    param(
        [Parameter(Mandatory)][object]$Rule,
        [Parameter(Mandatory)][int]$Port,
        [AllowEmptyCollection()][string[]]$PublicIpAddresses,
        [AllowEmptyCollection()][string[]]$SubnetPrefixes
    )

    $properties = Get-PropValue $Rule 'properties'
    if ([string](Get-PropValue $properties 'direction') -ine 'Inbound') { return $false }
    $protocol = [string](Get-PropValue $properties 'protocol')
    if ($protocol -notin @('*', 'Tcp')) { return $false }

    $portRanges = Get-ArmStringValues -Object $properties -PropertyNames @('destinationPortRange', 'destinationPortRanges')
    if (-not $portRanges -or -not @($portRanges | Where-Object { Test-PortRangeContains -PortRange $_ -Port $Port })) {
        return $false
    }

    # Application Gateway instances aren't members of application security groups, so an
    # ASG-targeted rule doesn't apply to their frontend traffic.
    $destinationAsgs = @((Get-PropValue $properties 'destinationApplicationSecurityGroups') | Where-Object { $null -ne $_ })
    if ($destinationAsgs.Count -gt 0) { return $false }

    $destinationPrefixes = Get-ArmStringValues -Object $properties -PropertyNames @('destinationAddressPrefix', 'destinationAddressPrefixes')
    if (-not $destinationPrefixes) { return $false }
    # Accept subnet overlap as well as public frontend matches; gateway instance IPs are not enumerated.
    foreach ($destinationPrefix in $destinationPrefixes) {
        if ($destinationPrefix -in @('*', 'Any', 'VirtualNetwork')) { return $true }
        foreach ($publicIpAddress in $PublicIpAddresses) {
            if (Test-IpAddressInPrefix -IpAddress $publicIpAddress -Prefix $destinationPrefix) { return $true }
        }
        foreach ($subnetPrefix in $SubnetPrefixes) {
            if (Test-IpPrefixesOverlap -FirstPrefix $subnetPrefix -SecondPrefix $destinationPrefix) { return $true }
        }
    }
    return $false
}

# Separate the dedicated AFD tag from private/platform exemptions and other possible public sources.
# This is a configuration heuristic, not expansion of Azure's changing service-tag IP ranges.
function Get-NsgSourceClassification {
    param([Parameter(Mandatory)][object]$Rule)

    $properties = Get-PropValue $Rule 'properties'
    $sourceAsgs = @((Get-PropValue $properties 'sourceApplicationSecurityGroups') | Where-Object { $null -ne $_ })
    if ($sourceAsgs.Count -gt 0) { return 'Exempt' }
    $sourcePrefixes = Get-ArmStringValues -Object $properties -PropertyNames @('sourceAddressPrefix', 'sourceAddressPrefixes')
    if (-not $sourcePrefixes) { return 'Unknown' }

    $hasAfd = $false
    foreach ($sourcePrefix in $sourcePrefixes) {
        if ($sourcePrefix -ieq 'AzureFrontDoor.Backend') {
            $hasAfd = $true
            continue
        }
        if ($sourcePrefix -in @('GatewayManager', 'AzureLoadBalancer', 'VirtualNetwork', '168.63.129.16', '169.254.169.254')) {
            continue
        }
        if ($sourcePrefix -in @('*', 'Any', 'Internet')) { return 'Public' }

        $networkAddress = ($sourcePrefix -split '/', 2)[0]
        $kind = Get-IpAddressKind -IpAddress $networkAddress
        if ($kind -like 'Private*' -or $kind -like 'UniqueLocal*' -or $kind -like 'LinkLocal*') {
            continue
        }
        return 'Public'
    }

    if ($hasAfd) { 'AzureFrontDoor.Backend' } else { 'Exempt' }
}

# Identify rules that could affect AFD before accepting a dedicated service-tag allow.
function Test-NsgRuleSourceMatchesFrontDoor {
    param([Parameter(Mandatory)][object]$Rule)

    # Any explicit public prefix/service tag might overlap the dynamic Front Door ranges. Treat it
    # conservatively as Front Door-affecting so a higher-priority CIDR deny can't be overlooked.
    (Get-NsgSourceClassification -Rule $Rule) -in @('AzureFrontDoor.Backend', 'Public')
}

# Backend connections use varying source ports; a restricted source-port allow is insufficient.
function Test-NsgRuleAllowsAllSourcePorts {
    param([Parameter(Mandatory)][object]$Rule)

    $properties = Get-PropValue $Rule 'properties'
    $sourcePortRanges = Get-ArmStringValues -Object $properties -PropertyNames @('sourcePortRange', 'sourcePortRanges')
    foreach ($sourcePortRange in $sourcePortRanges) {
        if ($sourcePortRange -in @('*', 'Any', '0-65535', '1-65535')) { return $true }
    }
    return $false
}

# Conservatively evaluates whether an NSG permits the Front Door backend service tag on the
# origin port while rejecting other public client sources. Platform and private-network rules
# do not invalidate the result.
function Get-ApplicationGatewayNsgResult {
    param(
        [AllowNull()][object]$Nsg,
        [AllowNull()][string]$NsgResourceId,
        [Parameter(Mandatory)][int]$Port,
        [AllowEmptyCollection()][string[]]$PublicIpAddresses,
        [AllowEmptyCollection()][string[]]$SubnetPrefixes
    )

    if ($null -eq $Nsg) {
        if (-not [string]::IsNullOrWhiteSpace($NsgResourceId)) {
            return [pscustomobject]@{ Status = 'Unknown'; Reason = "Subnet NSG '$NsgResourceId' could not be read." }
        }
        return [pscustomobject]@{ Status = 'No'; Reason = 'Application Gateway subnet has no NSG.' }
    }

    # Lower numeric priority wins; custom and default rules must be considered in the same order.
    $properties = Get-PropValue $Nsg 'properties'
    $rules = @(
        @((Get-PropValue $properties 'securityRules'))
        @((Get-PropValue $properties 'defaultSecurityRules'))
    ) | Sort-Object { [int](Get-PropValue (Get-PropValue $_ 'properties') 'priority') }

    $applicableRules = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $rules) {
        $applies = Test-NsgRuleAppliesToOrigin -Rule $rule -Port $Port -PublicIpAddresses $PublicIpAddresses -SubnetPrefixes $SubnetPrefixes
        if ($applies) { $applicableRules.Add($rule) }
    }

    # Later public allows cannot bypass an earlier broad deny in this conservative rule model.
    $broadDenyPriority = $null
    foreach ($rule in $applicableRules) {
        $ruleProperties = Get-PropValue $rule 'properties'
        if ([string](Get-PropValue $ruleProperties 'access') -ine 'Deny') { continue }
        $sourcePrefixes = Get-ArmStringValues -Object $ruleProperties -PropertyNames @('sourceAddressPrefix', 'sourceAddressPrefixes')
        if (@($sourcePrefixes | Where-Object { $_ -in @('*', 'Any', 'Internet') }).Count -gt 0) {
            $broadDenyPriority = [int](Get-PropValue $ruleProperties 'priority')
            break
        }
    }
    # ARG doesn't consistently expose properties.defaultSecurityRules. Every NSG still has the
    # platform DenyAllInBound rule at priority 65500, so use that as the effective final deny.
    if ($null -eq $broadDenyPriority) { $broadDenyPriority = 65500 }

    # A prior public deny or broader allow prevents proving a dedicated AFD-only ingress path.
    $firstFrontDoorRule = $applicableRules | Where-Object { Test-NsgRuleSourceMatchesFrontDoor -Rule $_ } | Select-Object -First 1
    if ($null -eq $firstFrontDoorRule) {
        return [pscustomobject]@{ Status = 'No'; Reason = "No effective AzureFrontDoor.Backend allow rule was found for TCP port $Port." }
    }
    $firstFrontDoorProperties = Get-PropValue $firstFrontDoorRule 'properties'
    $firstFrontDoorClassification = Get-NsgSourceClassification -Rule $firstFrontDoorRule
    if ([string](Get-PropValue $firstFrontDoorProperties 'access') -ine 'Allow' -or $firstFrontDoorClassification -ne 'AzureFrontDoor.Backend') {
        return [pscustomobject]@{
            Status = 'No'
            Reason = "Higher-priority NSG rule '$([string](Get-PropValue $firstFrontDoorRule 'name'))' prevents a dedicated AzureFrontDoor.Backend allow on TCP port $Port."
        }
    }
    if (-not (Test-NsgRuleAllowsAllSourcePorts -Rule $firstFrontDoorRule)) {
        return [pscustomobject]@{
            Status = 'No'
            Reason = "AzureFrontDoor.Backend rule '$([string](Get-PropValue $firstFrontDoorRule 'name'))' restricts source ports instead of allowing Any."
        }
    }

    foreach ($rule in $applicableRules) {
        $ruleProperties = Get-PropValue $rule 'properties'
        $priority = [int](Get-PropValue $ruleProperties 'priority')
        if ($priority -ge $broadDenyPriority) { continue }

        # Unknown sources prevent a positive finding; non-AFD public allows explicitly fail it.
        $classification = Get-NsgSourceClassification -Rule $rule
        if ($classification -eq 'Unknown') {
            return [pscustomobject]@{ Status = 'Unknown'; Reason = "NSG rule '$([string](Get-PropValue $rule 'name'))' has an unsupported source configuration." }
        }
        if ([string](Get-PropValue $ruleProperties 'access') -ine 'Allow') { continue }

        if ($classification -eq 'Public') {
            return [pscustomobject]@{ Status = 'No'; Reason = "NSG rule '$([string](Get-PropValue $rule 'name'))' allows another public source before the deny rule." }
        }
    }
    [pscustomobject]@{ Status = 'Yes'; Reason = "NSG allows AzureFrontDoor.Backend and blocks other public sources on TCP port $Port." }
}

# Recognize only a single Equal condition for the exact profile FDID, optionally negated.
# More complex operators/conditions are not treated as proof of profile-specific enforcement.
function Test-WafHeaderCondition {
    param(
        [Parameter(Mandatory)][object]$Condition,
        [Parameter(Mandatory)][string]$FrontDoorId,
        [Parameter(Mandatory)][bool]$Negated
    )

    # ARM has exposed both spellings of the negation property.
    $negationValue = (Get-PropValue $Condition 'negationCondition') ?? (Get-PropValue $Condition 'negationConditon')
    if ([bool]$negationValue -ne $Negated) { return $false }
    if ([string](Get-PropValue $Condition 'operator') -ine 'Equal') { return $false }

    $matchVariables = @((Get-PropValue $Condition 'matchVariables'))
    if ($matchVariables.Count -ne 1) { return $false }
    if ([string](Get-PropValue $matchVariables[0] 'variableName') -ine 'RequestHeaders') { return $false }
    if ([string](Get-PropValue $matchVariables[0] 'selector') -ine 'X-Azure-FDID') { return $false }

    # Normalize GUID casing/braces for this static comparison; do not emulate WAF transformations.
    $expected = $FrontDoorId.Trim().Trim('{', '}').ToLowerInvariant()
    $normalizedValues = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($matchValue in @((Get-PropValue $Condition 'matchValues'))) {
        if (-not [string]::IsNullOrWhiteSpace([string]$matchValue)) {
            [void]$normalizedValues.Add(([string]$matchValue).Trim().Trim('{', '}').ToLowerInvariant())
        }
    }
    return $normalizedValues.Count -eq 1 -and $normalizedValues.Contains($expected)
}

# Prove a narrow enforcement pattern: enabled Prevention policy blocking every mismatched FDID.
function Get-WafPolicyFrontDoorResult {
    param(
        [AllowNull()][object]$Policy,
        [Parameter(Mandatory)][string]$FrontDoorId
    )

    if ($null -eq $Policy) {
        return [pscustomobject]@{ Enforced = $false; Reason = 'Effective WAF policy could not be read.' }
    }
    if ([string]::IsNullOrWhiteSpace($FrontDoorId)) {
        return [pscustomobject]@{ Enforced = $false; Reason = 'Front Door profile did not expose properties.frontDoorId.' }
    }

    $properties = Get-PropValue $Policy 'properties'
    $settings = Get-PropValue $properties 'policySettings'
    if ([string](Get-PropValue $settings 'state') -ine 'Enabled') {
        return [pscustomobject]@{ Enforced = $false; Reason = 'WAF policy is disabled.' }
    }
    if ([string](Get-PropValue $settings 'mode') -ine 'Prevention') {
        return [pscustomobject]@{ Enforced = $false; Reason = 'WAF policy is not in Prevention mode.' }
    }

    $rules = @((Get-PropValue $properties 'customRules')) |
        Where-Object { [string](Get-PropValue $_ 'state') -ieq 'Enabled' } |
        Sort-Object { [int](Get-PropValue $_ 'priority') }

    # Extra AND conditions would narrow the mismatch block, so require exactly one condition.
    foreach ($rule in $rules) {
        if ([string](Get-PropValue $rule 'action') -ine 'Block' -or [string](Get-PropValue $rule 'ruleType') -ine 'MatchRule') { continue }
        $conditions = @((Get-PropValue $rule 'matchConditions'))
        if ($conditions.Count -ne 1 -or -not (Test-WafHeaderCondition -Condition $conditions[0] -FrontDoorId $FrontDoorId -Negated $true)) { continue }

        $rulePriority = [int](Get-PropValue $rule 'priority')
        # Earlier Allow actions short-circuit WAF; only an exact expected-FDID allow is safe here.
        foreach ($earlierRule in $rules) {
            $earlierPriority = [int](Get-PropValue $earlierRule 'priority')
            if ($earlierPriority -ge $rulePriority) { break }
            if ([string](Get-PropValue $earlierRule 'action') -ine 'Allow') { continue }

            $earlierConditions = @((Get-PropValue $earlierRule 'matchConditions'))
            $isExpectedFrontDoorAllow = $earlierConditions.Count -eq 1 -and
                (Test-WafHeaderCondition -Condition $earlierConditions[0] -FrontDoorId $FrontDoorId -Negated $false)
            if (-not $isExpectedFrontDoorAllow) {
                return [pscustomobject]@{ Enforced = $false; Reason = "Earlier WAF Allow rule '$([string](Get-PropValue $earlierRule 'name'))' could bypass the FDID block." }
            }
        }

        return [pscustomobject]@{ Enforced = $true; Reason = "WAF rule '$([string](Get-PropValue $rule 'name'))' blocks requests whose X-Azure-FDID differs from $FrontDoorId." }
    }

    [pscustomobject]@{ Enforced = $false; Reason = "No enabled Prevention-mode WAF block rule validates X-Azure-FDID against $FrontDoorId." }
}

# Collect every effective policy on matching listeners/paths; any uncovered scope prevents proof.
function Get-ApplicationGatewayEffectiveWafPolicies {
    param(
        [Parameter(Mandatory)][object]$Gateway,
        [AllowEmptyCollection()][string[]]$FrontendIpConfigurationIds,
        [Parameter(Mandatory)][int]$Port,
        [AllowNull()][string]$HostName
    )

    $properties = Get-PropValue $Gateway 'properties'
    $frontendPorts = @{}
    foreach ($frontendPort in @((Get-PropValue $properties 'frontendPorts'))) {
        $frontendPorts[[string](Get-PropValue $frontendPort 'id')] = [int](Get-PropValue (Get-PropValue $frontendPort 'properties') 'port')
    }

    # Match the resolved frontend, HTTPS port, and configured origin host header before reading policies.
    $listeners = [System.Collections.Generic.List[object]]::new()
    foreach ($listener in @((Get-PropValue $properties 'httpListeners'))) {
        $listenerProperties = Get-PropValue $listener 'properties'
        $frontendId = [string](Get-PropValue (Get-PropValue $listenerProperties 'frontendIPConfiguration') 'id')
        $frontendPortId = [string](Get-PropValue (Get-PropValue $listenerProperties 'frontendPort') 'id')
        if ($FrontendIpConfigurationIds.Count -gt 0 -and $frontendId -notin $FrontendIpConfigurationIds) { continue }
        if (-not $frontendPorts.ContainsKey($frontendPortId) -or $frontendPorts[$frontendPortId] -ne $Port) { continue }

        $listenerHosts = Get-ArmStringValues -Object $listenerProperties -PropertyNames @('hostName', 'hostNames')
        if (Test-ApplicationGatewayListenerHost -HostName $HostName -ListenerHosts $listenerHosts) {
            $listeners.Add($listener)
        }
    }

    if (-not $listeners) {
        return [pscustomobject]@{ PolicyIds = @(); HasUnprotectedScope = $true; Reason = 'No matching Application Gateway listener was found.' }
    }

    $globalPolicyId = [string](Get-PropValue (Get-PropValue $properties 'firewallPolicy') 'id')
    $routingRules = @((Get-PropValue $properties 'requestRoutingRules'))
    $urlPathMaps = @{}
    foreach ($urlPathMap in @((Get-PropValue $properties 'urlPathMaps'))) {
        $urlPathMaps[[string](Get-PropValue $urlPathMap 'id')] = $urlPathMap
    }

    $policyIds = [System.Collections.Generic.List[string]]::new()
    $seenPolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $hasUnprotectedScope = $false

    foreach ($listener in $listeners) {
        $listenerId = [string](Get-PropValue $listener 'id')
        $listenerProperties = Get-PropValue $listener 'properties'
        $listenerPolicyId = [string](Get-PropValue (Get-PropValue $listenerProperties 'firewallPolicy') 'id')
        # Listener policy overrides the gateway policy; path policies override that inherited base.
        $basePolicyId = if ($listenerPolicyId) { $listenerPolicyId } else { $globalPolicyId }
        $listenerRules = @($routingRules | Where-Object {
            [string](Get-PropValue (Get-PropValue (Get-PropValue $_ 'properties') 'httpListener') 'id') -ieq $listenerId
        })

        if (-not $listenerRules) {
            if ($basePolicyId) {
                if ($seenPolicyIds.Add($basePolicyId)) { $policyIds.Add($basePolicyId) }
            }
            else {
                $hasUnprotectedScope = $true
            }
            continue
        }

        foreach ($routingRule in $listenerRules) {
            $routingProperties = Get-PropValue $routingRule 'properties'
            $urlPathMapId = [string](Get-PropValue (Get-PropValue $routingProperties 'urlPathMap') 'id')
            if (-not $urlPathMapId -or -not $urlPathMaps.ContainsKey($urlPathMapId)) {
                if ($basePolicyId) {
                    if ($seenPolicyIds.Add($basePolicyId)) { $policyIds.Add($basePolicyId) }
                }
                else {
                    $hasUnprotectedScope = $true
                }
                continue
            }

            # No request path is known, so assess the default and every explicit path rule.
            $urlPathProperties = Get-PropValue $urlPathMaps[$urlPathMapId] 'properties'
            $defaultPathRule = Get-PropValue $urlPathProperties 'defaultPathRule'
            $defaultPolicyId = [string](Get-PropValue (Get-PropValue $defaultPathRule 'firewallPolicy') 'id')
            $effectiveDefaultPolicyId = if ($defaultPolicyId) { $defaultPolicyId } else { $basePolicyId }
            if ($effectiveDefaultPolicyId) {
                if ($seenPolicyIds.Add($effectiveDefaultPolicyId)) { $policyIds.Add($effectiveDefaultPolicyId) }
            }
            else {
                $hasUnprotectedScope = $true
            }

            foreach ($pathRule in @((Get-PropValue $urlPathProperties 'pathRules'))) {
                $pathPolicyId = [string](Get-PropValue (Get-PropValue (Get-PropValue $pathRule 'properties') 'firewallPolicy') 'id')
                $effectivePathPolicyId = if ($pathPolicyId) { $pathPolicyId } else { $basePolicyId }
                if ($effectivePathPolicyId) {
                    if ($seenPolicyIds.Add($effectivePathPolicyId)) { $policyIds.Add($effectivePathPolicyId) }
                }
                else {
                    $hasUnprotectedScope = $true
                }
            }
        }
    }

    [pscustomobject]@{
        PolicyIds          = @($policyIds)
        HasUnprotectedScope = $hasUnprotectedScope
        Reason             = if ($hasUnprotectedScope) { 'At least one matching listener or path has no effective WAF policy.' } else { $null }
    }
}

# Combine all mapped gateways conservatively: every subnet must pass NSG checks before WAF adds assurance.
# Blank means not associated with an App Gateway; Unknown means evidence was insufficient.
function Get-ApplicationGatewayOriginSecurityResult {
    param(
        [Parameter(Mandatory)][object]$Record,
        [AllowNull()][object]$ResolutionResult,
        [AllowNull()][object]$Inventory
    )

    $applicationGatewayIds = @(([string](Get-PropValue $ResolutionResult 'ApplicationGatewayResourceId')) -split ';\s*' |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if (-not $applicationGatewayIds) {
        return [pscustomobject]@{
            Status              = $null
            Reason              = $null
            NsgResourceIds      = $null
            WafPolicyIds        = $null
        }
    }
    if ($null -eq $Inventory) {
        return [pscustomobject]@{
            Status              = 'Unknown'
            Reason              = 'Application Gateway security inventory was unavailable.'
            NsgResourceIds      = $null
            WafPolicyIds        = $null
        }
    }

    $frontendIds = @(([string](Get-PropValue $ResolutionResult 'ApplicationGatewayFrontendIpConfigId')) -split ';\s*' |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $unverifiedPublicIps = @(([string](Get-PropValue $ResolutionResult 'ApplicationGatewayUnverifiedPublicIps')) -split ';\s*' |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $publicIpAddresses = @((Get-PropValue $ResolutionResult 'ResolvedAddresses') | Where-Object {
        (Get-IpAddressKind -IpAddress ([string]$_)) -like 'Public*'
    })
    $port = Get-TlsProbePort -Record $Record
    $originHostHeader = [string](Get-PropValue $Record 'OriginHostHeader')

    $nsgIds = [System.Collections.Generic.List[string]]::new()
    $wafPolicyIds = [System.Collections.Generic.List[string]]::new()
    $seenNsgIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seenWafPolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $reasons = [System.Collections.Generic.List[string]]::new()
    $allNsgRestricted = $true
    $nsgUnknown = $false
    $allWafEnforced = $true
    $hasUnverifiedPublicIps = $unverifiedPublicIps.Count -gt 0
    if ($hasUnverifiedPublicIps) {
        $reasons.Add("Not every resolved public address maps to an analyzed Application Gateway: $($unverifiedPublicIps -join ', ').")
    }

    foreach ($applicationGatewayId in $applicationGatewayIds) {
        if (-not $Inventory.Gateways.ContainsKey($applicationGatewayId)) {
            $nsgUnknown = $true
            $allNsgRestricted = $false
            $allWafEnforced = $false
            $reasons.Add("Application Gateway '$applicationGatewayId' could not be read.")
            continue
        }

        $gateway = $Inventory.Gateways[$applicationGatewayId]
        $gatewayProperties = Get-PropValue $gateway 'properties'
        $gatewaySubnets = [System.Collections.Generic.List[object]]::new()
        foreach ($gatewayIpConfiguration in @((Get-PropValue $gatewayProperties 'gatewayIPConfigurations'))) {
            $subnetId = [string](Get-PropValue (Get-PropValue (Get-PropValue $gatewayIpConfiguration 'properties') 'subnet') 'id')
            if ($subnetId -and $Inventory.Subnets.ContainsKey($subnetId)) {
                $gatewaySubnets.Add($Inventory.Subnets[$subnetId])
            }
        }

        if (-not $gatewaySubnets) {
            $nsgUnknown = $true
            $allNsgRestricted = $false
            $allWafEnforced = $false
            $reasons.Add("Gateway subnet metadata was unavailable for '$applicationGatewayId'.")
            continue
        }

        foreach ($subnet in $gatewaySubnets) {
            $nsg = $null
            if ($subnet.NetworkSecurityGroupId) {
                if ($seenNsgIds.Add($subnet.NetworkSecurityGroupId)) { $nsgIds.Add($subnet.NetworkSecurityGroupId) }
                if ($Inventory.Nsgs.ContainsKey($subnet.NetworkSecurityGroupId)) {
                    $nsg = $Inventory.Nsgs[$subnet.NetworkSecurityGroupId]
                }
            }

            $nsgResult = Get-ApplicationGatewayNsgResult -Nsg $nsg -NsgResourceId $subnet.NetworkSecurityGroupId -Port $port -PublicIpAddresses $publicIpAddresses -SubnetPrefixes @($subnet.AddressPrefixes)
            $reasons.Add($nsgResult.Reason)
            if ($nsgResult.Status -ne 'Yes') {
                $allNsgRestricted = $false
                if ($nsgResult.Status -eq 'Unknown') { $nsgUnknown = $true }
            }
        }

        # WAF alone does not establish network restriction to AFD, so stop short of Yes+WAF.
        if (-not $allNsgRestricted) {
            $allWafEnforced = $false
            continue
        }

        if ([string]::IsNullOrWhiteSpace($originHostHeader)) {
            $allWafEnforced = $false
            $reasons.Add('OriginHostHeader is blank, so the incoming request hostname and effective Application Gateway listener cannot be determined from the origin record.')
            continue
        }

        $gatewayFrontendIds = @($frontendIds | Where-Object { $_ -like "$applicationGatewayId/*" })
        $effectivePolicies = Get-ApplicationGatewayEffectiveWafPolicies -Gateway $gateway -FrontendIpConfigurationIds $gatewayFrontendIds -Port $port -HostName $originHostHeader
        if ($effectivePolicies.HasUnprotectedScope -or -not $effectivePolicies.PolicyIds) {
            $allWafEnforced = $false
            $reasons.Add($effectivePolicies.Reason ?? 'No effective WAF policy was associated with the matching listener.')
            continue
        }

        foreach ($policyId in $effectivePolicies.PolicyIds) {
            if ($seenWafPolicyIds.Add($policyId)) { $wafPolicyIds.Add($policyId) }
            $policy = if ($Inventory.WafPolicies.ContainsKey($policyId)) { $Inventory.WafPolicies[$policyId] } else { $null }
            $wafResult = Get-WafPolicyFrontDoorResult -Policy $policy -FrontDoorId ([string](Get-PropValue $Record 'FrontDoorId'))
            $reasons.Add($wafResult.Reason)
            if (-not $wafResult.Enforced) { $allWafEnforced = $false }
        }
    }

    # Aggregate across all associations, not just the first passing gateway or policy.
    $status = if ($allNsgRestricted -and $allWafEnforced) {
        'Yes+WAF'
    }
    elseif ($allNsgRestricted) {
        'Yes'
    }
    elseif ($nsgUnknown) {
        'Unknown'
    }
    else {
        'No'
    }
    # An unexplained public address leaves an unassessed ingress path even when known gateways pass.
    if ($hasUnverifiedPublicIps -and $status -in @('Yes', 'Yes+WAF')) {
        $status = 'Unknown'
    }

    [pscustomobject]@{
        Status         = $status
        Reason         = @($reasons | Sort-Object -Unique) -join ' '
        NsgResourceIds = if ($nsgIds.Count) { $nsgIds -join '; ' } else { $null }
        WafPolicyIds   = if ($wafPolicyIds.Count) { $wafPolicyIds -join '; ' } else { $null }
    }
}

# Collapse detailed diagnostics into stable reporting buckets without changing the exported status.
function Get-TlsStatusCategory {
    param([AllowNull()][string]$TlsStatus)

    switch -Regex ($TlsStatus) {
        '^(Expired)?(NoChain|PartialChain|FullChain)$' { return $Matches[2] }
        '^MSFT$'                  { return 'MicrosoftManaged' }
        '^Disabled$'              { return 'Disabled' }
        '^MigratedClassic$'       { return 'MigratedClassic' }
        '^Skipped$'               { return 'Skipped' }
        '^DnsFailure'             { return 'DnsFailure' }
        '^TlsError:'              { return 'TlsError' }
        '^NoCert$'                { return 'NoCert' }
        '^\d+ \(TimedOut\)$|^TcpTimeout$' { return 'TcpTimeout' }
        '^\d+ \(ConnectionRefused\)$|^TcpRefused$' { return 'TcpRefused' }
        '^\d+ \([^)]+\)$|^Tcp'    { return 'TcpFailure' }
        default                   { return 'Other' }
    }
}

# Count every input row once; expired rows are subsets of their chain bucket, not extra outcomes.
function Get-TlsSummary {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records)

    $counts = [ordered]@{
        NoChain = 0; PartialChain = 0; FullChain = 0
        Disabled = 0; MigratedClassic = 0
        MicrosoftManaged = 0; Skipped = 0; DnsFailure = 0
        TcpTimeout = 0; TcpRefused = 0; TcpFailure = 0
        TlsError = 0; NoCert = 0; Other = 0
    }
    $expired = @{ NoChain = 0; PartialChain = 0; FullChain = 0 }
    foreach ($record in $Records) {
        $status = [string](Get-PropValue $record 'TlsStatus')
        $category = Get-TlsStatusCategory -TlsStatus $status
        $counts[$category]++
        if ($expired.ContainsKey($category) -and $status -like 'Expired*') {
            $expired[$category]++
        }
    }
    # Only positive server-sent certificate counts are assessed, regardless of trust or expiry.
    $assessed = $counts.NoChain + $counts.PartialChain + $counts.FullChain
    [pscustomobject]@{
        Counts = $counts
        Expired = $expired
        Assessed = $assessed
        Unassessed = $Records.Count - $assessed
        Total = $Records.Count
    }
}

# Any certificate-bearing outcome, including an expired/leaf-only chain, suppresses private fallback.
function Test-NeedsPrivateIpProbe {
    param([AllowNull()][object]$TlsResult)

    [string](Get-PropValue $TlsResult 'TlsStatus') -notmatch '^(Expired)?(Full|Partial|No)Chain$'
}

# Share one report model between console and Excel, keeping row totals separate from endpoint totals.
function Get-TlsReportData {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]
        [object[]]$Records,
        [Parameter(Mandatory)][AllowEmptyCollection()]
        [object[]]$TargetRecords
    )

    $rows = Get-TlsSummary -Records $Records
    $targets = Get-TlsSummary -Records $TargetRecords
    $primaryLabels = [ordered]@{
        NoChain = 'No Chain (leaf only)'
        PartialChain = 'Partial Chain (2 certs)'
        FullChain = 'Full Chain (3+ certs)'
        NotAssessed = 'Not assessed'
    }
    # The denominator includes disabled, migrated, missing-host, and all other unassessed origin rows.
    # TargetRecords has already been deduplicated with active > disabled > migrated precedence.
    $primary = @(
        foreach ($key in $primaryLabels.Keys) {
            $count = if ($key -eq 'NotAssessed') { $rows.Unassessed } else { $rows.Counts[$key] }
            [pscustomobject]@{
                'Server-sent chain' = $primaryLabels[$key]
                Origins = $count
                'Unique targets' = if ($key -eq 'NotAssessed') { $targets.Unassessed } else { $targets.Counts[$key] }
                '% all origins' = if ($rows.Total) { $count / $rows.Total } else { 0.0 }
                'Expired origins' = if ($key -eq 'NotAssessed') { $null } else { $rows.Expired[$key] }
            }
        }
    )
    # These secondary buckets partition NotAssessed; do not add them to the primary total again.
    $labels = [ordered]@{
        Disabled = 'Disabled origins (not probed)'
        MigratedClassic = 'Migrated Classic (not probed)'
        MicrosoftManaged = 'Microsoft-managed (not probed)'
        Skipped = 'Skipped (-SkipTls)'
        DnsFailure = 'DNS failure'
        TcpTimeout = 'TCP timeout'
        TcpRefused = 'TCP connection refused'
        TcpFailure = 'Other TCP failure'
        TlsError = 'TLS / probe error'
        NoCert = 'No certificates sent'
        Other = 'Other / unavailable'
    }
    $secondary = @(
        foreach ($key in $labels.Keys) {
            [pscustomobject]@{
                Outcome = $labels[$key]
                Origins = $rows.Counts[$key]
                'Unique targets' = $targets.Counts[$key]
            }
        }
    )
    [pscustomobject]@{
        Primary = $primary
        Secondary = $secondary
        Origins = $rows.Total
        Targets = $targets.Total
        UnassessedOrigins = $rows.Unassessed
        UnassessedTargets = $targets.Unassessed
    }
}

# Render count-based chain categories first, with muted diagnostics for unassessed outcomes.
function Write-TlsStatusBreakdown {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$TargetRecords
    )

    $report = Get-TlsReportData -Records $Records -TargetRecords $TargetRecords
    Write-Host ''
    Write-Host '  ORIGIN CERTIFICATE CHAINS' -ForegroundColor Cyan
    Write-Host ('    {0,-30} {1,8} {2,14} {3,14} {4,9}' -f 'Server-sent chain', 'Origins', 'Unique targets', '% all origins', 'Expired')
    $colors = @('Yellow', 'Cyan', 'Green', 'DarkGray')
    for ($i = 0; $i -lt $report.Primary.Count; $i++) {
        $row = $report.Primary[$i]
        $percent = if ($report.Origins) { '{0:n1}%' -f (100 * $row.'% all origins') } else { '-' }
        $expired = if ($null -eq $row.'Expired origins') { '-' } else { $row.'Expired origins' }
        Write-Host ('    {0,-30} {1,8} {2,14} {3,14} {4,9}' -f $row.'Server-sent chain', $row.Origins, $row.'Unique targets', $percent, $expired) -ForegroundColor $colors[$i]
    }
    # Keep the grand total beside its four contributing categories, not inside the subset below.
    $totalPercent = if ($report.Origins) { '{0:n1}%' -f 100 } else { '-' }
    Write-Host ('    ' + ('-' * 79)) -ForegroundColor DarkGray
    Write-Host ('    {0,-30} {1,8} {2,14} {3,14} {4,9}' -f 'Grand total (all origins)', $report.Origins, $report.Targets, $totalPercent, '-')
    Write-Host '    Percentages use all origin rows. Expired = subset of origin rows.' -ForegroundColor DarkGray
    Write-Host '    Count-based labels, not chain trust/completeness validation.' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  Not assessed breakdown (included above, not additional origins):' -ForegroundColor DarkGray
    Write-Host ('    {0,-30} {1,8} {2,14}' -f 'Outcome', 'Origins', 'Unique targets') -ForegroundColor DarkGray
    foreach ($row in $report.Secondary) {
        if ($row.Origins -gt 0) {
            Write-Host ('    {0,-30} {1,8} {2,14}' -f $row.Outcome, $row.Origins, $row.'Unique targets') -ForegroundColor DarkGray
        }
    }
    Write-Host ('    ' + ('-' * 54)) -ForegroundColor DarkGray
    Write-Host ('    {0,-30} {1,8} {2,14}' -f 'Not assessed subtotal', $report.UnassessedOrigins, $report.UnassessedTargets) -ForegroundColor DarkGray
    Write-Host '    Unique targets = host/port/SNI; active rows take precedence over disabled/migrated.' -ForegroundColor DarkGray
    Write-Host '    Error details remain in CSV/XLSX TlsStatus; unassessed does not mean a bad chain.' -ForegroundColor DarkGray
}

# Build a companion summary without removing the per-origin diagnostic worksheet.
# Fixed table/chart ranges depend on the four primary categories produced by Get-TlsReportData.
function Add-TlsSummaryWorksheet {
    param(
        [Parameter(Mandatory)][object]$ExcelPackage,
        [Parameter(Mandatory)][object]$Report
    )

    $Report.Primary | Export-Excel -ExcelPackage $ExcelPackage -WorksheetName Summary -ClearSheet -StartRow 4 -TableName ChainSummary -TableStyle Medium2 -PassThru | Out-Null
    $Report.Secondary | Export-Excel -ExcelPackage $ExcelPackage -WorksheetName Summary -StartRow 13 -TableName UnassessedSummary -TableStyle Medium2 -PassThru | Out-Null
    $sheet = $ExcelPackage.Workbook.Worksheets['Summary']
    $sheet.View.ShowGridLines = $false
    $sheet.View.FreezePanes(5, 1)
    $sheet.Cells['A1:E2'].Merge = $true
    Set-ExcelRange -Range $sheet.Cells['A1:E2'] -Value 'Origin certificate chain summary' -Bold -FontSize 20 -FontColor White -BackgroundColor ([System.Drawing.ColorTranslator]::FromHtml('#17365D')) -VerticalAlignment Center
    $sheet.Cells['A3'].Value = 'All inventoried origins, including disabled and migrated Classic backends'
    $sheet.Cells['A3:E3'].Merge = $true
    # Store fractions as numeric values; percent formatting affects display, not the all-origin totals.
    $sheet.Cells['D5:D8'].Style.Numberformat.Format = '0.0%'
    $sheet.Cells['B5:C9'].Style.Numberformat.Format = '#,##0'
    $sheet.Cells['A9'].Value = 'Grand total (all origins)'
    $sheet.Cells['B9'].Value = $Report.Origins
    $sheet.Cells['C9'].Value = $Report.Targets
    $sheet.Cells['D9'].Value = if ($Report.Origins) { 1.0 } else { 0.0 }
    Set-ExcelRange -Range $sheet.Cells['D9'] -NumberFormat '0.0%'
    Set-ExcelRange -Range $sheet.Cells['A9:E9'] -Bold -BorderTop Thin
    $sheet.Cells['A10:E11'].Merge = $true
    Set-ExcelRange -Range $sheet.Cells['A10:E11'] -Value 'Percentages use all origin rows. Expired origins are subsets of the chain rows, not an additional category.' -WrapText -FontColor DimGray -VerticalAlignment Center
    $sheet.Cells['A12'].Value = 'Not assessed - breakdown (included above)'
    Set-ExcelRange -Range $sheet.Cells['A12:E12'] -Bold -FontSize 13 -FontColor DimGray
    # Secondary categories can grow without overlapping the explanatory notes below them.
    $detailEndRow = 13 + $Report.Secondary.Count
    Set-ExcelRange -Range $sheet.Cells["A14:C$detailEndRow"] -FontColor DimGray
    # A separate subtotal reconciles the breakdown to Not assessed without double-counting it.
    $subtotalRow = $detailEndRow + 1
    $sheet.Cells[$subtotalRow, 1].Value = 'Not assessed subtotal'
    $sheet.Cells[$subtotalRow, 2].Value = $Report.UnassessedOrigins
    $sheet.Cells[$subtotalRow, 3].Value = $Report.UnassessedTargets
    Set-ExcelRange -Range $sheet.Cells["A${subtotalRow}:C${subtotalRow}"] -Bold -BorderTop Thin -FontColor DimGray
    Set-ExcelRange -Range $sheet.Cells["B14:C${subtotalRow}"] -NumberFormat '#,##0'
    # Match the chart's category order: leaf-only yellow, two-cert blue, 3+ green, unassessed gray.
    Set-ExcelRange -Range $sheet.Cells['A5:E5'] -BackgroundColor ([System.Drawing.ColorTranslator]::FromHtml('#FFF2CC'))
    Set-ExcelRange -Range $sheet.Cells['A6:E6'] -BackgroundColor ([System.Drawing.ColorTranslator]::FromHtml('#DDEBF7'))
    Set-ExcelRange -Range $sheet.Cells['A7:E7'] -BackgroundColor ([System.Drawing.ColorTranslator]::FromHtml('#E2EFDA'))
    Set-ExcelRange -Range $sheet.Cells['A8:E8'] -BackgroundColor ([System.Drawing.ColorTranslator]::FromHtml('#E7E6E6')) -FontColor DimGray
    $sheet.Column(1).Width = 38
    foreach ($column in 2..5) { $sheet.Column($column).Width = 18 }
    $sheet.Column(6).Width = 3

    $chart = Add-ExcelChart -Worksheet $sheet -ChartType Doughnut -Title 'Share of all origins' -TitleBold -XRange 'A5:A8' -YRange 'B5:B8' -SeriesHeader 'Origins' -ShowPercent -LegendPosition Bottom -Row 3 -Column 6 -Width 640 -Height 400 -PassThru
    # This bundled EPPlus version lacks point-color/label-format APIs; use standard chart XML.
    $chartNamespace = 'http://schemas.openxmlformats.org/drawingml/2006/chart'
    $drawingNamespace = 'http://schemas.openxmlformats.org/drawingml/2006/main'
    $namespaces = [System.Xml.XmlNamespaceManager]::new($chart.ChartXml.NameTable)
    $namespaces.AddNamespace('c', $chartNamespace)
    # Disable source-linked formatting so percentage labels consistently show one decimal place.
    $labelFormat = $chart.ChartXml.CreateElement('c', 'numFmt', $chartNamespace)
    $labelFormat.SetAttribute('formatCode', '0.0%')
    $labelFormat.SetAttribute('sourceLinked', '0')
    [void]$chart.ChartXml.SelectSingleNode('//c:dLbls', $namespaces).PrependChild($labelFormat)
    $series = $chart.ChartXml.SelectSingleNode('//c:ser', $namespaces)
    $categoryNode = $series.SelectSingleNode('c:cat', $namespaces)
    $pointColors = @('FFC000', '5B9BD5', '70AD47', 'A5A5A5')
    # Use zero-based point indices and insert before c:cat to preserve chart schema element order.
    for ($i = 0; $i -lt $pointColors.Count; $i++) {
        $point = $chart.ChartXml.CreateElement('c', 'dPt', $chartNamespace)
        $point.InnerXml = "<c:idx xmlns:c='$chartNamespace' val='$i'/><c:spPr xmlns:c='$chartNamespace'><a:solidFill xmlns:a='$drawingNamespace'><a:srgbClr val='$($pointColors[$i])'/></a:solidFill></c:spPr>"
        [void]$series.InsertBefore($point, $categoryNode)
    }
    $notes = @(
        'Unique targets = hostname + HTTPS port + effective SNI. Active rows take precedence over disabled, then migrated rows for shared endpoints.'
        'Disabled and migrated Classic origins remain in inventory but are not probed. Missing hostnames count as origins, not targets.'
        'Chain labels count certificates sent (1 / 2 / 3+); they do not validate completeness or trust. Diagnostics are on the first worksheet.'
    )
    for ($i = 0; $i -lt $notes.Count; $i++) {
        $row = $detailEndRow + 4 + $i
        $sheet.Cells["A${row}:N${row}"].Merge = $true
        Set-ExcelRange -Range $sheet.Cells["A${row}:N${row}"] -Value $notes[$i] -FontColor DimGray -WrapText -Height 30
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

            # Replace only the changed ZIP member, retaining other workbook metadata and UTF-8 encoding.
            $entryPath = $tableEntry.FullName
            $tableEntry.Delete()
            $writer = [System.IO.StreamWriter]::new($zip.CreateEntry($entryPath).Open(), [System.Text.UTF8Encoding]::new($false))
            try { $writer.Write($updated) } finally { $writer.Dispose() }
        }
    }
    finally { $zip.Dispose() }
}

# Fail before discovery rather than attempting a different authentication mechanism.
try {
    Import-Module Az.Accounts -ErrorAction Stop
}
catch {
    throw "Az.Accounts is required. Install it with 'Install-Module Az.Accounts -Scope CurrentUser' and sign in with Connect-AzAccount."
}

# Compile helper types once so every parallel runspace can reuse them.
# The parser extracts the raw certificates from the TLS 1.2 Certificate message, which avoids
# false positives from locally cached intermediates that can affect X509Chain-based detection.
# It is a limited capture parser, not a general TLS validator: no TLS 1.3 decryption or
# cross-record handshake reassembly is implemented, so fragmented messages may be missed/misparsed.
if (-not ([System.Management.Automation.PSTypeName]'AfdTlsCaptureParser').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

// Observe certificates even when expired, untrusted, or mismatched; this is not trust validation.
public static class AfdTlsAcceptAll {
    // A CLR callback also avoids invoking a PowerShell scriptblock on an SslStream worker thread.
    public static bool Callback(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
        return true;
    }
}

// Mirror inbound wire bytes while forwarding transport operations required by SslStream.
// The probe owns transport cleanup; this adapter is non-seekable and does not close _inner itself.
public sealed class AfdCapturingStream : Stream {
    private readonly Stream _inner;
    private readonly List<byte> _buffer = new List<byte>(32768);

    // Wrap an already-connected network stream without initiating another connection.
    public AfdCapturingStream(Stream inner) {
        _inner = inner;
    }

    // Snapshot the received bytes for parsing after the bounded handshake attempt.
    public byte[] GetCaptured() {
        return _buffer.ToArray();
    }

    // Capture only bytes actually read, honoring the caller's buffer offset.
    public override int Read(byte[] buffer, int offset, int count) {
        int read = _inner.Read(buffer, offset, count);
        for (int i = 0; i < read; i++) {
            _buffer.Add(buffer[offset + i]);
        }
        return read;
    }

    // Apply identical capture semantics to async reads without requiring a synchronization context.
    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) {
        int read = await _inner.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        for (int i = 0; i < read; i++) {
            _buffer.Add(buffer[offset + i]);
        }
        return read;
    }

    // Outbound handshake data is forwarded, not included in the server certificate capture.
    public override void Write(byte[] buffer, int offset, int count) {
        _inner.Write(buffer, offset, count);
    }

    // Preserve asynchronous writes and cancellation on the underlying transport.
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) {
        return _inner.WriteAsync(buffer, offset, count, cancellationToken);
    }

    // Forward flushes; the adapter has no separate outbound buffer.
    public override void Flush() {
        _inner.Flush();
    }

    // Minimal Stream surface for SslStream; positioning members are unused stubs, not real seeking.
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => 0;
    public override long Position { get => 0; set { } }
    public override long Seek(long offset, SeekOrigin origin) { return 0; }
    public override void SetLength(long value) { }
}

// Extract the first plaintext TLS 1.2 Certificate payload using network-order length fields.
public static class AfdTlsCaptureParser {
    /// <summary>
    /// Returns the DER-encoded certificates carried by the TLS 1.2 Certificate message.
    /// Returns null when the Certificate message cannot be found.
    /// </summary>
    public static byte[][] ExtractCertificates(byte[] data) {
        int pos = 0;
        // TLS records have a five-byte header; stop at an incomplete trailing record.
        while (pos + 5 <= data.Length) {
            byte contentType = data[pos];
            int recordLength = (data[pos + 3] << 8) | data[pos + 4];
            if (pos + 5 + recordLength > data.Length) {
                break;
            }

            // Content type 22 carries handshakes; other records are skipped without decryption.
            if (contentType == 22) {
                int handshakePos = pos + 5;
                int handshakeEnd = handshakePos + recordLength;

                // Each handshake starts with a type byte and uint24 length.
                // This walks the capture directly: it does not remove intervening record headers
                // when a handshake spans records, and its bounds checks are not full TLS validation.
                while (handshakePos + 4 <= handshakeEnd) {
                    byte handshakeType = data[handshakePos];
                    int handshakeLength = (data[handshakePos + 1] << 16) | (data[handshakePos + 2] << 8) | data[handshakePos + 3];
                    if (handshakePos + 4 + handshakeLength > data.Length) {
                        break;
                    }

                    // Type 11 has a uint24 certificate-list length followed by length-prefixed DER blobs.
                    if (handshakeType == 11) {
                        if (handshakePos + 7 > data.Length) {
                            return Array.Empty<byte[]>();
                        }

                        // Clamp to captured bytes; malformed/truncated data can yield a partial list.
                        int certificateListLength = (data[handshakePos + 4] << 16) | (data[handshakePos + 5] << 8) | data[handshakePos + 6];
                        int certificatePos = handshakePos + 7;
                        int certificateEnd = Math.Min(certificatePos + certificateListLength, data.Length);
                        var certificates = new List<byte[]>();

                        while (certificatePos + 3 <= certificateEnd) {
                            int certificateLength = (data[certificatePos] << 16) | (data[certificatePos + 1] << 8) | data[certificatePos + 2];
                            if (certificatePos + 3 + certificateLength > data.Length) {
                                break;
                            }

                            // Preserve server order; X509 parsing and metadata extraction happen later.
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

        // Distinguish no Certificate message from an observed message with an empty list.
        return null;
    }
}
'@
}

# Acquire one token for all ARM/ARG requests; long runs do not refresh it automatically.
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

# Keep subscription IDs for API scope and names for human-readable inventory rows.
Write-PhaseBanner -Phase '2' -Message 'Resolving enabled subscriptions...'
$subscriptions = Get-EnabledSubscriptions
$subscriptionIds = @($subscriptions | Select-Object -ExpandProperty Id)
$subscriptionLookup = @{}
foreach ($subscription in $subscriptions) {
    $subscriptionLookup[$subscription.Id] = $subscription.Name
}
Write-Host "        $($subscriptions.Count) enabled subscription(s) accessible." -ForegroundColor Green

# Discover both deployment models, excluding unrelated CDN SKUs but retaining migrated Classic profiles.
Write-PhaseBanner -Phase '3' -Message 'Discovering Azure Front Door Standard/Premium and Classic profiles via Resource Graph...'
$profileQuery = @"
resources
| where type in~ ('microsoft.cdn/profiles', 'microsoft.network/frontdoors')
| extend skuName = tostring(sku.name)
| extend deploymentModel = case(type =~ 'microsoft.network/frontdoors', 'Classic', 'Standard/Premium')
| extend normalizedSkuName = case(type =~ 'microsoft.network/frontdoors', 'Classic_AzureFrontDoor', skuName)
| where type =~ 'microsoft.network/frontdoors' or skuName in~ ('Standard_AzureFrontDoor', 'Premium_AzureFrontDoor')
| project resourceType = type, subscriptionId, resourceGroup, profileName = name, profileId = id,
          frontDoorId = tostring(properties.frontDoorId), skuName = normalizedSkuName, deploymentModel,
          resourceState = tostring(properties.resourceState)
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
            FrontDoorId      = $row.frontDoorId
            ResourceType     = $row.resourceType
            DeploymentModel  = $row.deploymentModel
            SkuName          = $row.skuName
            ResourceState    = [string](Get-PropValue $row 'resourceState')
        }
    }
)
$profiles = @($profiles | Sort-Object SubscriptionName, ResourceGroup, ProfileName, ResourceType -Unique)
$discoveredProfileCount = $profiles.Count
$migratedClassicProfileCount = @($profiles | Where-Object {
    Test-IsMigratedClassicProfile -ResourceType $_.ResourceType -ResourceState $_.ResourceState
}).Count
Write-Host ("        {0} profile(s) discovered; {1} migrated Classic profile(s) retained for inventory only." -f $discoveredProfileCount, $migratedClassicProfileCount) -ForegroundColor Green

if (-not $profiles) {
    Write-Host '        No Azure Front Door profiles were found.' -ForegroundColor Yellow
    $scriptStopwatch.Stop()
    return
}

$profilesScannedCount = $profiles.Count
$classicMigrationFuncText = "function Test-IsMigratedClassicProfile { ${function:Test-IsMigratedClassicProfile} }"

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
        $afdProfile = $_
        $hdrs = $using:headers
        $apiVer = $using:standardPremiumApiVersion

        # Runspaces do not inherit caller-defined helpers; redefine the ARM retry wrapper and
        # Get-PagedArmCollection (both packaged in $ArmRetryFuncText) here.
        Invoke-Expression $using:ArmRetryFuncText

        $baseUri = "https://management.azure.com/subscriptions/$($afdProfile.SubscriptionId)/resourceGroups/$($afdProfile.ResourceGroup)/providers/Microsoft.Cdn/profiles/$($afdProfile.ProfileName)"
        $originGroups = @(Get-PagedArmCollection -Uri "$baseUri/originGroups?api-version=$apiVer" -Headers $hdrs)

        foreach ($originGroup in $originGroups) {
            [pscustomobject]@{
                SubscriptionName = $afdProfile.SubscriptionName
                SubscriptionId   = $afdProfile.SubscriptionId
                ResourceGroup    = $afdProfile.ResourceGroup
                ProfileName      = $afdProfile.ProfileName
                ProfileId        = $afdProfile.ProfileId
                FrontDoorId      = $afdProfile.FrontDoorId
                ResourceType     = $afdProfile.ResourceType
                ProfileResourceState = $afdProfile.ResourceState
                DeploymentModel  = $afdProfile.DeploymentModel
                SkuName          = $afdProfile.SkuName
                OriginGroupName  = $originGroup.name
            }
        }

        # Progress markers travel with results but are consumed only by the parent runspace.
        [pscustomobject]@{
            __Kind           = 'OriginGroupProgress'
            ProfileName      = $afdProfile.ProfileName
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

            # Runspaces do not inherit caller-defined helpers; redefine the ARM retry wrapper and
            # Get-PagedArmCollection (both packaged in $ArmRetryFuncText) here.
            Invoke-Expression $using:ArmRetryFuncText

            $uri = "https://management.azure.com/subscriptions/$($group.SubscriptionId)/resourceGroups/$($group.ResourceGroup)/providers/Microsoft.Cdn/profiles/$($group.ProfileName)/originGroups/$($group.OriginGroupName)/origins?api-version=$apiVer"
            $origins = @(Get-PagedArmCollection -Uri $uri -Headers $hdrs)

            # Preserve disabled origins and profile migration metadata; eligibility is decided after inventory.
            foreach ($origin in $origins) {
                [pscustomobject]@{
                    SubscriptionName = $group.SubscriptionName
                    SubscriptionId   = $group.SubscriptionId
                    ResourceGroup    = $group.ResourceGroup
                    ProfileName      = $group.ProfileName
                    ProfileId        = $group.ProfileId
                    FrontDoorId      = $group.FrontDoorId
                    ResourceType     = $group.ResourceType
                    ProfileResourceState = $group.ProfileResourceState
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
        $afdProfile = $_
        $hdrs = $using:headers
        $apiVer = $using:classicApiVersion

        # Runspaces do not inherit caller-defined helpers; redefine the ARM retry wrapper here.
        Invoke-Expression $using:ArmRetryFuncText

        $uri = "https://management.azure.com/subscriptions/$($afdProfile.SubscriptionId)/resourceGroups/$($afdProfile.ResourceGroup)/providers/Microsoft.Network/frontDoors/$($afdProfile.ProfileName)?api-version=$apiVer"
        $frontDoor = Invoke-ArmRequestWithRetry -Method Get -Uri $uri -Headers $hdrs
        Invoke-Expression $using:classicMigrationFuncText
        $stateProperty = $frontDoor.properties.PSObject.Properties['resourceState']
        $resourceState = if ($stateProperty) { [string]$stateProperty.Value } else { '' }
        # Either source confirming completed migration is enough to suppress probing.
        $wasMigrated = Test-IsMigratedClassicProfile -ResourceType $afdProfile.ResourceType -ResourceState $afdProfile.ResourceState
        $isMigrated = $wasMigrated -or (Test-IsMigratedClassicProfile -ResourceType $afdProfile.ResourceType -ResourceState $resourceState)
        if ($isMigrated) { $resourceState = 'Migrated' }
        # Missing inventory is an error, not an empty profile: silently dropping it would skew percentages.
        if (-not $frontDoor.properties.PSObject.Properties['backendPools']) {
            throw "Classic backend inventory unavailable for '$($afdProfile.ProfileId)'; origin totals would be incomplete."
        }
        $classicFrontDoorId = [string]$frontDoor.properties.frontdoorId
        $backendPools = @($frontDoor.properties.backendPools)
        $backendCount = 0

        # Emit pools and backends even after migration so Classic's inventoried origin denominator survives.
        foreach ($backendPool in $backendPools) {
            [pscustomobject]@{
                SubscriptionName = $afdProfile.SubscriptionName
                SubscriptionId   = $afdProfile.SubscriptionId
                ResourceGroup    = $afdProfile.ResourceGroup
                ProfileName      = $afdProfile.ProfileName
                ProfileId        = $afdProfile.ProfileId
                FrontDoorId      = $classicFrontDoorId
                ResourceType     = $afdProfile.ResourceType
                ProfileResourceState = $resourceState
                DeploymentModel  = $afdProfile.DeploymentModel
                SkuName          = $afdProfile.SkuName
                OriginGroupName  = $backendPool.name
            }

            $backendIndex = 0
            foreach ($backend in @($backendPool.properties.backends)) {
                $backendIndex++
                $backendCount++
                # Classic backends have no separate origin name; supply an index-based label if address is absent.
                $originName = if ([string]::IsNullOrWhiteSpace($backend.address)) {
                    "{0}-backend-{1}" -f $backendPool.name, $backendIndex
                }
                else {
                    $backend.address
                }

                [pscustomobject]@{
                    SubscriptionName = $afdProfile.SubscriptionName
                    SubscriptionId   = $afdProfile.SubscriptionId
                    ResourceGroup    = $afdProfile.ResourceGroup
                    ProfileName      = $afdProfile.ProfileName
                    ProfileId        = $afdProfile.ProfileId
                    FrontDoorId      = $classicFrontDoorId
                    ResourceType     = $afdProfile.ResourceType
                    ProfileResourceState = $resourceState
                    DeploymentModel  = $afdProfile.DeploymentModel
                    SkuName          = $afdProfile.SkuName
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
            ProfileName      = $afdProfile.ProfileName
            OriginGroupCount = $backendPools.Count
            OriginCount      = $backendCount
            NewlyMigrated    = $isMigrated -and -not $wasMigrated
        }
    } | ForEach-Object {
        if ($_.PSObject.Properties.Match('__Kind').Count -gt 0) {
            $classicProfilesComplete++
            if ($_.NewlyMigrated) {
                $migratedClassicProfileCount++
                Write-Verbose "Classic profile reported Migrated by ARM; inventory only: $($_.ProfileName)"
            }
            if (($classicProfilesComplete % $classicInterval -eq 0) -or ($classicProfilesComplete -eq $classicProfiles.Count)) {
                Write-Host ("        Classic profiles inventoried {0}/{1}; latest {2} -> {3} backend pool(s), {4} backend(s)" -f $classicProfilesComplete, $classicProfiles.Count, $_.ProfileName, $_.OriginGroupCount, $_.OriginCount) -ForegroundColor DarkGray
            }
        }
        # Distinguish backend rows from pool rows without discarding backends that lack a hostname value.
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
    Write-Host "        No origins found; $profilesScannedCount profile(s) inventoried, $migratedClassicProfileCount migrated Classic profile(s)." -ForegroundColor Yellow
    $scriptStopwatch.Stop()
    return
}

Write-Host "        $($originGroups.Count) origin group(s) discovered." -ForegroundColor Green
Write-Host "        $($allRecords.Count) origin record(s) discovered." -ForegroundColor Green

# Factory for the TLS-result objects stored in $tlsLookup. Centralising the shape guarantees every
# seeded entry (MSFT/Skipped/Disabled/MigratedClassic) exposes the same TLS fields as live probes, so the
# per-origin CSV/XLSX stamping stays consistent regardless of which code path produced the entry.
function New-TlsResultObject {
    param(
        [Parameter(Mandatory)][string]$TlsStatus,
        [object]$TcpAttemptedAddresses   = $null,
        [object]$TcpConnectedAddress     = $null,
        [object]$ServerCertificateCount  = $null,
        [object]$DigiCertIssued          = $null,
        [object]$LeafSubject             = $null,
        [object]$LeafIssuer              = $null,
        [object]$LeafNotAfterUtc         = $null,
        [object]$IntermediateSubject     = $null,
        [object]$IntermediateIssuer      = $null,
        [object]$IntermediateNotAfterUtc = $null,
        [object]$RootSubject             = $null,
        [object]$RootIssuer              = $null,
        [object]$RootNotAfterUtc         = $null
    )
    [pscustomobject]@{
        TlsStatus               = $TlsStatus
        TcpAttemptedAddresses   = $TcpAttemptedAddresses
        TcpConnectedAddress     = $TcpConnectedAddress
        ServerCertificateCount  = $ServerCertificateCount
        DigiCertIssued          = $DigiCertIssued
        LeafSubject             = $LeafSubject
        LeafIssuer              = $LeafIssuer
        LeafNotAfterUtc         = $LeafNotAfterUtc
        IntermediateSubject     = $IntermediateSubject
        IntermediateIssuer      = $IntermediateIssuer
        IntermediateNotAfterUtc = $IntermediateNotAfterUtc
        RootSubject             = $RootSubject
        RootIssuer              = $RootIssuer
        RootNotAfterUtc         = $RootNotAfterUtc
    }
}

# Shared TLS-probe helpers, packaged as text so a single Invoke-Expression re-creates them inside
# every parallel runspace (runspaces do not inherit caller-defined functions). The same bundle is
# used by Phase 7 (public-IP probe) and Phase 7b (private-IP probe). Phase 5 imports only
# the address-ordering helper to avoid repeatedly parsing the entire TLS helper bundle.
$script:TlsProbeFuncText = @'
# Orders addresses IPv4 first, IPv6 second, any other family last, preserving source order within
# each family and deduplicating by string form. Returns IPAddress objects.
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

# Maps socket error names/messages to a coarse category used when raw TCP diagnostics are unavailable.
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

    # A common result shape carries socket ownership on success and diagnostics on failure.
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

    # Each attempt has one shared budget, not a full TimeoutMs allowance for every DNS address.
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

            # Divide the remaining time among untried candidates so IPv6/secondary addresses get a chance.
            $perAddrMs = [Math]::Max([int][Math]::Ceiling($remaining / ($targets.Count - $i)), 1)
            $client = [System.Net.Sockets.TcpClient]::new($addr.AddressFamily)
            try {
                $client.NoDelay = $true
                $task = $client.ConnectAsync($addr, $Port)
                # Wait can throw for faulted tasks; catch below extracts the underlying socket exception.
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
                # Discard failed candidates; a connected client is handed back for the caller to dispose.
                if ($client -and -not $client.Connected) { try { $client.Dispose() } catch { } }
            }
        }

        # Explicit refusals and other immediate failures are not retried.
        if ($timedOut.Count -eq 0) { break }
        $retryAddrs = @($timedOut)
        # Small back-off between attempts so transient ICMP-throttled paths have a chance to clear.
        if ($ai -lt ($attemptBudgets.Count - 1)) { [System.Threading.Tasks.Task]::Delay(250).Wait() }
    }

    & $buildResult $null $sawTimeout (Get-TcpFailureKind -SocketErrorName $lastName -ErrorMessage $lastMsg -TimedOut:$sawTimeout) $lastName $lastCode $lastMsg $attemptCount $attempted $null
}

# Performs the TLS 1.2 handshake over an already-connected TcpClient, captures the raw Certificate
# message and returns the leaf/intermediate/root details plus a chain-classification status. Disposes
# the SslStream/capturing stream/certificates it creates; the caller still owns (and disposes) the
# TcpClient. Returns a result object whose .Status is $null only when the caller should treat it as
# 'TlsError: Unknown'.
function Get-TlsChainFromClient {
    param(
        [Parameter(Mandatory)][System.Net.Sockets.TcpClient]$TcpClient,
        [Parameter(Mandatory)][string]$SniName,
        [Parameter(Mandatory)][int]$TimeoutMs
    )

    $status = $null
    $serverCertificateCount = $null
    $digiCertIssued = $false
    $leafSubject = $null; $leafIssuer = $null; $leafNotAfterUtc = $null
    $intermediateSubject = $null; $intermediateIssuer = $null; $intermediateNotAfterUtc = $null
    $rootSubject = $null; $rootIssuer = $null; $rootNotAfterUtc = $null
    $handshakeFailure = $null
    $leafExpired = $false

    $capturingStream = $null
    $sslStream = $null
    $fallbackLeafCertificate = $null
    $certificateObjects = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()

    try {
        # Accept policy errors to observe the wire chain, forcing TLS 1.2 because its Certificate is plaintext.
        # A TLS-1.3-only endpoint therefore cannot be assessed by this probe.
        $callback = [System.Net.Security.RemoteCertificateValidationCallback]([AfdTlsAcceptAll]::Callback)
        $capturingStream = [AfdCapturingStream]::new($TcpClient.GetStream())
        $sslStream = [System.Net.Security.SslStream]::new($capturingStream, $false, $callback)
        $sslOptions = [System.Net.Security.SslClientAuthenticationOptions]@{
            TargetHost                          = $SniName
            EnabledSslProtocols                 = [System.Security.Authentication.SslProtocols]::Tls12
            RemoteCertificateValidationCallback = $callback
        }

        try {
            $authenticateTask = $sslStream.AuthenticateAsClientAsync($sslOptions)
            if (-not $authenticateTask.Wait($TimeoutMs)) {
                $status = 'TlsError: TLS handshake timed out.'
            }
        }
        catch {
            $innerMessage = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            $handshakeFailure = $innerMessage.Substring(0, [Math]::Min($innerMessage.Length, 120))
        }

        # A server may send certificates before the handshake fails; keep that evidence instead of the error.
        # The count is from the wire list, even if individual DER blobs cannot be decoded below.
        $rawCertificates = [AfdTlsCaptureParser]::ExtractCertificates($capturingStream.GetCaptured())
        if ($null -ne $rawCertificates) {
            $serverCertificateCount = $rawCertificates.Length

            foreach ($rawCertificate in $rawCertificates) {
                try { $certificateObjects.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate)) } catch { }
            }

            # RemoteCertificate supplies metadata only; it must not inflate the server-sent count.
            $leafCertificate = $null
            if ($certificateObjects.Count -gt 0) { $leafCertificate = $certificateObjects[0] }
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

            # Use the second successfully decoded certificate as the intermediate display slot.
            # Positions are descriptive only: issuer linkage and signatures are not verified.
            $intermediateCertificate = if ($certificateObjects.Count -ge 2) { $certificateObjects[1] } else { $null }
            if ($intermediateCertificate) {
                $intermediateSubject     = $intermediateCertificate.Subject
                $intermediateIssuer      = $intermediateCertificate.Issuer
                $intermediateNotAfterUtc = $intermediateCertificate.NotAfter.ToUniversalTime()
            }

            # The last certificate is labeled "root" for display but may actually be another intermediate.
            $rootCertificate = if ($certificateObjects.Count -ge 3) { $certificateObjects[$certificateObjects.Count - 1] } else { $null }
            if ($rootCertificate) {
                $rootSubject = $rootCertificate.Subject
                $rootIssuer = $rootCertificate.Issuer
                $rootNotAfterUtc = $rootCertificate.NotAfter.ToUniversalTime()
            }

            # Legacy names encode count thresholds, not cryptographic completeness or chain trust.
            if     ($serverCertificateCount -ge 3) { $status = if ($leafExpired) { 'ExpiredFullChain' }    else { 'FullChain' } }
            elseif ($serverCertificateCount -eq 2) { $status = if ($leafExpired) { 'ExpiredPartialChain' } else { 'PartialChain' } }
            elseif ($serverCertificateCount -eq 1) { $status = if ($leafExpired) { 'ExpiredNoChain' }      else { 'NoChain' } }
            elseif ($serverCertificateCount -eq 0) { $status = 'NoCert' }
            elseif (-not $status)                  { $status = 'TlsError: CertMsgNotFound' }
        }
        elseif (-not $status) {
            $status = if ($handshakeFailure) { "TlsError: $handshakeFailure" } else { 'TlsError: CertMsgNotFound' }
        }
    }
    finally {
        # Dispose what this function created (certificates first, then transport streams). The caller
        # retains ownership of the TcpClient.
        $disposables = [System.Collections.Generic.List[object]]::new()
        if ($fallbackLeafCertificate) { $disposables.Add($fallbackLeafCertificate) }
        foreach ($cert in $certificateObjects) { $disposables.Add($cert) }
        if ($sslStream)       { $disposables.Add($sslStream) }
        if ($capturingStream) { $disposables.Add($capturingStream) }
        foreach ($d in $disposables) { try { $d.Dispose() } catch { } }
    }

    [pscustomobject]@{
        Status                  = $status
        ServerCertificateCount  = $serverCertificateCount
        DigiCertIssued          = $digiCertIssued
        LeafSubject             = $leafSubject
        LeafIssuer              = $leafIssuer
        LeafNotAfterUtc         = $leafNotAfterUtc
        IntermediateSubject     = $intermediateSubject
        IntermediateIssuer      = $intermediateIssuer
        IntermediateNotAfterUtc = $intermediateNotAfterUtc
        RootSubject             = $rootSubject
        RootIssuer              = $rootIssuer
        RootNotAfterUtc         = $rootNotAfterUtc
    }
}
'@
Invoke-Expression $script:TlsProbeFuncText
$dnsProbeFuncText = "function Get-OrderedProbeAddresses { ${function:Get-OrderedProbeAddresses} }"

# Build unique network targets as (ConnectTo, Port, SniName) triples.
# DNS is shared by hostname; TCP uses the configured HTTPS port and TLS uses the effective SNI.
# Migrated Classic and disabled origins are excluded before Microsoft suffix classification.
# They remain in $allRecords and receive their own skip status even if an active row shares the target.
#
# Origins whose host names use a Microsoft-owned Azure PaaS public DNS suffix are excluded
# from the network-probe pipeline: Microsoft manages their TLS chains, so DNS resolution,
# TCP connect and TLS handshake would add no actionable diagnostic. They are pre-seeded into
# $tlsLookup with TlsStatus='MSFT' so the per-origin CSV/XLSX row still reports a status.
$tlsLookup = @{}
$msftSkippedRecordCount = 0
$msftSkippedTargetSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($record in $allRecords) {
    if (Get-OriginSkipStatus -Record $record) { continue }
    if (-not $record.HostName) { continue }
    if (-not (Test-IsMicrosoftManagedHost -HostName $record.HostName)) { continue }
    $msftSkippedRecordCount++
    $msftKey = "{0}|{1}|{2}" -f $record.HostName, (Get-TlsProbePort -Record $record), (Get-TlsSniName -Record $record)
    if (-not $tlsLookup.ContainsKey($msftKey)) {
        $tlsLookup[$msftKey] = New-TlsResultObject -TlsStatus 'MSFT'
    }
    [void]$msftSkippedTargetSet.Add($msftKey)
}
if ($msftSkippedTargetSet.Count -gt 0) {
    Write-Host ("        Microsoft-managed origins detected: {0} origin record(s) across {1} distinct target(s) marked TlsStatus=MSFT and excluded from TLS probing." -f $msftSkippedRecordCount, $msftSkippedTargetSet.Count) -ForegroundColor Cyan
}

$tlsTargets = @(
    $allRecords |
        Where-Object { $_.HostName -and -not (Get-OriginSkipStatus -Record $_) -and -not (Test-IsMicrosoftManagedHost -HostName $_.HostName) } |
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
$applicationGatewaySecurityInventory = $null
if (-not $tlsTargets) {
    Write-PhaseBanner -Phase '5' -Message 'No origin targets were found for IP resolution.'
}
else {
    $dnsHosts = @($tlsTargets.ConnectTo | Sort-Object -Unique)
    $hostResolutionLookup = @{}
    Write-PhaseBanner -Phase '5' -Message "Resolving $($dnsHosts.Count) distinct hostname(s) for $($tlsTargets.Count) TLS target(s) and mapping Azure public IP resources..."
    $resolutionInterval = Get-ProgressInterval -TotalCount $dnsHosts.Count
    $resolutionComplete = 0

    $dnsHosts | ForEach-Object -ThrottleLimit $TlsThrottleLimit -Parallel {
        $connectTo = $_

        Invoke-Expression $using:dnsProbeFuncText

        $parsedIp = $null
        $resolvedAddresses = @()
        $resolutionFailure = $null

        try {
            # IP-literal origins bypass DNS; other hosts are resolved once for all port/SNI combinations.
            if ([System.Net.IPAddress]::TryParse($connectTo, [ref]$parsedIp)) {
                $resolvedAddresses = @($parsedIp.IPAddressToString)
            }
            else {
                $resolvedAddresses = @(Get-OrderedProbeAddresses -Addresses ([System.Net.Dns]::GetHostAddresses($connectTo)) | ForEach-Object { $_.IPAddressToString })
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

        [pscustomobject]@{
            ConnectTo          = $connectTo
            ResolvedAddresses  = @($resolvedAddresses)
            ResolutionFailure  = if ([string]::IsNullOrWhiteSpace($resolutionFailure)) { $null } else { $resolutionFailure.Substring(0, [Math]::Min($resolutionFailure.Length, 200)) }
        }

        [pscustomobject]@{
            __Kind           = 'ResolutionProgress'
            TargetLabel      = $connectTo
            ResolutionStatus = if ($resolvedAddresses.Count -gt 0) { $resolvedAddresses -join ', ' } else { 'DnsFailure' }
        }
    } | ForEach-Object {
        if ($_.PSObject.Properties.Match('__Kind').Count -gt 0) {
            $resolutionComplete++
            if (($resolutionComplete % $resolutionInterval -eq 0) -or ($resolutionComplete -eq $dnsHosts.Count)) {
                Write-Host ("        IP resolution complete {0}/{1}; latest {2} -> {3}" -f $resolutionComplete, $dnsHosts.Count, $_.TargetLabel, $_.ResolutionStatus) -ForegroundColor DarkGray
            }
        }
        else {
            $hostResolutionLookup[$_.ConnectTo] = $_
        }
    }

    # Fan the hostname-only resolution out to each target without issuing another DNS request.
    foreach ($target in $tlsTargets) {
        $resolution = $hostResolutionLookup[$target.ConnectTo]
        if (-not $resolution) { throw "Missing DNS result for '$($target.ConnectTo)'." }
        $targetResolutionLookup["$($target.ConnectTo)|$($target.Port)|$($target.SniName)"] = [pscustomobject]@{
            ConnectTo = $target.ConnectTo
            Port = $target.Port
            SniName = $target.SniName
            ResolvedAddresses = @($resolution.ResolvedAddresses)
            ResolutionFailure = $resolution.ResolutionFailure
        }
    }

    $resolvedPublicIpAddresses = @(
        $targetResolutionLookup.Values |
            ForEach-Object { @($_.ResolvedAddresses) } |
            Where-Object { (Get-IpAddressKind -IpAddress $_) -like 'Public*' } |
            Sort-Object -Unique
    )

    # Correlation is best-effort; an ARG failure must not discard DNS evidence or prevent TLS probing.
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

    # Retain the address array for probes alongside export-friendly text and reusable security metadata.
    foreach ($lookupKey in @($targetResolutionLookup.Keys)) {
        $resolutionResult = $targetResolutionLookup[$lookupKey]
        $resolvedIpMetadata = Get-ResolvedIpMetadata -IpAddresses @($resolutionResult.ResolvedAddresses) -AzurePublicIpLookup $azurePublicIpLookup

        $resolutionResult | Add-Member -NotePropertyName ResolvedAddressesText -NotePropertyValue $resolvedIpMetadata.ResolvedAddresses -Force
        $resolutionResult | Add-Member -NotePropertyName IpKind -NotePropertyValue $resolvedIpMetadata.IpKind -Force
        $resolutionResult | Add-Member -NotePropertyName AzureResourceId -NotePropertyValue $resolvedIpMetadata.AzureResourceId -Force
        $resolutionResult | Add-Member -NotePropertyName ApplicationGatewayResourceId -NotePropertyValue $resolvedIpMetadata.ApplicationGatewayResourceId -Force
        $resolutionResult | Add-Member -NotePropertyName ApplicationGatewayFrontendIpConfigId -NotePropertyValue $resolvedIpMetadata.ApplicationGatewayFrontendIpConfigId -Force
        $resolutionResult | Add-Member -NotePropertyName ApplicationGatewayUnverifiedPublicIps -NotePropertyValue $resolvedIpMetadata.ApplicationGatewayUnverifiedPublicIps -Force
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

# Load gateway security dependencies once for all eligible targets, independent of -SkipTls.
$applicationGatewayIds = @(
    $targetResolutionLookup.Values |
        ForEach-Object { ([string](Get-PropValue $_ 'ApplicationGatewayResourceId')) -split ';\s*' } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
)
if (-not $applicationGatewayIds) {
    Write-PhaseBanner -Phase '6' -Message 'No resolved origins are associated with Azure Application Gateways.'
}
else {
    Write-PhaseBanner -Phase '6' -Message "Investigating NSG and WAF controls for $($applicationGatewayIds.Count) distinct Application Gateway resource(s)..."
    try {
        $applicationGatewaySecurityInventory = Get-ApplicationGatewaySecurityInventory -Headers $headers -SubscriptionIds $subscriptionIds -ApplicationGatewayIds $applicationGatewayIds
        Write-Host ("        Loaded {0} Application Gateway(s), {1} subnet(s), {2} NSG(s), and {3} WAF policy resource(s)." -f
            $applicationGatewaySecurityInventory.Gateways.Count,
            $applicationGatewaySecurityInventory.Subnets.Count,
            $applicationGatewaySecurityInventory.Nsgs.Count,
            $applicationGatewaySecurityInventory.WafPolicies.Count) -ForegroundColor Green
    }
    catch {
        Write-Warning ("Application Gateway security lookup failed. AppGatewayFrontDoorSecurity will be Unknown. {0}" -f $_.Exception.Message)
        $applicationGatewaySecurityInventory = $null
    }
}

# -SkipTls bypasses only TLS/TCP, not DNS, Azure correlation, or gateway configuration evaluation.
if ($SkipTls) {
    Write-PhaseBanner -Phase '7' -Message 'Skipping TLS checks (-SkipTls).'
    foreach ($target in $tlsTargets) {
        $tlsLookup["$($target.ConnectTo)|$($target.Port)|$($target.SniName)"] = New-TlsResultObject -TlsStatus 'Skipped'
    }
}
elseif (-not $tlsTargets) {
    Write-PhaseBanner -Phase '7' -Message 'No TLS targets were found.'
}
else {
    Write-PhaseBanner -Phase '7' -Message "Testing TLS on $($tlsTargets.Count) distinct target(s) (parallel=$TlsThrottleLimit, timeout=${TlsTimeoutMs}ms)..."
    $tlsInterval = Get-ProgressInterval -TotalCount $tlsTargets.Count
    $tlsComplete = 0

    # Pass resolved addresses to workers explicitly; workers must not perform a second DNS lookup.
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

        # Runspaces do not inherit caller-defined helpers; re-create the shared probe helpers.
        Invoke-Expression $using:TlsProbeFuncText

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
        $probeAddresses = $null
        $tcpAttemptedAddresses = $null
        $tcpConnectedAddress = $null
        $tcpSocketErrorName = $null
        $tcpSocketErrorCode = $null

        $tcpClient = $null

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
                }
            }

            if (-not $status) {
                # Hand the connected socket to the shared TLS-chain extractor (Phase 7/7b use the same
                # handshake + capture + classification logic).
                $chain = Get-TlsChainFromClient -TcpClient $tcpClient -SniName $sniName -TimeoutMs $timeoutMs
                $status                  = $chain.Status
                $serverCertificateCount  = $chain.ServerCertificateCount
                $digiCertIssued          = $chain.DigiCertIssued
                $leafSubject             = $chain.LeafSubject
                $leafIssuer              = $chain.LeafIssuer
                $leafNotAfterUtc         = $chain.LeafNotAfterUtc
                $intermediateSubject     = $chain.IntermediateSubject
                $intermediateIssuer      = $chain.IntermediateIssuer
                $intermediateNotAfterUtc = $chain.IntermediateNotAfterUtc
                $rootSubject             = $chain.RootSubject
                $rootIssuer              = $chain.RootIssuer
                $rootNotAfterUtc         = $chain.RootNotAfterUtc
            }
        }
        catch {
            # Keep DNS, socket, and other TLS failures distinguishable without aborting the whole scan.
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
                $status = (Get-ConnectionDetail -SocketErrorCode $tcpSocketErrorCode -SocketErrorName $tcpSocketErrorName -ErrorMessage $innerMessage) ??
                          (Get-TcpStatusFallback -FailureKind (Get-TcpFailureKind -SocketErrorName $tcpSocketErrorName -ErrorMessage $innerMessage -TimedOut:$false))
            }
            else {
                $status = 'TlsError: ' + $innerMessage.Substring(0, [Math]::Min($innerMessage.Length, 120))
            }
        }
        finally {
            # Get-TlsChainFromClient disposes the streams/certificates it created; the socket is ours.
            if ($tcpClient) { try { $tcpClient.Dispose() } catch { } }
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

        # Separate progress messages from lookup data to keep shared hashtable writes in the parent.
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

# Phase 7b — Probe private IPs discovered via the Private_IP tag on Azure public IP resources.
# This tag is treated as a D-NAT hint, not verified evidence of firewall/NAT configuration.
# The private IP is only tested when the public-IP probe failed to retrieve certificates.
# If the private-IP probe succeeds, its results replace the public-IP results in the export.
# If it also fails, the failure is accepted as the final result for that origin.
$privateIpTlsLookup = @{}
if (-not $SkipTls -and $targetResolutionLookup.Count -gt 0) {
    # Share a private probe across public endpoints with the same tagged IP/port/SNI.
    # Preserve the original SNI even though the connection destination changes to an IP literal.
    $privateIpTargets = @(
        $targetResolutionLookup.Keys | ForEach-Object {
            $key = $_
            $res = $targetResolutionLookup[$key]
            $privateIp = $res.AzurePrivateIpTag
            if (-not [string]::IsNullOrWhiteSpace($privateIp)) {
                # Only probe the private IP when the public-IP TLS probe did not get certificates.
                $publicResult = $tlsLookup[$key]
                if (Test-NeedsPrivateIpProbe -TlsResult $publicResult) {
                    $parts = $key -split '\|', 3
                    [pscustomobject]@{
                        PrivateIp         = $privateIp
                        Port              = [int]$parts[1]
                        SniName           = $parts[2]
                        OriginalLookupKey = $key
                    }
                }
            }
        } | Sort-Object PrivateIp, Port, SniName -Unique
    )

    if ($privateIpTargets.Count -gt 0) {
        Write-PhaseBanner -Phase '7b' -Message "Testing TLS on $($privateIpTargets.Count) private-IP target(s) from Private_IP tags (parallel=$TlsThrottleLimit, timeout=${TlsTimeoutMs}ms)..."
        $privTlsInterval = Get-ProgressInterval -TotalCount $privateIpTargets.Count
        $privTlsComplete = 0

        $privateIpTargets | ForEach-Object -ThrottleLimit $TlsThrottleLimit -Parallel {
            $target = $_
            $timeoutMs = $using:TlsTimeoutMs

            # Runspaces do not inherit caller-defined helpers; re-create the shared probe helpers.
            Invoke-Expression $using:TlsProbeFuncText

            $privateIp = $target.PrivateIp
            $port      = $target.Port
            $sniName   = $target.SniName
            $status    = $null
            $serverCertificateCount = $null
            $digiCertIssued         = $false
            $leafSubject = $null; $leafIssuer = $null; $leafNotAfterUtc = $null
            $intermediateSubject = $null; $intermediateIssuer = $null; $intermediateNotAfterUtc = $null
            $rootSubject = $null; $rootIssuer = $null; $rootNotAfterUtc = $null
            $tcpAttemptedAddresses = $null
            $tcpConnectedAddress  = $null

            $tcpClient = $null

            try {
                $parsedIp = $null
                # Tags must contain a single IP literal; hostnames and joined multi-tag values are not resolved.
                if (-not [System.Net.IPAddress]::TryParse($privateIp, [ref]$parsedIp)) {
                    $status = "TlsError: Invalid private IP '$privateIp'"
                }
                else {
                    # Reuse the shared multi-attempt TCP connector so private-IP probes get the same
                    # bounded-timeout + single-retry resilience as the public-IP probes (Phase 7).
                    $tcpConnectResult = Connect-TcpWithRetry -Addresses @($parsedIp) -Port $port -TimeoutMs $timeoutMs
                    $tcpClient = $tcpConnectResult.Client
                    $tcpAttemptedAddresses = if ($tcpConnectResult.AttemptedAddresses.Count -gt 0) { $tcpConnectResult.AttemptedAddresses -join ', ' } else { $null }
                    $tcpConnectedAddress = $tcpConnectResult.ConnectedAddress

                    if (-not $tcpClient) {
                        $status = (Get-ConnectionDetail -SocketErrorCode $tcpConnectResult.SocketErrorCode -SocketErrorName $tcpConnectResult.SocketErrorName -ErrorMessage $tcpConnectResult.ErrorMessage) ??
                                  (Get-TcpStatusFallback -FailureKind $tcpConnectResult.FailureKind)
                    }
                }

                if (-not $status) {
                    # Shared TLS-chain extractor (same logic as Phase 7).
                    $chain = Get-TlsChainFromClient -TcpClient $tcpClient -SniName $sniName -TimeoutMs $timeoutMs
                    $status                  = $chain.Status
                    $serverCertificateCount  = $chain.ServerCertificateCount
                    $digiCertIssued          = $chain.DigiCertIssued
                    $leafSubject             = $chain.LeafSubject
                    $leafIssuer              = $chain.LeafIssuer
                    $leafNotAfterUtc         = $chain.LeafNotAfterUtc
                    $intermediateSubject     = $chain.IntermediateSubject
                    $intermediateIssuer      = $chain.IntermediateIssuer
                    $intermediateNotAfterUtc = $chain.IntermediateNotAfterUtc
                    $rootSubject             = $chain.RootSubject
                    $rootIssuer              = $chain.RootIssuer
                    $rootNotAfterUtc         = $chain.RootNotAfterUtc
                }
            }
            catch {
                $innerMessage = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
                $status = 'TlsError: ' + $innerMessage.Substring(0, [Math]::Min($innerMessage.Length, 120))
            }
            finally {
                # Get-TlsChainFromClient disposes the streams/certificates it created; the socket is ours.
                if ($tcpClient) { try { $tcpClient.Dispose() } catch { } }
            }

            $targetLabel = "{0}:{1} (SNI={2})" -f $privateIp, $port, $sniName

            [pscustomobject]@{
                PrivateIp              = $privateIp
                Port                   = $port
                SniName                = $sniName
                OriginalLookupKey      = $target.OriginalLookupKey
                TlsStatus              = $status ?? 'TlsError: Unknown'
                TcpAttemptedAddresses  = $tcpAttemptedAddresses
                TcpConnectedAddress    = $tcpConnectedAddress
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
                __Kind      = 'PrivTlsProgress'
                TargetLabel = $targetLabel
                TlsStatus   = $status ?? 'TlsError: Unknown'
            }
        } | ForEach-Object {
            if ($_.PSObject.Properties.Match('__Kind').Count -gt 0) {
                $privTlsComplete++
                if (($privTlsComplete % $privTlsInterval -eq 0) -or ($privTlsComplete -eq $privateIpTargets.Count)) {
                    Write-Host ("        Private-IP TLS complete {0}/{1}; latest {2} -> {3}" -f $privTlsComplete, $privateIpTargets.Count, $_.TargetLabel, $_.TlsStatus) -ForegroundColor DarkGray
                }
            }
            else {
                $privateIpTlsLookup["$($_.PrivateIp)|$($_.Port)|$($_.SniName)"] = $_
            }
        }
    }
}

# Stamp the resolved-IP details and TLS findings back onto every origin row so the CSV remains
# one row per origin. Missing metadata becomes null; missing TLS results receive N/A.
# -SkipTls has explicit Skipped results, while migrated/disabled rows get isolated skip results.
$stampFromResolution = @(
    'ResolvedAddressesText|ResolvedAddresses',
    'IpKind',
    'AzureResourceId',
    'ApplicationGatewayResourceId',
    'AzurePrivateIpTag'
)
$stampFromTls        = @(
    'TlsStatus',
    'TcpAttemptedAddresses',  'TcpConnectedAddress',
    'ServerCertificateCount', 'DigiCertIssued',
    'LeafSubject',   'LeafIssuer',   'LeafNotAfterUtc',
    'IntermediateSubject', 'IntermediateIssuer', 'IntermediateNotAfterUtc',
    'RootSubject',   'RootIssuer',   'RootNotAfterUtc'
)
$appGatewaySecurityResultLookup = @{}
$finalTargetResultLookup = @{}

foreach ($record in $allRecords) {
    $tlsPort   = Get-TlsProbePort -Record $record
    $sniName   = Get-TlsSniName   -Record $record
    $lookupKey = "$($record.HostName)|$tlsPort|$sniName"
    $skipStatus = Get-OriginSkipStatus -Record $record
    # Never leak an active row's shared-target DNS, TLS, or security findings into a skipped origin.
    $resolutionResult = if ($skipStatus) { $null } else { $targetResolutionLookup[$lookupKey] }
    $tlsResult = if ($skipStatus) { New-TlsResultObject -TlsStatus $skipStatus } else { $tlsLookup[$lookupKey] }

    $record | Add-Member -NotePropertyName TlsPort -NotePropertyValue $tlsPort -Force

    # Mapping entries may rename a source property (e.g. ResolvedAddressesText) for the exported schema.
    foreach ($pair in $stampFromResolution) {
        $parts = $pair -split '\|', 2
        $sourceName = $parts[0]
        $targetName = if ($parts.Count -eq 2) { $parts[1] } else { $parts[0] }
        $record | Add-Member -NotePropertyName $targetName -NotePropertyValue (Get-PropValue $resolutionResult $sourceName) -Force
    }

    # FDID and explicit host-header presence affect WAF evaluation even when the TLS endpoint is shared.
    $appGatewaySecurityKey = "$lookupKey|$([string](Get-PropValue $record 'OriginHostHeader'))|$([string](Get-PropValue $record 'FrontDoorId'))|$skipStatus"
    if (-not $appGatewaySecurityResultLookup.ContainsKey($appGatewaySecurityKey)) {
        $appGatewaySecurityResultLookup[$appGatewaySecurityKey] = Get-ApplicationGatewayOriginSecurityResult -Record $record -ResolutionResult $resolutionResult -Inventory $applicationGatewaySecurityInventory
    }
    $appGatewaySecurity = $appGatewaySecurityResultLookup[$appGatewaySecurityKey]
    $record | Add-Member -NotePropertyName AppGatewayFrontDoorSecurity -NotePropertyValue $appGatewaySecurity.Status -Force
    $record | Add-Member -NotePropertyName AppGatewayFrontDoorSecurityReason -NotePropertyValue $appGatewaySecurity.Reason -Force
    $record | Add-Member -NotePropertyName ApplicationGatewayNsgResourceId -NotePropertyValue $appGatewaySecurity.NsgResourceIds -Force
    $record | Add-Member -NotePropertyName ApplicationGatewayWafPolicyId -NotePropertyValue $appGatewaySecurity.WafPolicyIds -Force

    $defaultTlsStatus = if ($tlsResult) { $null } else { 'N/A' }
    foreach ($name in $stampFromTls) {
        $value = Get-PropValue $tlsResult $name
        if ($name -eq 'TlsStatus' -and -not $value) { $value = $defaultTlsStatus }
        $record | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force
    }

    # If the public-IP probe failed to retrieve certificates and a private-IP probe was performed,
    # overwrite the TLS and certificate columns with the private-IP results (whether success or
    # failure) and merge TcpAttemptedAddresses so both tested IPs are visible.
    $privateIp = Get-PropValue $resolutionResult 'AzurePrivateIpTag'
    if ($privateIp -and $privateIpTlsLookup.Count -gt 0 -and (Test-NeedsPrivateIpProbe -TlsResult $tlsResult)) {
        $privKey = "$privateIp|$tlsPort|$sniName"
        $privResult = $privateIpTlsLookup[$privKey]
        if ($privResult) {
            # Merge attempted addresses: public attempts first, then private.
            $publicAttempted  = Get-PropValue $tlsResult 'TcpAttemptedAddresses'
            $privateAttempted = Get-PropValue $privResult 'TcpAttemptedAddresses'
            $mergedAttempted  = @($publicAttempted, $privateAttempted) |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            $mergedAttempted  = if ($mergedAttempted) { $mergedAttempted -join ', ' } else { $null }

            foreach ($name in $stampFromTls) {
                $record | Add-Member -NotePropertyName $name -NotePropertyValue (Get-PropValue $privResult $name) -Force
            }
            # Overwrite TcpAttemptedAddresses with the merged list.
            $record | Add-Member -NotePropertyName 'TcpAttemptedAddresses' -NotePropertyValue $mergedAttempted -Force
        }
    }

    # Derive summary columns after private fallback; unassessed expiry is unknown, not false.
    $category = Get-TlsStatusCategory -TlsStatus $record.TlsStatus
    $chainStatus = if ($category -in @('NoChain', 'PartialChain', 'FullChain')) { $category } else { 'NotAssessed' }
    $record | Add-Member -NotePropertyName ChainStatus -NotePropertyValue $chainStatus -Force
    $record | Add-Member -NotePropertyName LeafExpired -NotePropertyValue $(if ($chainStatus -ne 'NotAssessed') { $record.TlsStatus -like 'Expired*' } else { $null }) -Force
    if ($record.HostName) {
        # Unique targets prefer active > disabled > migrated; equal-priority rows retain the first result.
        # Missing-host rows still count as origins but cannot define a network target.
        $previous = $finalTargetResultLookup[$lookupKey]
        if (-not $previous -or (Get-TlsTargetResultPriority $record) -gt (Get-TlsTargetResultPriority $previous)) {
            $finalTargetResultLookup[$lookupKey] = $record
        }
    }
}

# Put actionable chain-count groups first and lead with diagnostic columns without dropping inventory fields.
Write-PhaseBanner -Phase '8' -Message 'Exporting results...'
$chainSortOrder = @{ NoChain = 0; PartialChain = 1; FullChain = 2; NotAssessed = 3 }
$allRecords = @($allRecords | Sort-Object { $chainSortOrder[$_.ChainStatus] }, SubscriptionName, ResourceGroup, ProfileName, OriginGroupName, OriginName, HostName)
$leadingColumns = @('ChainStatus', 'TlsStatus', 'ServerCertificateCount', 'LeafExpired', 'HostName', 'OriginHostHeader')
$reportColumns = $leadingColumns + @($allRecords[0].PSObject.Properties.Name | Where-Object { $_ -notin $leadingColumns })
$allRecords = @($allRecords | Select-Object -Property $reportColumns)
$allRecords | Export-Csv -LiteralPath $OutputCsvPath -NoTypeInformation -Encoding utf8

# CSV remains the guaranteed output. When ImportExcel is available, emit a companion workbook
# with the same data as a formatted Excel table so the file is immediately filterable in Excel.
$xlsxOutputPath = [System.IO.Path]::ChangeExtension($OutputCsvPath, '.xlsx')
$xlsxWasExported = $false
$importExcelModule = Get-Module -ListAvailable -Name ImportExcel | Sort-Object Version -Descending | Select-Object -First 1
if ($importExcelModule) {
    try {
        Import-Module $importExcelModule.Path -ErrorAction Stop | Out-Null
        $xlsxTextColumns = @(
            'OriginName', 'HostName', 'OriginHostHeader', 'FrontDoorId',
            'ResolvedAddresses', 'IpKind', 'AzureResourceId', 'ApplicationGatewayResourceId',
            'ApplicationGatewayNsgResourceId', 'ApplicationGatewayWafPolicyId',
            'AppGatewayFrontDoorSecurity', 'AppGatewayFrontDoorSecurityReason',
            'AzurePrivateIpTag', 'ChainStatus', 'TlsStatus', 'TcpAttemptedAddresses', 'TcpConnectedAddress'
        )
        # Excel sheet names have restricted characters/length; reserve Summary for the companion sheet.
        $worksheetName = [System.IO.Path]::GetFileNameWithoutExtension($xlsxOutputPath)
        $worksheetName = $worksheetName -replace '[\\/\?\*\[\]:]', '_'
        if ([string]::IsNullOrWhiteSpace($worksheetName)) {
            $worksheetName = 'afd-origins'
        }
        if ($worksheetName.Length -gt 31) {
            $worksheetName = $worksheetName.Substring(0, 31)
        }
        if ($worksheetName -eq 'Summary') { $worksheetName = 'Origins' }

        # ImportExcel attempts CurrentCulture numeric parsing on string values by default.
        # Keep host-related columns as literal text so IPv4 addresses are never coerced into numbers.
        $excelPackage = $allRecords | Export-Excel -Path $xlsxOutputPath -WorksheetName $worksheetName -TableName Table1 -TableStyle Medium2 -NoNumberConversion $xlsxTextColumns -AutoFilter -AutoSize -FreezeTopRow -ClearSheet -PassThru
        try {
            $detailSheet = $excelPackage.Workbook.Worksheets[$worksheetName]
            # Sorting above makes unassessed rows contiguous; gray them without changing any diagnostics.
            $assessedRowCount = @($allRecords | Where-Object ChainStatus -ne 'NotAssessed').Count
            if ($assessedRowCount -lt $allRecords.Count) {
                $columnCount = @($allRecords[0].PSObject.Properties).Count
                Set-ExcelRange -Range $detailSheet.Cells[($assessedRowCount + 2), 1, ($allRecords.Count + 1), $columnCount] -FontColor DimGray
            }
            # Reuse the console report model so worksheet counts and all-origin percentages agree.
            $report = Get-TlsReportData -Records $allRecords -TargetRecords @($finalTargetResultLookup.Values)
            Add-TlsSummaryWorksheet -ExcelPackage $excelPackage -Report $report
            $excelPackage.Workbook.Worksheets.MoveAfter('Summary', $worksheetName)
            $excelPackage.Save()
        }
        finally { $excelPackage.Dispose() }
        # Release EPPlus's file handle before patching table styles directly in the ZIP archive.
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

# Distinct inventory counts are informational only; report percentages always use all origin rows.
$distinctOrigins = @($allRecords | Sort-Object SubscriptionName, ResourceGroup, ProfileName, OriginGroupName, OriginName, HostName -Unique)
$distinctHosts = @($allRecords | Where-Object { $_.HostName } | Sort-Object HostName -Unique)

Write-Host ''
Write-Host ('=' * 88) -ForegroundColor Green
Write-Host '  RESULTS' -ForegroundColor Green
Write-Host ('=' * 88) -ForegroundColor Green
Write-TlsStatusBreakdown -Records $allRecords -TargetRecords @($finalTargetResultLookup.Values)
Write-Host ''
Write-Host '  Scan details:' -ForegroundColor DarkGray
Write-Host "  Subscriptions scanned   : $($subscriptions.Count)"
Write-Host "  Profiles discovered     : $discoveredProfileCount"
Write-Host "  Classic migrated (no TLS): $migratedClassicProfileCount"
Write-Host "  Profiles inventoried    : $profilesScannedCount"
Write-Host "  Origin groups scanned   : $($originGroups.Count)"
Write-Host "  Total origin records    : $($allRecords.Count)"
Write-Host "  Distinct origins        : $($distinctOrigins.Count)"
Write-Host "  Distinct hostnames      : $($distinctHosts.Count)"
Write-Host "  Unmanaged TLS targets   : $($tlsTargets.Count)"
Write-Host "  Application Gateways    : $($applicationGatewayIds.Count)"
Write-Host "  Output CSV              : $OutputCsvPath"
if ($xlsxWasExported) {
    Write-Host "  Output XLSX             : $xlsxOutputPath"
}

$scriptStopwatch.Stop()
$elapsed = $scriptStopwatch.Elapsed
Write-Host ("  Total execution time    : {0:hh\:mm\:ss} ({1:n1}s)" -f $elapsed, $elapsed.TotalSeconds)

# These ancillary totals use final per-origin findings, including any private-IP replacement results.
if (-not $SkipTls -and $tlsLookup.Count -gt 0) {
    $digiCertOriginCount = @($allRecords | Where-Object { $_.DigiCertIssued }).Count
    Write-Host ''
    Write-Host "  DigiCert-issued leaf certs (origin rows): $digiCertOriginCount" -ForegroundColor DarkGray
}

$appGatewaySecurityRows = @($allRecords | Where-Object { $_.AppGatewayFrontDoorSecurity })
if ($appGatewaySecurityRows) {
    Write-Host ''
    Write-Host '  Application Gateway origin security:' -ForegroundColor DarkGray
    foreach ($group in @($appGatewaySecurityRows | Group-Object AppGatewayFrontDoorSecurity | Sort-Object Name)) {
        Write-Host ("    {0,-10} {1,6}" -f $group.Name, $group.Count) -ForegroundColor DarkGray
    }
}

Write-Host ('=' * 88) -ForegroundColor Green

Write-Host "`nDone." -ForegroundColor Green
