#requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$sourcePath = Join-Path $PSScriptRoot '..\Get-AFDOriginCertChains.ps1'
$source = Get-Content -LiteralPath $sourcePath -Raw
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors.Message -join "`n") }

# Load definitions, never the script's authentication or live inventory entry point.
foreach ($definition in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
$probeAssignment = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$script:TlsProbeFuncText'
}, $false)
. ([scriptblock]::Create($probeAssignment.Extent.Text))
. ([scriptblock]::Create($script:TlsProbeFuncText))
$suffixAssignment = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$script:MicrosoftPublicDnsSuffixes'
}, $false)
. ([scriptblock]::Create($suffixAssignment.Extent.Text))
$totalSteps = 8

# Execute bounded production stages with fixtures so tests cannot reach the live entry point.
function Get-ProductionStage {
    param([string]$Start, [string]$End)
    $startIndex = $source.IndexOf($Start, [StringComparison]::Ordinal)
    if ($startIndex -lt 0) { throw "Stage start not found: $Start" }
    $endIndex = $source.IndexOf($End, $startIndex + $Start.Length, [StringComparison]::Ordinal)
    if ($endIndex -lt 0) { throw "Stage end not found: $End" }
    [scriptblock]::Create($source.Substring($startIndex, $endIndex - $startIndex))
}

# Fail immediately with the expected/actual values; no external test framework is required.
function Assert-Equal {
    param($Actual, $Expected, [string]$Because)
    if ($Actual -cne $Expected) { throw "$Because -- expected [$Expected], got [$Actual]" }
}

# Console assertions accept either locale's decimal separator without relaxing the totals.
function Assert-Match {
    param([string]$Actual, [string]$Pattern, [string]$Because)
    if ($Actual -notmatch $Pattern) { throw "$Because -- pattern not found: $Pattern" }
}

$script:passed = 0
# Isolate each fixture's local variables and mocks while retaining the shared loaded helpers.
function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    & $Body
    $script:passed++
    Write-Host "PASS: $Name" -ForegroundColor Green
}

Test-Case 'User sample reconciles exactly, including expired subsets' {
    $inputCounts = [ordered]@{
        '10060 (TimedOut)' = 1692
        '10061 (ConnectionRefused)' = 6
        'DnsFailure: No such host is known.' = 2723
        ExpiredNoChain = 1
        ExpiredPartialChain = 2
        FullChain = 106
        MSFT = 891
        NoChain = 55
        PartialChain = 211
        "TlsError: Invalid private IP ' 10.60.204.118'" = 19
        'TlsError: transport error' = 1
    }
    $records = @(
        foreach ($entry in $inputCounts.GetEnumerator()) {
            for ($i = 0; $i -lt $entry.Value; $i++) { [pscustomobject]@{ TlsStatus = $entry.Key } }
        }
    )
    $summary = Get-TlsSummary $records
    Assert-Equal $summary.Total 5707 'Origin total'
    Assert-Equal $summary.Assessed 375 'Assessed total'
    Assert-Equal $summary.Unassessed 5332 'All other outcomes'
    Assert-Equal $summary.Counts.NoChain 56 'Leaf only'
    Assert-Equal $summary.Counts.PartialChain 213 'Partial'
    Assert-Equal $summary.Counts.FullChain 106 'Full'
    Assert-Equal $summary.Expired.NoChain 1 'Expired leaf only'
    Assert-Equal $summary.Expired.PartialChain 2 'Expired partial'
    Assert-Equal $summary.Counts.TlsError 20 'TLS errors aggregate'
    Assert-Equal $summary.Counts.DnsFailure 2723 'DNS errors retained'
    Assert-Equal $summary.Counts.TcpTimeout 1692 'Timeouts retained'
    Assert-Equal $summary.Counts.MicrosoftManaged 891 'Managed, not verified'
    $text = (Write-TlsStatusBreakdown -Records $records -TargetRecords @() 6>&1 | Out-String)
    Assert-Match $text 'No Chain \(leaf only\)\s+56\s+0\s+1[.,]0%\s+1' 'Primary row and all-origin denominator'
    Assert-Match $text 'Partial Chain \(2 certs\)\s+213\s+0\s+3[.,]7%\s+2' 'Partial includes expired'
    Assert-Match $text 'Full Chain \(3\+ certs\)\s+106\s+0\s+1[.,]9%\s+0' 'Full row'
    Assert-Match $text 'Not assessed\s+5332\s+0\s+93[.,]4%\s+-' 'Unassessed completes primary table'
    Assert-Equal ($text -match 'Certificates observed|% assessed') $false 'Old subtotal and denominator removed'
    Assert-Match $text 'Unique targets' 'Unambiguous target header'
    $report = Get-TlsReportData $records @()
    Assert-Equal (($report.Primary.Origins | Measure-Object -Sum).Sum) 5707 'Four rows sum to every origin'
    Assert-Equal ([Math]::Round(($report.Primary.'% all origins' | Measure-Object -Sum).Sum, 12)) 1.0 'Unrounded percentages sum to 100%'
    Assert-Equal ($text -cmatch 'GOOD|BAD|Invalid private IP|No such host is known') $false 'No raw diagnostic spam or misleading verdicts'
}

Test-Case 'Latest 3780-origin excerpt uses all-origin percentages and four primary rows' {
    $records = @(
        foreach ($entry in ([ordered]@{
            NoChain = 33; ExpiredNoChain = 1; PartialChain = 115; ExpiredPartialChain = 2
            FullChain = 67; MSFT = 632; DnsFailure = 1791; TcpTimeout = 1094; TcpRefused = 6; 'TlsError: fixture' = 39
        }).GetEnumerator()) {
            for ($i = 0; $i -lt $entry.Value; $i++) { [pscustomobject]@{ TlsStatus = $entry.Key } }
        }
    )
    $text = (Write-TlsStatusBreakdown $records @() 6>&1 | Out-String)
    Assert-Match $text 'No Chain \(leaf only\)\s+34\s+0\s+0[.,]9%\s+1' 'Leaf-only percentage includes unassessed'
    Assert-Match $text 'Partial Chain \(2 certs\)\s+117\s+0\s+3[.,]1%\s+2' 'Partial percentage includes unassessed'
    Assert-Match $text 'Full Chain \(3\+ certs\)\s+67\s+0\s+1[.,]8%\s+0' 'Full percentage includes unassessed'
    Assert-Match $text 'Not assessed\s+3562\s+0\s+94[.,]2%\s+-' 'Unassessed row replaces subtotal'
    $report = Get-TlsReportData $records @()
    Assert-Equal $report.Primary.Count 4 'Four primary categories only'
    Assert-Equal $report.Primary[3].'Server-sent chain' 'Not assessed' 'Not assessed is last'
    Assert-Equal (($report.Secondary.Origins | Measure-Object -Sum).Sum) $report.Primary[3].Origins 'Gray breakdown reconciles to primary row'
}

Test-Case '5706-origin excerpt places the grand total and unassessed subtotal in separate blocks' {
    $originCounts = [ordered]@{
        NoChain = 33; ExpiredNoChain = 1; PartialChain = 112; ExpiredPartialChain = 2
        FullChain = 52; Disabled = 503; MigratedClassic = 1926; MSFT = 570
        DnsFailure = 1514; TcpTimeout = 952; TcpRefused = 6; 'TlsError: fixture' = 35
    }
    $targetCounts = [ordered]@{
        NoChain = 33; PartialChain = 111; FullChain = 48; Disabled = 414; MigratedClassic = 50
        MSFT = 312; DnsFailure = 1338; TcpTimeout = 856; TcpRefused = 6; 'TlsError: fixture' = 29
    }
    $records = @(foreach ($entry in $originCounts.GetEnumerator()) {
        for ($i = 0; $i -lt $entry.Value; $i++) { [pscustomobject]@{ TlsStatus = $entry.Key } }
    })
    $targets = @(foreach ($entry in $targetCounts.GetEnumerator()) {
        for ($i = 0; $i -lt $entry.Value; $i++) { [pscustomobject]@{ TlsStatus = $entry.Key } }
    })
    $text = (Write-TlsStatusBreakdown $records $targets 6>&1 | Out-String)
    $blocks = $text -split 'Not assessed breakdown', 2
    Assert-Equal $blocks.Count 2 'Two clearly separated report blocks'
    Assert-Match $blocks[0] 'Grand total \(all origins\)\s+5706\s+3197\s+100[.,]0%\s+-' 'Grand total belongs to primary table'
    Assert-Match $blocks[1] 'Not assessed subtotal\s+5506\s+3005' 'Subset has its own subtotal'
    Assert-Equal ($blocks[1] -match 'Grand total|TOTAL \(all outcomes\)') $false 'No grand total inside subset breakdown'
    Assert-Match $blocks[1] 'included above, not additional origins' 'No implication of additional inventory'
    $report = Get-TlsReportData $records $targets
    Assert-Equal $report.UnassessedOrigins (($report.Secondary.Origins | Measure-Object -Sum).Sum) 'Origin subtotal reconciles to secondary rows'
    Assert-Equal $report.UnassessedTargets (($report.Secondary.'Unique targets' | Measure-Object -Sum).Sum) 'Target subtotal reconciles to secondary rows'
}

Test-Case 'All categories, empty input, and SkipTls have reconciled totals' {
    $statuses = @('ExpiredFullChain', 'MSFT', 'Skipped', 'DnsFailure: localized error', 'TcpTimeout',
        'TcpRefused', 'TcpReset', '10054 (ConnectionReset)', 'TlsError: timeout', 'NoCert', 'new status', $null)
    $records = @($statuses | ForEach-Object { [pscustomobject]@{ TlsStatus = $_ } })
    $summary = Get-TlsSummary $records
    Assert-Equal $summary.Total 12 'Every row counted'
    Assert-Equal $summary.Assessed 1 'Only observed chains assessed'
    Assert-Equal $summary.Expired.FullChain 1 'Expired full chain'
    Assert-Equal $summary.Counts.TcpTimeout 1 'Fallback timeout status'
    Assert-Equal $summary.Counts.TcpRefused 1 'Fallback refused status'
    Assert-Equal $summary.Counts.TcpFailure 2 'Other TCP statuses'
    Assert-Equal $summary.Counts.Other 2 'Null and unknown accounted for'
    $empty = Get-TlsSummary @()
    Assert-Equal $empty.Total 0 'Empty input supported'
    $text = (Write-TlsStatusBreakdown -Records @([pscustomobject]@{ TlsStatus = 'Skipped' }) -TargetRecords @() 6>&1 | Out-String)
    Assert-Match $text 'No Chain \(leaf only\)\s+0\s+0\s+0[.,]0%\s+0' 'Skipped origins are in the denominator'
    Assert-Match $text 'Skipped \(-SkipTls\)\s+1' 'SkipTls remains visible'
    $emptyText = (Write-TlsStatusBreakdown -Records @() -TargetRecords @() 6>&1 | Out-String)
    Assert-Match $emptyText 'No Chain \(leaf only\)\s+0\s+0\s+-\s+0' 'Empty inventory has no divide by zero'
    Assert-Match $emptyText 'Grand total \(all origins\)\s+0\s+0\s+-\s+-' 'Empty inventory does not claim 100%'
    Assert-Match $emptyText 'Not assessed subtotal\s+0\s+0' 'Empty subset has a zero subtotal'
}

Test-Case 'Only completed Classic migration is skipped' {
    foreach ($state in @('Migrated', 'migrated', ' Migrated ')) {
        Assert-Equal (Test-IsMigratedClassicProfile 'Microsoft.Network/frontDoors' $state) $true 'Completed migration'
    }
    foreach ($state in @('Migrating', 'Disabled', 'Enabled', 'AbortingMigration', '', $null, 'Unknown')) {
        Assert-Equal (Test-IsMigratedClassicProfile 'microsoft.network/frontdoors' $state) $false 'Conservative inclusion'
    }
    Assert-Equal (Test-IsMigratedClassicProfile 'microsoft.cdn/profiles' 'Migrated') $false 'Replacement profile stays included'
}

Test-Case 'ARG retains migrated profiles for inventory without losing migration state' {
    $headers = @{}
    $subscriptionIds = @('sub')
    $subscriptionLookup = @{ sub = 'Subscription' }
    function Invoke-ResourceGraphQueryAllPages {
        @('Migrated', 'Migrating', '') | ForEach-Object {
            [pscustomobject]@{
                subscriptionId = 'sub'; resourceGroup = 'rg'; profileName = "classic-$_"
                profileId = "id-$_"; frontDoorId = 'fdid'; resourceType = 'microsoft.network/frontdoors'
                deploymentModel = 'Classic'; skuName = 'Classic_AzureFrontDoor'; resourceState = $_
            }
        }
    }
    . (Get-ProductionStage '$profileQuery = @"' '# Stage 4 is split')
    Assert-Equal $discoveredProfileCount 3 'All discovered profiles reported'
    Assert-Equal $migratedClassicProfileCount 1 'Migrated profile counted'
    Assert-Equal $profilesScannedCount 3 'All profiles inventoried'
    Assert-Equal @($profiles | Where-Object ResourceState -eq 'Migrated').Count 1 'Migrated profile retained for row counts'
    Assert-Match $profileQuery 'resourceState = tostring\(properties.resourceState\)' 'ARG projects actual resource state'
}

Test-Case 'Classic ARM recheck retains backends and marks completed migrations' {
    $classicProfiles = @(
        foreach ($name in @('already', 'migrated', 'migrating', 'missing')) {
            [pscustomobject]@{
                SubscriptionName = 'Subscription'; SubscriptionId = 'sub'; ResourceGroup = 'rg'
                ProfileName = $name; ProfileId = "id-$name"; ResourceType = 'microsoft.network/frontdoors'
                DeploymentModel = 'Classic'; SkuName = 'Classic_AzureFrontDoor'
                ResourceState = if ($name -eq 'already') { 'Migrated' } else { '' }
            }
        }
    )
    $headers = @{}; $classicApiVersion = '2021-06-01'; $ThrottleLimit = 2
    $migratedClassicProfileCount = 1; $profilesScannedCount = 4
    $originGroupList = [System.Collections.Generic.List[object]]::new()
    $allRecordsList = [System.Collections.Generic.List[object]]::new()
    $classicMigrationFuncText = "function Test-IsMigratedClassicProfile { ${function:Test-IsMigratedClassicProfile} }"
    $ArmRetryFuncText = @'
function Invoke-ArmRequestWithRetry {
    param($Method, $Uri, $Headers)
    $properties = [ordered]@{
        frontdoorId = 'fdid'
        backendPools = @([pscustomobject]@{
            name = 'pool'; properties = [pscustomobject]@{
                backends = @([pscustomobject]@{
                    address = '127.0.0.1'; backendHostHeader = 'test'; enabledState = 'Enabled'
                    httpPort = 80; httpsPort = 443; priority = 1; weight = 100
                })
            }
        })
    }
    if ($Uri -match '/migrating\?') { $properties.resourceState = 'Migrating' }
    if ($Uri -match '/migrated\?') { $properties.resourceState = 'Migrated' }
    [pscustomobject]@{ properties = [pscustomobject]$properties }
}
'@
    . (Get-ProductionStage 'if ($classicProfiles) {' '$originGroups = @($originGroupList)')
    Assert-Equal $migratedClassicProfileCount 2 'Fresh ARM migration counted without double counting ARG'
    Assert-Equal $profilesScannedCount 4 'All profiles inventoried'
    Assert-Equal $originGroupList.Count 4 'All pools retained'
    Assert-Equal $allRecordsList.Count 4 'All origins retained'
    Assert-Equal @($allRecordsList | Where-Object { (Get-OriginSkipStatus $_) -eq 'MigratedClassic' }).Count 2 'Both completed migrations excluded from probes'
}

Test-Case 'An all-migrated discovery still schedules inventory for reporting' {
    $headers = @{}
    $subscriptionIds = @('sub')
    $subscriptionLookup = @{ sub = 'Subscription' }
    $scriptStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    function Invoke-ResourceGraphQueryAllPages {
        [pscustomobject]@{
            subscriptionId = 'sub'; resourceGroup = 'rg'; profileName = 'old'
            profileId = 'id'; frontDoorId = 'fdid'; resourceType = 'microsoft.network/frontdoors'
            deploymentModel = 'Classic'; skuName = 'Classic_AzureFrontDoor'; resourceState = 'Migrated'
        }
    }
    . (Get-ProductionStage '$profileQuery = @"' '# Stage 4 is split')
    Assert-Equal $migratedClassicProfileCount 1 'Migration count retained'
    Assert-Equal $profiles.Count 1 'Migrated profile reaches inventory'
    Assert-Equal $profilesScannedCount 1 'Inventory is still scheduled'
    $scriptStopwatch.Stop()
}

Test-Case 'Disabled and migrated records cannot schedule DNS or TLS, including shared endpoints' {
    $allRecords = @(
        [pscustomobject]@{ HostName = 'shared.test'; HttpsPort = 443; OriginHostHeader = ''; EnabledState = 'Disabled' }
        [pscustomobject]@{ HostName = 'disabled.test'; HttpsPort = 443; OriginHostHeader = ''; EnabledState = 'Disabled' }
        [pscustomobject]@{ HostName = 'old.test'; HttpsPort = 443; OriginHostHeader = ''; EnabledState = 'Enabled'; ResourceType = 'microsoft.network/frontdoors'; ProfileResourceState = 'Migrated' }
        [pscustomobject]@{ HostName = 'shared.test'; HttpsPort = 443; OriginHostHeader = ''; EnabledState = 'Enabled' }
        [pscustomobject]@{ HostName = 'disabled.azurewebsites.net'; HttpsPort = 443; OriginHostHeader = ''; EnabledState = 'Disabled' }
        [pscustomobject]@{ HostName = 'managed.azurewebsites.net'; HttpsPort = 443; OriginHostHeader = ''; EnabledState = 'Enabled' }
    )
    . (Get-ProductionStage '$tlsLookup = @{}' '$targetResolutionLookup = @{}')
    Assert-Equal $tlsTargets.Count 1 'Only active unmanaged origin can be probed'
    Assert-Equal $tlsTargets[0].ConnectTo 'shared.test' 'Disabled reference does not suppress active reference'
    Assert-Equal $tlsLookup.Count 1 'Only active managed origin is seeded as MSFT'
    Assert-Equal $msftSkippedRecordCount 1 'Disabled managed origin retains Disabled category'

    $tlsLookup['shared.test|443|shared.test'] = New-TlsResultObject FullChain -ServerCertificateCount 3
    $targetResolutionLookup = @{}
    $privateIpTlsLookup = @{}
    $applicationGatewaySecurityInventory = $null
    function Get-ApplicationGatewayOriginSecurityResult {
        param($Record, $ResolutionResult, $Inventory)
        [pscustomobject]@{ Status = $null; Reason = $null; NsgResourceIds = $null; WafPolicyIds = $null }
    }
    . (Get-ProductionStage '$stampFromResolution' "Write-PhaseBanner -Phase '8'")
    Assert-Equal $allRecords[0].TlsStatus 'Disabled' 'Disabled row never borrows active certificate'
    Assert-Equal $allRecords[0].ServerCertificateCount $null 'No certificates attributed to skipped row'
    Assert-Equal $allRecords[2].TlsStatus 'MigratedClassic' 'Migrated row visible in output'
    Assert-Equal $finalTargetResultLookup['shared.test|443|shared.test'].TlsStatus 'FullChain' 'Active result wins after disabled row'
    [array]::Reverse($allRecords)
    . (Get-ProductionStage '$stampFromResolution' "Write-PhaseBanner -Phase '8'")
    Assert-Equal $finalTargetResultLookup['shared.test|443|shared.test'].TlsStatus 'FullChain' 'Active result wins regardless of inventory order'
    $report = Get-TlsReportData $allRecords @($finalTargetResultLookup.Values)
    Assert-Equal $report.Primary[3].Origins 5 'All skipped/managed rows are Not assessed'
    Assert-Equal $report.Primary[3].'Unique targets' 4 'Shared endpoint counted only once'
    Assert-Equal $report.Targets 5 'Unique target total is additive'
}

Test-Case 'Migration wins over disabled for row categories; disabled wins for shared target totals' {
    $migrated = [pscustomobject]@{
        ResourceType = 'microsoft.network/frontdoors'; ProfileResourceState = 'Migrated'; EnabledState = 'Disabled'
    }
    Assert-Equal (Get-OriginSkipStatus $migrated) 'MigratedClassic' 'No double counting for migrated disabled row'
    Assert-Equal ((Get-TlsTargetResultPriority ([pscustomobject]@{ TlsStatus = 'Disabled' })) -gt
        (Get-TlsTargetResultPriority ([pscustomobject]@{ TlsStatus = 'MigratedClassic' }))) $true 'Non-migrated reference wins for an otherwise skipped target'
    Assert-Equal ((Get-TlsTargetResultPriority ([pscustomobject]@{ TlsStatus = 'TcpTimeout' })) -gt
        (Get-TlsTargetResultPriority ([pscustomobject]@{ TlsStatus = 'Disabled' }))) $true 'Active failure still wins over disabled reference'
}

Test-Case 'DNS resolves once per host while preserving port and SNI targets' {
    $TlsThrottleLimit = 2
    $dnsProbeFuncText = "function Get-OrderedProbeAddresses { ${function:Get-OrderedProbeAddresses} }"
    $tlsTargets = @(
        [pscustomobject]@{ ConnectTo = '127.0.0.1'; Port = 443; SniName = 'one.test' }
        [pscustomobject]@{ ConnectTo = '127.0.0.1'; Port = 8443; SniName = 'two.test' }
        [pscustomobject]@{ ConnectTo = '::1'; Port = 443; SniName = 'three.test' }
    )
    . (Get-ProductionStage '$targetResolutionLookup = @{}' '$applicationGatewayIds = @(')
    Assert-Equal $dnsHosts.Count 2 'Only unique hostnames scheduled'
    Assert-Equal $resolutionComplete 2 'Only unique resolutions executed'
    Assert-Equal $targetResolutionLookup.Count 3 'Distinct TLS triples retained'
    Assert-Equal $targetResolutionLookup['127.0.0.1|8443|two.test'].Port 8443 'Port retained'
    Assert-Equal $targetResolutionLookup['127.0.0.1|8443|two.test'].ResolvedAddresses[0] '127.0.0.1' 'Shared DNS addresses'
    Assert-Equal $targetResolutionLookup['::1|443|three.test'].ResolvedAddresses[0] '::1' 'IPv6 preserved'
}

Test-Case 'Private_IP whitespace is removed before deduplication and parsing' {
    function Invoke-ResourceGraphQueryAllPages {
        [pscustomobject]@{
            ipAddress = '203.0.113.10'; ipConfigurationId = ''; natGatewayId = ''
            linkedPublicIpAddressId = ''; publicIpResourceId = 'pip'; privateIpTag = ' 10.60.204.118 '
        }
    }
    $lookup = Get-AzurePublicIpResourceLookup -Headers @{} -SubscriptionIds @('sub') -PublicIpAddresses @('203.0.113.10')
    Assert-Equal $lookup['203.0.113.10'].PrivateIpTag '10.60.204.118' 'Trim tag at ingestion'
    $metadata = Get-ResolvedIpMetadata -IpAddresses @('203.0.113.10') -AzurePublicIpLookup $lookup
    Assert-Equal $metadata.AzurePrivateIpTag '10.60.204.118' 'Trimmed tag propagated'
    $ip = $null
    Assert-Equal ([System.Net.IPAddress]::TryParse($metadata.AzurePrivateIpTag, [ref]$ip)) $true 'Original invalid-IP symptom removed'
}

Test-Case 'Fallback only applies when no certificate was observed' {
    foreach ($status in @('NoChain', 'PartialChain', 'FullChain', 'ExpiredNoChain', 'ExpiredPartialChain', 'ExpiredFullChain')) {
        Assert-Equal (Test-NeedsPrivateIpProbe ([pscustomobject]@{ TlsStatus = $status })) $false 'Never replace an observed chain'
    }
    foreach ($status in @('DnsFailure', '10060 (TimedOut)', 'TlsError: failure', 'NoCert')) {
        Assert-Equal (Test-NeedsPrivateIpProbe ([pscustomobject]@{ TlsStatus = $status })) $true 'Failed public probe eligible'
    }
    Assert-Equal (Test-NeedsPrivateIpProbe $null) $true 'Missing result eligible'
}

Test-Case 'SkipTls and Microsoft-managed rows remain unassessed, not bad chains' {
    $allRecords = @(
        [pscustomobject]@{ HostName = 'managed.test'; OriginHostHeader = ''; HttpsPort = 443 }
        [pscustomobject]@{ HostName = 'skipped.test'; OriginHostHeader = ''; HttpsPort = 443 }
        [pscustomobject]@{ HostName = ''; OriginHostHeader = ''; HttpsPort = 443 }
    )
    $tlsLookup = @{
        'managed.test|443|managed.test' = New-TlsResultObject MSFT
        'skipped.test|443|skipped.test' = New-TlsResultObject Skipped
    }
    $privateIpTlsLookup = @{}
    $targetResolutionLookup = @{}
    $applicationGatewaySecurityInventory = $null
    function Get-ApplicationGatewayOriginSecurityResult {
        param($Record, $ResolutionResult, $Inventory)
        [pscustomobject]@{ Status = $null; Reason = $null; NsgResourceIds = $null; WafPolicyIds = $null }
    }
    . (Get-ProductionStage '$stampFromResolution' "Write-PhaseBanner -Phase '8'")
    Assert-Equal ($allRecords.ChainStatus -join ',') 'NotAssessed,NotAssessed,NotAssessed' 'No implied verification'
    Assert-Equal $allRecords[2].TlsStatus 'N/A' 'Missing hostname remains in origin totals'
    Assert-Equal $finalTargetResultLookup.Count 2 'Missing hostname is not a target'
    $summary = Get-TlsSummary $allRecords
    Assert-Equal $summary.Assessed 0 'No assessed certificates'
    Assert-Equal $summary.Unassessed 3 'Every row reconciled'
}

Test-Case 'Final stamping and exports prioritize chains and isolate shared fallback' {
    $allRecords = @(
        foreach ($name in @('public-ok', 'public-failed', 'expired', 'partial', 'unreachable', 'duplicate')) {
            [pscustomobject]@{
                SubscriptionName = 'Subscription'; ResourceGroup = 'rg'; ProfileName = 'profile'
                OriginGroupName = 'group'; OriginName = $name
                HostName = if ($name -eq 'duplicate') { 'public-ok' } else { $name }
                OriginHostHeader = 'sni.test'; HttpsPort = 443
            }
        }
    )
    $tlsLookup = @{
        'public-ok|443|sni.test' = New-TlsResultObject -TlsStatus FullChain -ServerCertificateCount 3 -TcpAttemptedAddresses '203.0.113.1'
        'public-failed|443|sni.test' = New-TlsResultObject -TlsStatus '10060 (TimedOut)' -TcpAttemptedAddresses '203.0.113.2'
        'expired|443|sni.test' = New-TlsResultObject -TlsStatus ExpiredPartialChain -ServerCertificateCount 2
        'partial|443|sni.test' = New-TlsResultObject -TlsStatus PartialChain -ServerCertificateCount 2
        'unreachable|443|sni.test' = New-TlsResultObject -TlsStatus 'TlsError: fixture failure'
    }
    $privateIpTlsLookup = @{
        '10.0.0.1|443|sni.test' = New-TlsResultObject -TlsStatus NoChain -ServerCertificateCount 1 -TcpAttemptedAddresses '10.0.0.1'
    }
    $targetResolutionLookup = @{}
    foreach ($key in $tlsLookup.Keys) {
        $targetResolutionLookup[$key] = [pscustomobject]@{ AzurePrivateIpTag = if ($key -match '^public-') { '10.0.0.1' } else { $null } }
    }
    $applicationGatewaySecurityInventory = $null
    function Get-ApplicationGatewayOriginSecurityResult {
        param($Record, $ResolutionResult, $Inventory)
        [pscustomobject]@{ Status = $null; Reason = $null; NsgResourceIds = $null; WafPolicyIds = $null }
    }
    . (Get-ProductionStage '$stampFromResolution' "Write-PhaseBanner -Phase '8'")
    Assert-Equal ($allRecords | Where-Object OriginName -eq 'public-ok').TlsStatus 'FullChain' 'Public success not overwritten'
    Assert-Equal ($allRecords | Where-Object OriginName -eq 'public-ok').TcpAttemptedAddresses '203.0.113.1' 'Successful public target has no spurious private attempt'
    Assert-Equal ($allRecords | Where-Object OriginName -eq 'public-failed').TlsStatus 'NoChain' 'Failed public target uses fallback'
    Assert-Equal ($allRecords | Where-Object OriginName -eq 'public-failed').TcpAttemptedAddresses '203.0.113.2, 10.0.0.1' 'Both attempts retained'
    Assert-Equal ($allRecords | Where-Object OriginName -eq 'expired').ChainStatus 'PartialChain' 'Expired chain grouped'
    Assert-Equal ($allRecords | Where-Object OriginName -eq 'expired').LeafExpired $true 'Expiry retained'
    Assert-Equal ($allRecords | Where-Object OriginName -eq 'unreachable').ChainStatus 'NotAssessed' 'Failure not a bad chain'
    Assert-Equal ($allRecords | Where-Object OriginName -eq 'unreachable').LeafExpired $null 'Unassessed expiry not false'
    Assert-Equal $finalTargetResultLookup.Count 5 'Duplicate origin shares one final target'
    $targetSummary = Get-TlsSummary @($finalTargetResultLookup.Values)
    Assert-Equal $targetSummary.Counts.FullChain 1 'Deduplicated full-chain target'
    Assert-Equal $targetSummary.Counts.NoChain 1 'Target summary reflects fallback'

    $testDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("afd-regression-{0}" -f [guid]::NewGuid())
    [void][System.IO.Directory]::CreateDirectory($testDirectory)
    $OutputCsvPath = Join-Path $testDirectory 'Summary.csv'
    $xlsxOutputPath = [System.IO.Path]::ChangeExtension($OutputCsvPath, '.xlsx')
    try {
        . (Get-ProductionStage "Write-PhaseBanner -Phase '8'" '$distinctOrigins = @(')
        $exported = @(Import-Csv -LiteralPath $OutputCsvPath)
        Assert-Equal $exported.Count 6 'Every eligible origin exported'
        Assert-Equal ($exported.ChainStatus -join ',') 'NoChain,PartialChain,PartialChain,FullChain,FullChain,NotAssessed' 'Chain-first sort'
        Assert-Equal (($exported[0].PSObject.Properties.Name | Select-Object -First 6) -join ',') 'ChainStatus,TlsStatus,ServerCertificateCount,LeafExpired,HostName,OriginHostHeader' 'Leading diagnostic columns'
        if ($importExcelModule) {
            Assert-Equal $xlsxWasExported $true 'Optional XLSX export must succeed when installed'
            $sheet = @(Import-Excel -Path $xlsxOutputPath -WorksheetName $worksheetName)
            Assert-Equal $sheet.Count 6 'XLSX rows match CSV'
            Assert-Equal ($sheet.ChainStatus -join ',') ($exported.ChainStatus -join ',') 'CSV/XLSX order matches'
            # Validate the saved artifact, not just the in-memory workbook used to create it.
            $package = Open-ExcelPackage -Path $xlsxOutputPath
            try {
                Assert-Equal $package.Workbook.Worksheets.Count 2 'Detail plus summary worksheet'
                Assert-Equal $package.Workbook.Worksheets[1].Name 'Origins' 'Summary filename cannot collide with summary sheet'
                Assert-Equal $package.Workbook.Worksheets[2].Name 'Summary' 'Summary is the second worksheet'
                $summarySheet = $package.Workbook.Worksheets['Summary']
                Assert-Equal $summarySheet.Tables.Count 2 'Primary and unassessed breakdown tables'
                Assert-Equal $summarySheet.Tables['ChainSummary'].Address.Address 'A4:E8' 'Four primary rows in table'
                Assert-Equal $summarySheet.Cells['A8'].Value 'Not assessed' 'Not assessed last in primary table'
                Assert-Equal $summarySheet.Cells['B8'].Value 1 'Saved unassessed total'
                Assert-Equal $summarySheet.Cells['C9'].Value 5 'Saved distinct target total'
                Assert-Equal $summarySheet.Cells['A9'].Value 'Grand total (all origins)' 'Saved grand total has explicit scope'
                Assert-Equal $summarySheet.Cells['A25'].Value 'Not assessed subtotal' 'Saved breakdown has its own subtotal'
                Assert-Equal $summarySheet.Cells['B25'].Value $summarySheet.Cells['B8'].Value 'Saved origin subtotal matches Not assessed'
                Assert-Equal $summarySheet.Cells['C25'].Value $summarySheet.Cells['C8'].Value 'Saved target subtotal matches Not assessed'
                Assert-Equal $summarySheet.Cells['A25'].Style.Font.Color.Rgb 'FF696969' 'Saved subtotal remains gray'
                Assert-Equal $summarySheet.Cells['D5'].Value (1.0 / 6.0) 'Numeric all-origin percentage, not formatted text'
                Assert-Equal $summarySheet.Cells['D5'].Style.Numberformat.Format '0.0%' 'Excel percentage format'
                Assert-Equal $summarySheet.Cells['A8'].Style.Font.Color.Rgb 'FF696969' 'Unassessed row is gray'
                Assert-Equal $summarySheet.Cells['A14'].Style.Font.Color.Rgb 'FF696969' 'Secondary breakdown is gray'
                Assert-Equal $package.Workbook.Worksheets[1].Cells['A7'].Style.Font.Color.Rgb 'FF696969' 'Unassessed detail row is gray'
                Assert-Equal $summarySheet.Drawings.Count 1 'One summary chart'
                $chartXml = $summarySheet.Drawings[0].ChartXml
                $ns = [System.Xml.XmlNamespaceManager]::new($chartXml.NameTable)
                $ns.AddNamespace('c', 'http://schemas.openxmlformats.org/drawingml/2006/chart')
                $ns.AddNamespace('a', 'http://schemas.openxmlformats.org/drawingml/2006/main')
                Assert-Equal $chartXml.SelectSingleNode('//c:ser/c:val/c:numRef/c:f', $ns).InnerText "'Summary'!B5:B8" 'Chart includes all four categories, excludes total'
                Assert-Equal $chartXml.SelectSingleNode('//c:ser/c:dPt[c:idx/@val="3"]/c:spPr/a:solidFill/a:srgbClr', $ns).GetAttribute('val') 'A5A5A5' 'Chart unassessed segment is gray'
                Assert-Equal $chartXml.SelectSingleNode('//c:dLbls/c:numFmt', $ns).GetAttribute('formatCode') '0.0%' 'Chart label percentage format'
            }
            finally { $package.Dispose() }
            # EPPlus can substitute its default style on load; check the persisted OOXML itself.
            $archive = [System.IO.Compression.ZipFile]::OpenRead($xlsxOutputPath)
            try {
                foreach ($entry in @($archive.Entries | Where-Object FullName -like 'xl/tables/table*.xml')) {
                    $reader = [System.IO.StreamReader]::new($entry.Open())
                    try { [xml]$tableXml = $reader.ReadToEnd() } finally { $reader.Dispose() }
                    Assert-Equal $tableXml.table.tableStyleInfo.name 'TableStyleMedium2' 'Persisted table style'
                    Assert-Equal $tableXml.table.tableStyleInfo.showRowStripes '0' 'Persisted row banding disabled'
                }
            }
            finally { $archive.Dispose() }
        }

        $subscriptions = @('sub')
        $discoveredProfileCount = 4
        $profilesScannedCount = 2
        $migratedClassicProfileCount = 2
        $originGroups = @('group')
        $tlsTargets = @('one', 'two', 'three', 'four', 'five')
        $applicationGatewayIds = @()
        $SkipTls = $false
        $scriptStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $summaryStart = $source.IndexOf('$distinctOrigins = @(', [StringComparison]::Ordinal)
        $console = (. ([scriptblock]::Create($source.Substring($summaryStart))) 6>&1 | Out-String)
        Assert-Match $console 'No Chain \(leaf only\)\s+1\s+1' 'Final console uses post-fallback results'
        Assert-Match $console 'Full Chain \(3\+ certs\)\s+2\s+1' 'Final console separates origins and targets'
        Assert-Match $console 'Classic migrated \(no TLS\):\s+2' 'Final migration inventory statistics'
        Assert-Equal ($console.IndexOf('ORIGIN CERTIFICATE CHAINS') -lt $console.IndexOf('Scan details:')) $true 'Chains presented first'

        # Reusing an output path must replace summary tables/chart, including an all-skipped run.
        $finalTargetResultLookup = @{}
        foreach ($record in $allRecords) {
            $record.TlsStatus = 'Disabled'
            $record.ChainStatus = 'NotAssessed'
            $record.LeafExpired = $null
            $record.ServerCertificateCount = $null
            $finalTargetResultLookup["$($record.HostName)|443|sni.test"] = $record
        }
        . (Get-ProductionStage "Write-PhaseBanner -Phase '8'" '$distinctOrigins = @(')
        if ($importExcelModule) {
            Assert-Equal $xlsxWasExported $true 'Repeated all-skipped workbook export succeeds'
            $package = Open-ExcelPackage -Path $xlsxOutputPath
            try {
                Assert-Equal $package.Workbook.Worksheets.Count 2 'Repeated export does not accumulate sheets'
                $summarySheet = $package.Workbook.Worksheets['Summary']
                Assert-Equal $summarySheet.Drawings.Count 1 'Repeated export does not duplicate charts'
                Assert-Equal $summarySheet.Tables.Count 2 'Repeated export does not duplicate tables'
                Assert-Equal $summarySheet.Cells['B8'].Value 6 'All skipped origins counted'
                Assert-Equal $summarySheet.Cells['C8'].Value 5 'All skipped unique targets counted'
                Assert-Equal $summarySheet.Cells['D8'].Value 1.0 'All-skipped chart/table represent 100% Not assessed'
                Assert-Equal $summarySheet.Cells['B14'].Value 6 'Disabled secondary count'
                Assert-Equal $summarySheet.Cells['B25'].Value 6 'Repeated export updates origin subtotal'
                Assert-Equal $summarySheet.Cells['C25'].Value 5 'Repeated export updates target subtotal'
                Assert-Equal $package.Workbook.Worksheets[1].Cells['A2'].Style.Font.Color.Rgb 'FF696969' 'First disabled detail row is gray'
            }
            finally { $package.Dispose() }
        }
    }
    finally {
        foreach ($path in @($OutputCsvPath, $xlsxOutputPath)) {
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
        }
        Remove-Item -LiteralPath $testDirectory
    }
}

Write-Host "`nAll $script:passed regression cases passed." -ForegroundColor Green
