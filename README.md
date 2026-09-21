# Get-AFDOriginCertChains

`Get-AFDOriginCertChains.ps1` scans every Azure Front Door Standard/Premium and Classic profile the current identity can read across all enabled subscriptions, enumerates every origin, and classifies the TLS certificate chain each distinct HTTPS origin endpoint presents.

- Authentication is Az PowerShell-only: use `Az.Accounts` and `Connect-AzAccount`. The script never calls Azure CLI.
- Discovery uses Azure Resource Graph plus ARM REST.
- Migrated Classic profiles (`properties.resourceState = Migrated`) are inventoried so every available backend appears as **Not assessed / MigratedClassic**, but they are never DNS/TCP/TLS-probed. Completion reported by either ARG or the ARM recheck suppresses probing. `Migrating`, missing, and unknown states are not treated as completed migrations.
- Disabled origins are also retained as **Not assessed / Disabled** without DNS/TCP/TLS probing. A disabled origin in a migrated Classic profile is counted as migrated, not twice.
- Each distinct hostname is resolved to IP addresses once per run (shared across ports/SNI names), and resolved public IPs are matched back to Azure public IP resources when possible.
- Origins resolving to a discoverable Application Gateway public frontend are checked against their subnet NSG and effective WAF policy.
- TLS probing deduplicates by hostname, effective HTTPS port, and effective SNI (`OriginHostHeader` when set, otherwise `HostName`).
- CSV is always written. If `ImportExcel` is installed, a companion XLSX includes a filterable detail worksheet and a second **Summary** worksheet with tables and a chart. Detail styling preserves `Medium2`, a frozen top row, disabled row banding, and literal text in host/IP columns.
- The primary summary has four rows: **No Chain**, **Partial Chain**, **Full Chain**, and **Not assessed**. All percentages use **all inventoried origin rows**, including disabled and migrated origins.

## What's new in 1.8.0

- Chain-first reporting with **Unique targets**, percentages of all origins, and clearly separated grand totals and Not assessed subtotals.
- Disabled and migrated Classic origins retained in inventory without DNS/TCP/TLS probing.
- An XLSX **Summary** worksheet with styled tables, a chart, and gray Not assessed rows.
- DNS resolution reused across targets sharing a hostname; whitespace-normalized private-IP tags and isolated private-IP fallback results.
- Expanded function/block documentation and 15 offline regression cases, including saved-workbook validation.

**Upgrade note:** CSV/XLSX detail columns now start with chain diagnostics, rows are sorted by chain category, and `ChainStatus`, `LeafExpired`, and `ProfileResourceState` are included. Consumers should use column names rather than fixed positions. Chain labels remain certificate-count heuristics, not cryptographic validation.

## Why Raw TLS Parsing

The script parses the TLS 1.2 Certificate message instead of relying on `X509Chain` alone.

- It counts only the certificates the server actually sent.
- It avoids false positives caused by locally cached intermediates.
- It keeps chain completeness classification consistent across repeated runs.

**Important:** the existing names are certificate-count heuristics, not cryptographic chain validation: `NoChain` = 1 certificate, `PartialChain` = 2, `FullChain` = 3 or more. A server normally need not send its root certificate; two certificates can be sufficient, and three certificates do not prove a complete, trusted chain. These labels do not validate issuer linkage, signatures, hostname, trust, or revocation. The probe accepts certificates to inspect what was sent, including expired/untrusted certificates.

## Prerequisites

- PowerShell 7 or later.
- `Az.Accounts` PowerShell module.
- Optional: `ImportExcel` if you want XLSX output.
- An active Azure PowerShell login via `Connect-AzAccount`.
- Permissions to list subscriptions, query Azure Resource Graph, and read Front Door, Application Gateway, virtual network, NSG, and WAF policy metadata.
- Network access from the machine running the script to the origin HTTPS endpoints.

Install the required module if needed:

```powershell
Install-Module Az.Accounts -Scope CurrentUser
```

Optional XLSX support:

```powershell
Install-Module ImportExcel -Scope CurrentUser
```

Sign in before running the script:

```powershell
Connect-AzAccount
```

## Usage

```powershell
./Get-AFDOriginCertChains.ps1
./Get-AFDOriginCertChains.ps1 -OutputCsvPath .\results.csv
./Get-AFDOriginCertChains.ps1 -ThrottleLimit 32 -TlsThrottleLimit 128
./Get-AFDOriginCertChains.ps1 -SkipTls
./Get-AFDOriginCertChains.ps1 -TlsTimeoutMs 10000
```

## Parameters

| Parameter | Required | Default | Description |
| --- | --- | --- | --- |
| `OutputCsvPath` | No | `afd-impacted-origins-<timestamp>.csv` | Output CSV path. If `ImportExcel` is installed, the script also writes an XLSX with the same base name. |
| `ThrottleLimit` | No | Dynamic | Parallelism for ARM origin-group and origin enumeration. |
| `TlsThrottleLimit` | No | Dynamic | Parallelism for TLS checks. |
| `TlsTimeoutMs` | No | `5000` | Timeout in milliseconds for TCP and TLS operations. |
| `SkipTls` | No | Off | Enumerate origins, resolve/classify IP addresses, and skip TLS checks. |

The dynamic throttle defaults are derived from processor count and tuned separately for inventory and TLS probing.

## Output

The CSV and first XLSX worksheet contain one row per inventoried Front Door origin, including disabled origins and backends of migrated Classic profiles. The replacement Standard/Premium profile is still scanned if accessible; no name-based deduplication or inferred migration is used. Reading a migrated profile's backend configuration is necessary for accurate origin counts, but does not cause network probes. If the backend inventory cannot be retrieved, the script reports an error rather than inventing an origin count.

The leading columns are `ChainStatus`, `TlsStatus`, `ServerCertificateCount`, `LeafExpired`, `HostName`, and `OriginHostHeader`. Rows are sorted **NoChain -> PartialChain -> FullChain -> NotAssessed**, then by subscription/profile/origin. Existing columns and detailed `TlsStatus` values are preserved, but their order changes.

- `ChainStatus`: `NoChain`, `PartialChain`, `FullChain`, or `NotAssessed`. Expired variants are grouped with their observed chain shape.
- `LeafExpired`: `True`/`False` when a chain was observed, blank when not assessed. Expiration remains encoded in `TlsStatus` as well.

Key column groups:

- Inventory: `SubscriptionName`, `SubscriptionId`, `ResourceGroup`, `ProfileName`, `FrontDoorId`, `DeploymentModel`, `SkuName`, `ProfileResourceState`, `OriginGroupName`, `OriginName`
- Origin settings: `HostName`, `OriginHostHeader`, `HttpPort`, `HttpsPort`, `EnabledState`, `Priority`, `Weight`, `CertNameCheck`
- Resolved IPs: `ResolvedAddresses`, `IpKind`, `AzureResourceId`, `ApplicationGatewayResourceId`, `AzurePrivateIpTag`
- Application Gateway security: `ApplicationGatewayNsgResourceId`, `ApplicationGatewayWafPolicyId`, `AppGatewayFrontDoorSecurity`, `AppGatewayFrontDoorSecurityReason`

`AzureResourceId` remains the generic resource associated with the public IP. When that resource is an Application Gateway, `ApplicationGatewayResourceId` repeats it in a dedicated filterable column.

`AppGatewayFrontDoorSecurity` is blank for non-Application-Gateway origins and otherwise contains:

| Value | Meaning |
| --- | --- |
| `No` | The gateway subnet has no NSG, the NSG doesn't effectively allow `AzureFrontDoor.Backend`, or another public source is allowed on the origin HTTPS port. |
| `Yes` | The NSG restricts public client traffic to `AzureFrontDoor.Backend`, but matching `X-Azure-FDID` enforcement wasn't found in an enabled Prevention-mode WAF policy. |
| `Yes+WAF` | The NSG restriction is effective and every applicable WAF policy blocks requests whose `X-Azure-FDID` differs from this origin row's `FrontDoorId`. |
| `Unknown` | Referenced Application Gateway security metadata couldn't be read or safely evaluated. |

Application Gateway WAF policy precedence is evaluated from path rule to listener to gateway-wide policy. The check is conservative: broader public NSG allows, partial WAF coverage, Detection-mode policies, mismatched or multiple Front Door IDs, and earlier WAF allow rules don't qualify for `Yes+WAF`. `Yes+WAF` also requires an explicit `OriginHostHeader`; when it is blank, Front Door forwards the incoming hostname and the script can't determine a single effective Application Gateway listener from the origin record alone. Required platform/private rules such as `GatewayManager`, `AzureLoadBalancer`, and private-network sources don't invalidate the NSG result.

The Application Gateway analysis applies only when every resolved public address can be correlated to an accessible Application Gateway public IP resource. Mixed or uncorrelated public DNS answers are reported as `Unknown`. Internal-only and Azure Front Door Private Link Application Gateways aren't discoverable through this public-IP association and leave the Application Gateway security columns blank.

`AzurePrivateIpTag` is populated from the `Private_IP` tag on the matched Azure public IP resource, with surrounding whitespace removed. When the public-IP TLS probe fails to retrieve certificates and a private IP tag is present, the script falls back to probing the private IP directly (Phase 7b). The fallback result becomes the final result for that target, including its diagnostic if it also fails. A successful public probe (including an expired certificate) is never replaced by a fallback performed for another target sharing the same private IP. `TcpAttemptedAddresses` shows only the public IP when it succeeded, or both the public and private IPs when both were tested. Invalid tags are still reported as probe errors; multiple distinct tag values are not guessed or silently reduced to one IP.

- TLS results: `TlsPort`, `TlsStatus`, `TcpAttemptedAddresses`, `TcpConnectedAddress`, `ServerCertificateCount`, `DigiCertIssued`, `LeafSubject`, `LeafIssuer`, `LeafNotAfterUtc`, `IntermediateSubject`, `IntermediateIssuer`, `IntermediateNotAfterUtc`, `RootSubject`, `RootIssuer`, `RootNotAfterUtc`

`TlsStatus` is self-describing: on a successful handshake it holds the chain classification (`FullChain`, `PartialChain`, `NoChain`, `Expired*`, `NoCert`); on a TCP failure it holds the raw socket error in the form `<code> (<name>)`, for example `10060 (TimedOut)`; DNS failures are reported as `DnsFailure: <message>`, and TLS handshake errors as `TlsError: <message>`.

The certificate columns reflect the server-sent chain positions: `Leaf*` is certificate #1, `Intermediate*` is certificate #2, and `Root*` is the last certificate when at least three were sent. The script does not verify these roles; the last certificate may be another intermediate rather than a root.

Console output includes:

- phase-based progress updates for discovery, inventory, Application Gateway security analysis, and TLS probing
- a four-row chain table ending in **Not assessed**, with origin row counts, **Unique targets**, percentages **among all origin rows**, and expired origin row subsets (blank/dash for Not assessed)
- a compact, gray secondary breakdown of the Not assessed row: disabled, migrated Classic, Microsoft-managed, skipped, DNS failures, TCP timeouts/refusals/other TCP failures, TLS/probe errors, no certificates, and other/unavailable results; per-origin diagnostics remain in `TlsStatus`
- reconciled assessed/unassessed totals; unreachable origins are **not** described as bad certificate chains, and Microsoft-managed origins are **not** described as verified chains
- a **Grand total (all origins)** directly below the four primary categories, and a separate gray **Not assessed subtotal** below the breakdown; the breakdown is included in the primary table, not additional origins
- discovery/inventory totals and a count of migrated Classic profiles excluded from probing

**Unique targets** are hostname + HTTPS port + effective SNI (the origin host header if set, otherwise hostname). Counts use final results after private-IP fallback and include managed/skipped endpoints, so they differ from the **Unmanaged TLS targets** scan counter. Rows without a hostname count as origins but have no target.

When active, disabled, and migrated origin records share an endpoint, it is counted **once** in the unique-target totals: an active result takes precedence over a disabled reference, which takes precedence over a migrated reference. This keeps the unique-target column additive. The skipped origin rows themselves remain Not assessed and never inherit the active origin's certificate or resolved-IP metadata.

Example console summary for 5,706 inventoried origin rows:

```text
Server-sent chain                 Origins   Unique targets   % all origins   Expired
No Chain (leaf only)                    34               33            0.6%         1
Partial Chain (2 certs)                 114              111            2.0%         2
Full Chain (3+ certs)                    52               48            0.9%         0
Not assessed                         5506             3005           96.5%         -
----------------------------------------------------------------------------------
Grand total (all origins)             5706             3197          100.0%         -

Not assessed breakdown (included above, not additional origins):
Outcome                           Origins   Unique targets
Disabled origins (not probed)          503              414
Migrated Classic (not probed)         1926               50
Microsoft-managed (not probed)         570              312
DNS failure                          1514             1338
TCP timeout                           952              856
TCP connection refused                  6                6
TLS / probe error                      35               29
----------------------------------------------------------
Not assessed subtotal                5506             3005
```

The four primary rows sum to **5,706 origins / 3,197 unique targets**. The secondary rows sum to **5,506 origins / 3,005 unique targets**, matching Not assessed exactly. The secondary breakdown is not added again to the grand total. These are illustrative scan results, not fixed expected counts; future scans can differ. Display rounding may make percentages total slightly above or below 100%.

### XLSX summary

The second worksheet, **Summary**, contains:

- a styled four-row chain table with numeric percentages of all origins, unique targets, and expired subsets;
- a grand total below the primary table and a gray Not assessed breakdown with its own subtotal (including zero-count categories so the layout is stable);
- a doughnut chart of **all origin rows**, including a gray Not assessed segment;
- notes explaining the denominator, unique-target precedence, and certificate-count limitations.

Not assessed rows on the detail worksheet are gray too. CSV remains a single detailed table; no summary rows are mixed into origin records. An output filename of `Summary.csv` uses `Origins` for the first XLSX worksheet to avoid a name collision.

## TLS Status Values

| TlsStatus | Meaning |
| --- | --- |
| `FullChain` | The server sent 3 or more certificates. |
| `ExpiredFullChain` | Full chain was sent, but the leaf certificate is expired. |
| `PartialChain` | The server sent 2 certificates. |
| `ExpiredPartialChain` | Partial chain was sent, but the leaf certificate is expired. |
| `NoChain` | The server sent only 1 certificate. |
| `ExpiredNoChain` | Only 1 certificate was sent and the leaf certificate is expired. |
| `NoCert` | The TLS Certificate message contained no certificates. |
| `Skipped` | TLS probing was skipped with `-SkipTls`. |
| `Disabled` | Origin is disabled. Inventory retained; DNS/TCP/TLS and IP-based security enrichment skipped. |
| `MigratedClassic` | Origin belongs to a migrated Classic profile. Inventory retained; DNS/TCP/TLS and IP-based security enrichment skipped. Takes precedence over Disabled. |
| `MSFT` | Origin host name belongs to a Microsoft-owned Azure PaaS public DNS suffix (see [Azure Private Endpoint DNS](https://learn.microsoft.com/azure/private-link/private-endpoint-dns), "Public DNS zone forwarders" column). Microsoft manages the TLS chain for these endpoints, so DNS resolution, TCP and TLS probing are skipped. |
| `DnsFailure[: <message>]` | DNS resolution failed for the origin hostname. |
| `<code> (<name>)` | TCP connect failed. Example: `10060 (TimedOut)`, `10061 (ConnectionRefused)`, `10054 (ConnectionReset)`, `10065 (HostUnreachable)`. |
| `TlsError: <message>` | TLS or probe setup failed, including handshake timeouts and invalid private-IP tags. |

## Resilience

ARM REST calls (Azure Resource Graph paging, Standard/Premium origin-group and origin enumeration, and Classic Front Door GETs) are routed through an internal `Invoke-ArmRequestWithRetry` wrapper. It retries on:

- HTTP `408`, `429`, `500`, `502`, `503`, `504`
- HTML outage interstitials (the `AzureResourceManager` "Our services aren't available right now" page with `Ref A/B/C` tokens) that some ARM edges return during regional incidents or throttling
- transient DNS, connection reset/closure, and timeout failures while reaching Azure Resource Manager

The wrapper honors the `Retry-After` header (delta-seconds or HTTP-date). Otherwise it uses exponential backoff with ±20% jitter, capped at 30 seconds per wait. Default `MaxAttempts` is 6. Transient failures are logged to the console as `ARM transient failure (status=...) on attempt N/Max; retrying in <ms> ms...` so retry activity is visible during a scan.

## Notes

- There is no input inventory file. The script discovers accessible subscriptions and profiles directly.
- Classic backend pools are normalized into the same row shape as Standard/Premium origin groups.
- Resolved-IP and Application Gateway security columns are populated even when `-SkipTls` is used for eligible unmanaged origins. Disabled and migrated origins are excluded from this enrichment.
- Because the CSV and XLSX contain one row per origin, per-status row counts in those files can be higher than the distinct TLS target counts shown in the console summary.
- TLS 1.2 is forced because the TLS 1.3 certificate message is encrypted and cannot be parsed reliably without key material.
- Connection diagnostics include `TlsStatus` (which carries the raw TCP/TLS error detail on failure), `TcpAttemptedAddresses`, and `TcpConnectedAddress` so TCP and TLS failures can be triaged directly from the export.
- Migration detection follows Microsoft's [migration resource states](https://learn.microsoft.com/azure/frontdoor/tier-migration#resource-states) and the [`properties.resourceState` field](https://learn.microsoft.com/dotnet/api/microsoft.azure.management.frontdoor.models.frontdoormodel.resourcestate). Only `Migrated` suppresses probing; missing state is conservatively scanned.

## Further optimization candidates

- Add separate issuer-linkage/path validation without local intermediate-cache or AIA-download influence. Keep server-sent counts separate from trust evaluation rather than assuming the root must be sent.
- Measure per-phase elapsed times before increasing concurrency; ARM throttling and network timeouts can dominate large scans.
- Consider opt-in scope filters and an opt-in switch to omit Application Gateway security enrichment for chain-only scans. Keep the default full inventory behavior.
- Harden raw TLS parsing for handshake messages fragmented across TLS records, with synthetic protocol fixtures.

## Local regression tests

Run the dependency-free regression script with PowerShell 7:

```powershell
.\Tests\Regression.Tests.ps1
```

Tests load helpers and selected production stages without authenticating to Azure. Azure responses and TLS results are fixtures; DNS-stage checks use only loopback IP literals. Tests cover all-origin percentages, expired subsets, migrated/disabled inventory and probe exclusion, shared-target precedence, DNS reuse, whitespace-normalized tags, fallback isolation, and CSV/optional XLSX output. Saved workbook checks validate the second sheet, summary values, gray formatting, chart ranges/colors, and table styles.

## Troubleshooting

If the script fails early:

- verify `Az.Accounts` is installed
- verify you have signed in with `Connect-AzAccount`
- verify your identity can query Azure Resource Graph and read Front Door profiles in the target subscriptions

If many origins return a TCP error code (for example `10060 (TimedOut)`, `10061 (ConnectionRefused)`) or `TlsError: <message>`:

- confirm the machine running the script can reach the origin network
- verify firewall, NSG, proxy, routing, and DNS behavior
- verify the origin listens on the configured HTTPS port
- verify the SNI hostname expected by the origin matches `OriginHostHeader`
