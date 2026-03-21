# Get-AFDOriginCertChains

`Get-AFDOriginCertChains.ps1` enumerates origins from a set of Azure Front Door profiles and evaluates the TLS certificate chain each origin presents on port 443.

The script is intended for impact analysis when you need to understand which origins:

- return a full certificate chain
- return only part of the chain
- return only a leaf certificate
- fail DNS, TCP, or TLS negotiation
- present an expired leaf certificate

## What The Script Does

Given a CSV containing Azure subscription and Front Door profile information, the script:

1. Authenticates once with Azure by calling `az account get-access-token`.
2. Uses Azure Resource Graph to resolve each Front Door profile to its resource group.
3. Calls the Azure Management REST API to enumerate origin groups and origins for every profile.
4. Builds a distinct set of TLS test targets using:
   - `HostName` as the connection target
   - `OriginHostHeader` as the SNI value when present
5. Connects to each unique origin on port `443`.
6. Forces a TLS 1.2 handshake and parses the raw TLS Certificate message to count how many certificates the server actually sent.
7. Exports the origin inventory plus a `TlsStatus` column to CSV.

## Why It Exists

Standard certificate-chain APIs can be misleading because Windows may silently use cached intermediates. That makes it hard to tell whether the server actually sent:

- leaf only
- leaf + intermediate
- leaf + intermediate + root

This script avoids that problem by capturing the raw TLS handshake bytes and counting the certificates in the TLS Certificate message itself.

## Prerequisites

- PowerShell 7 or later
- Azure CLI installed and available as `az`
- An active Azure login
- Permissions to read Azure Front Door profile metadata and query Azure Resource Graph
- Network access from the machine running the script to the origin endpoints on TCP `443`

## Input CSV Format

The script expects a CSV with these column names:

- `Subscription Name`
- `Subscription ID`
- `Profile ID(s)`

Example:

```csv
"Subscription Name","Subscription ID","Profile ID(s)"
"Contoso-Prod","11111111-1111-1111-1111-111111111111","afd-prod-01, afd-prod-02"
"Contoso-Test","22222222-2222-2222-2222-222222222222","afd-test-01"
```

`Profile ID(s)` can contain a comma-separated list of Front Door profile names.

## Usage

Basic usage:

```powershell
./Get-AFDOriginCertChains.ps1 -InputCsvPath .\afd-impacted-profiles.csv
```

Write results to a specific file:

```powershell
./Get-AFDOriginCertChains.ps1 -InputCsvPath .\afd-impacted-profiles.csv -OutputCsvPath .\afd-impacted-origins.csv
```

Increase parallel TLS testing:

```powershell
./Get-AFDOriginCertChains.ps1 -InputCsvPath .\afd-impacted-profiles.csv -TlsThrottleLimit 30
```

Increase profile enumeration parallelism:

```powershell
./Get-AFDOriginCertChains.ps1 -InputCsvPath .\afd-impacted-profiles.csv -ThrottleLimit 10
```

Skip TLS testing and only enumerate origins:

```powershell
./Get-AFDOriginCertChains.ps1 -InputCsvPath .\afd-impacted-profiles.csv -SkipTls
```

Use a longer timeout for slow endpoints:

```powershell
./Get-AFDOriginCertChains.ps1 -InputCsvPath .\afd-impacted-profiles.csv -TlsTimeoutMs 10000
```

## Parameters

| Parameter | Required | Default | Description |
| --- | --- | --- | --- |
| `InputCsvPath` | Yes | None | Path to the input CSV containing subscriptions and profile names. |
| `OutputCsvPath` | No | `afd-impacted-origins.csv` | Path to the output CSV. |
| `ThrottleLimit` | No | `5` | Parallelism for enumerating Front Door profiles. |
| `TlsThrottleLimit` | No | `20` | Parallelism for TLS checks. |
| `TlsTimeoutMs` | No | `5000` | Timeout in milliseconds for TCP and TLS operations. |
| `SkipTls` | No | Off | Enumerate origins without performing TLS checks. |

## Output

The output CSV includes one row per Front Door origin and adds a `TlsStatus` column.

Typical columns include:

- `SubscriptionName`
- `SubscriptionId`
- `ProfileName`
- `ResourceGroup`
- `OriginGroupName`
- `OriginName`
- `HostName`
- `OriginHostHeader`
- `EnabledState`
- `HttpPort`
- `HttpsPort`
- `Priority`
- `Weight`
- `CertNameCheck`
- `TlsStatus`

## TLS Status Values

The script classifies each distinct `(HostName, OriginHostHeader)` TLS target using these values:

| TlsStatus | Meaning |
| --- | --- |
| `FullChain` | The server sent 3 or more certificates. |
| `ExpiredFullChain` | Full chain was sent, but the leaf certificate is expired. |
| `PartialChain` | The server sent 2 certificates, usually leaf + intermediate. |
| `ExpiredPartialChain` | Partial chain was sent, but the leaf certificate is expired. |
| `NoChain` | The server sent only 1 certificate, usually the leaf. |
| `ExpiredNoChain` | Only the leaf was sent, and it is expired. |
| `NoCert` | No certificates were observed in the TLS Certificate message. |
| `DnsFailure` | DNS resolution failed for the hostname. |
| `TcpFailure` | TCP connection to port 443 failed, was refused, or timed out before TLS. |
| `TlsError: Timeout` | TCP connected but the TLS handshake timed out. |
| `TlsError: <message>` | TLS handshake failed for another reason. |

## How It Works

### 1. Azure Authentication

The script obtains one Azure bearer token through Azure CLI and reuses it for all management-plane REST calls.

### 2. Resource Group Resolution

Front Door profile names are provided in the CSV, but the REST API paths also require the resource group. The script resolves all profile-to-resource-group mappings in one Azure Resource Graph call instead of repeatedly querying each subscription.

### 3. Origin Enumeration

For each resolved Front Door profile, the script:

1. lists origin groups
2. lists origins under each origin group
3. emits one record per origin

This is done with `Invoke-RestMethod` against the Azure Management API.

### 4. Target Normalization

TLS tests are deduplicated by connection target and SNI target:

- `HostName` is the socket destination
- `OriginHostHeader` is preferred as SNI when present

This matters when the origin is configured as an IP address but expects a hostname during TLS negotiation.

### 5. TLS Inspection

The script:

- opens a TCP connection to port `443`
- performs a TLS 1.2 client handshake
- captures raw bytes from the network stream
- parses the TLS Certificate handshake message
- counts the certificates actually delivered by the server
- inspects the leaf certificate expiry date

TLS 1.2 is forced intentionally because the certificate message is visible in the clear during the handshake. In TLS 1.3, that information is encrypted and cannot be counted with the same approach.

### 6. Export And Summary

Finally, the script writes the full CSV and prints a console summary with:

- profiles scanned
- total origin records
- distinct origin targets
- output path
- TLS status breakdown
- per-profile origin counts
- distinct hostnames discovered

## Notes And Limitations

- The script evaluates what the origin presents directly, not what Azure Front Door caches or rewrites.
- TLS testing is done only on port `443`.
- A successful TLS connection does not imply the backend application is healthy.
- A `PartialChain` result is often acceptable in practice because clients typically already trust the root CA, but it still indicates the server did not send a full chain.
- `TlsError: CertMsgNotFound` can occur if the expected TLS certificate message cannot be parsed.
- Because the script uses `ForEach-Object -Parallel`, Windows PowerShell 5.1 is not sufficient.

## Example Workflow

1. Export or prepare a CSV of impacted Front Door profiles.
2. Log in with Azure CLI.
3. Run the script.
4. Review the output CSV and filter on `TlsStatus` for values such as `NoChain`, `ExpiredNoChain`, `TcpFailure`, or `TlsError: Timeout`.
5. Remediate origin TLS configuration where needed.

## Troubleshooting

If the script fails early:

- verify `az` is installed and you are logged in
- verify the CSV column names match exactly
- verify the profile names in `Profile ID(s)` are correct
- verify your account can query Azure Resource Graph and read Front Door profile configuration

If many origins return `TcpFailure` or `TlsError: Timeout`:

- confirm the machine running the script can reach the origin network
- verify NSG, firewall, proxy, and routing rules
- verify the backend actually listens on `443`
- verify the SNI hostname expected by the origin matches `OriginHostHeader`