# Get-AFDOriginCertChains

`Get-AFDOriginCertChains.ps1` scans every Azure Front Door Standard/Premium and Classic profile the current identity can read across all enabled subscriptions, enumerates all origin groups and origins, and evaluates the TLS certificate chain each distinct origin endpoint presents.

The script is PowerShell 7-only. It uses Azure Resource Graph for broad discovery, ARM REST for fast origin inventory, and raw TLS 1.2 certificate-message parsing for certificate-chain classification.

When the optional `ImportExcel` PowerShell module is installed, the script also writes a companion `.xlsx` workbook alongside the CSV.

## Why This TLS Approach

The repository now keeps the raw TLS parser from `Get-AFDOriginCertChains.ps1` instead of the `X509Chain`-only approach used in `..\Check-AFDOriginCertsPG\Check-AfdOriginCertsPG.ps1`.

- Raw TLS parsing is more accurate for chain completeness because it counts only the certificates the server actually sent.
- `X509Chain` can reuse intermediates already cached on the machine and make a leaf-only server appear to have returned a fuller chain than it really did.
- ARM REST plus a single access token is also faster for large scans than enumerating profiles and origins through Az.Cdn cmdlets.

The script now also includes a `DigiCertIssued` output column based on the leaf certificate issuer.

## What It Scans

- Every enabled Azure subscription visible to the current identity.
- Every Azure Front Door Standard/Premium profile (`Microsoft.Cdn/profiles` with `Standard_AzureFrontDoor` or `Premium_AzureFrontDoor` SKU).
- Every Azure Front Door Classic profile (`Microsoft.Network/frontDoors`).
- Every origin group under those profiles.
- Every origin under those origin groups.

## Prerequisites

- PowerShell 7 or later.
- `Az.Accounts` PowerShell module.
- Optional: `ImportExcel` PowerShell module if you want the script to emit a companion XLSX workbook.
- An active Azure PowerShell login via `Connect-AzAccount`.
- Permissions to list subscriptions, query Azure Resource Graph, and read Azure Front Door profile metadata.
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
# Basic scan across all accessible subscriptions
# If ImportExcel is installed, a companion XLSX is also generated.
./Get-AFDOriginCertChains.ps1

# Custom output path
./Get-AFDOriginCertChains.ps1 -OutputCsvPath .\results.csv

# Higher parallelism for large estates
./Get-AFDOriginCertChains.ps1 -ThrottleLimit 32 -TlsThrottleLimit 128

# Enumerate origins only
./Get-AFDOriginCertChains.ps1 -SkipTls

# Longer timeout for slow origins
./Get-AFDOriginCertChains.ps1 -TlsTimeoutMs 10000
```

## Parameters

| Parameter | Required | Default | Description |
| --- | --- | --- | --- |
| `OutputCsvPath` | No | `afd-impacted-origins-<timestamp>.csv` | Optional path to the output CSV. If ImportExcel is installed, the script also writes an XLSX with the same base name. |
| `ThrottleLimit` | No | Dynamic | Parallelism for ARM origin-group and origin enumeration. |
| `TlsThrottleLimit` | No | Dynamic | Parallelism for TLS checks. |
| `TlsTimeoutMs` | No | `5000` | Timeout in milliseconds for TCP and TLS operations. |
| `SkipTls` | No | Off | Enumerate origins without performing TLS checks. |

The dynamic throttle defaults are derived from processor count and tuned separately for inventory and TLS probing.

## Output

The script always writes a CSV containing one row per Front Door origin.

If `ImportExcel` is installed, the script also writes a companion XLSX workbook with the same data in a formatted Excel table.

Both outputs include:

- Subscription and profile metadata.
- Deployment model metadata (`Standard/Premium` or `Classic`).
- Origin group and origin names.
- Origin host settings (`HostName`, `OriginHostHeader`, `HttpPort`, `HttpsPort`).
- Load-balancing metadata (`Priority`, `Weight`, `EnabledState`).
- Certificate name check setting.
- TLS probe details:
  - `TlsPort`
  - `TlsStatus`
  - `ServerCertificateCount`
  - `DigiCertIssued`
  - `LeafSubject`
  - `LeafIssuer`
  - `LeafNotAfterUtc`

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
| `DnsFailure` | DNS resolution failed for the origin hostname. |
| `TcpFailure` | TCP connection to the configured HTTPS port failed, was refused, or timed out. |
| `TlsError: Timeout` | TCP connected, but the TLS handshake timed out. |
| `TlsError: <message>` | TLS failed for another reason. |
| `Skipped` | TLS probing was skipped with `-SkipTls`. |

## Progress Output

The script prints phase-based progress and periodic completion updates during:

- profile discovery
- origin-group inventory
- origin inventory
- TLS probing

This keeps long-running scans readable without writing a line for every single origin.

## Notes

- The script intentionally scans all accessible subscriptions. There is no input CSV anymore.
- Classic backend pools are normalized into origin groups so Standard/Premium and Classic rows share the same CSV shape.
- TLS targets are deduplicated by `HostName`, `HttpsPort`, and `OriginHostHeader` so repeated origins are only probed once.
- TLS probing uses the configured HTTPS port and prefers `OriginHostHeader` as SNI when present.
- TLS 1.2 is forced because the TLS Certificate message is encrypted in TLS 1.3 and cannot be parsed reliably without key material.
- The default CSV filename includes a timestamp so repeated runs do not overwrite each other unless you pass `-OutputCsvPath`.
- If ImportExcel is installed, the default XLSX filename uses the same base name as the CSV.

## Troubleshooting

If the script fails early:

- verify `Az.Accounts` is installed
- verify you have signed in with `Connect-AzAccount`
- verify your identity can query Azure Resource Graph and read Front Door profiles in the target subscriptions

If many origins return `TcpFailure` or `TlsError: Timeout`:

- confirm the machine running the script can reach the origin network
- verify firewall, NSG, proxy, routing, and DNS behavior
- verify the origin listens on the configured HTTPS port
- verify the SNI hostname expected by the origin matches `OriginHostHeader`
