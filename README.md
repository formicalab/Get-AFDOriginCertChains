# Get-AFDOriginCertChains

`Get-AFDOriginCertChains.ps1` scans every Azure Front Door Standard/Premium and Classic profile the current identity can read across all enabled subscriptions, enumerates every origin, and classifies the TLS certificate chain each distinct HTTPS origin endpoint presents.

- Authentication is Az PowerShell-only: use `Az.Accounts` and `Connect-AzAccount`. The script never calls Azure CLI.
- Discovery uses Azure Resource Graph plus ARM REST.
- Each distinct origin target is resolved to IP addresses once, and resolved public IPs are matched back to Azure public IP resources when possible.
- TLS probing deduplicates by `HostName`, `HttpsPort`, and `OriginHostHeader`.
- CSV is always written. If `ImportExcel` is installed, a companion XLSX with the same base name is also written as a filterable table using the current workbook's `Medium2` table style, with the top row frozen, row banding disabled, and host-related text columns preserved as text so literal IP addresses are not coerced into numbers.

## Why Raw TLS Parsing

The script parses the TLS 1.2 Certificate message instead of relying on `X509Chain` alone.

- It counts only the certificates the server actually sent.
- It avoids false positives caused by locally cached intermediates.
- It keeps chain completeness classification consistent across repeated runs.

## Prerequisites

- PowerShell 7 or later.
- `Az.Accounts` PowerShell module.
- Optional: `ImportExcel` if you want XLSX output.
- An active Azure PowerShell login via `Connect-AzAccount`.
- Permissions to list subscriptions, query Azure Resource Graph, and read Front Door profile metadata.
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

The CSV and optional XLSX contain one row per Front Door origin.

Key column groups:

- Inventory: `SubscriptionName`, `SubscriptionId`, `ResourceGroup`, `ProfileName`, `DeploymentModel`, `SkuName`, `OriginGroupName`, `OriginName`
- Origin settings: `HostName`, `OriginHostHeader`, `HttpPort`, `HttpsPort`, `EnabledState`, `Priority`, `Weight`, `CertNameCheck`
- Resolved IPs: `ResolvedAddresses`, `IpKind`, `AzureResourceId` (for example `20.30.40.50`, `AzurePublicIp`, `/subscriptions/.../providers/Microsoft.Network/applicationGateways/agw1`)
- TLS results: `TlsPort`, `TlsStatus`, `ConnectionDetail`, `TcpAttemptedAddresses`, `TcpConnectedAddress`, `PingStatus`, `PingAddress`, `ServerCertificateCount`, `DigiCertIssued`, `LeafSubject`, `LeafIssuer`, `LeafNotAfterUtc`, `IssuerSubject`, `IssuerIssuer`, `IssuerNotAfterUtc`, `RootSubject`, `RootIssuer`, `RootNotAfterUtc`

Console output includes:

- phase-based progress updates for discovery, inventory, and TLS probing
- a TLS status breakdown by origin records, which matches the CSV/XLSX row counts
- a TLS status breakdown by distinct TLS targets, which matches the deduplicated probe count

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
| `TcpTimeout` | TCP connection attempts timed out after bounded retries. |
| `TcpRefused` | The remote host actively refused the TCP connection. |
| `TcpReset` | The remote host reset the TCP connection during setup. |
| `TcpUnreachable` | The host or network was unreachable for the TCP connection. |
| `TcpAborted` | The TCP connection attempt was aborted. |
| `TcpError` | Another TCP failure occurred; inspect `ConnectionDetail`. |
| `TlsError: Timeout` | TCP connected, but the TLS handshake timed out. |
| `TlsError: <message>` | TLS failed for another reason. |
| `Skipped` | TLS probing was skipped with `-SkipTls`. |

## Notes

- There is no input inventory file. The script discovers accessible subscriptions and profiles directly.
- Classic backend pools are normalized into the same row shape as Standard/Premium origin groups.
- `ResolvedAddresses`, `IpKind`, and `AzureResourceId` are populated even when `-SkipTls` is used, so the export still shows the resolved IP kind and any Azure resource association.
- Because the CSV and XLSX contain one row per origin, per-status row counts in those files can be higher than the distinct TLS target counts shown in the console summary.
- TLS 1.2 is forced because the TLS 1.3 certificate message is encrypted and cannot be parsed reliably without key material.
- Connection diagnostics include `ConnectionDetail`, `TcpAttemptedAddresses`, `TcpConnectedAddress`, `PingStatus`, and `PingAddress` so TCP and TLS failures can be triaged directly from the export.

## Troubleshooting

If the script fails early:

- verify `Az.Accounts` is installed
- verify you have signed in with `Connect-AzAccount`
- verify your identity can query Azure Resource Graph and read Front Door profiles in the target subscriptions

If many origins return `TcpTimeout`, `TcpRefused`, `TcpReset`, `TcpUnreachable`, `TcpError`, or `TlsError: Timeout`:

- confirm the machine running the script can reach the origin network
- verify firewall, NSG, proxy, routing, and DNS behavior
- verify the origin listens on the configured HTTPS port
- verify the SNI hostname expected by the origin matches `OriginHostHeader`
