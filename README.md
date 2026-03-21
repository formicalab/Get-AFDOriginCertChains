# Get-AFDOriginCertChains

`Get-AFDOriginCertChains.ps1` enumerates origins from a set of Azure Front Door profiles and evaluates the TLS certificate chain each origin presents on port 443. It classifies each origin as full chain, partial chain, leaf only, no certificate, expired, or connection failure — useful for impact analysis when you need to identify origins with incomplete or broken certificate chains.

## Prerequisites

- PowerShell 7 or later
- `Az.Accounts` PowerShell module installed
- An active Azure PowerShell login via `Connect-AzAccount`
- Permissions to read Azure Front Door profile metadata and query Azure Resource Graph
- Network access from the machine running the script to the origin endpoints on TCP `443`

Install the required module if needed:

```powershell
Install-Module Az.Accounts -Scope CurrentUser
```

Sign in before running the script:

```powershell
Connect-AzAccount
```

## Input CSV Format

Start from [input-template.csv](input-template.csv), edit it with your real subscription and profile values, and pass the file to `-InputCsvPath`.

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

```powershell
# Basic — uses default output path and parallelism
./Get-AFDOriginCertChains.ps1 -InputCsvPath .\input-template.csv

# Custom output path
./Get-AFDOriginCertChains.ps1 -InputCsvPath .\input-template.csv -OutputCsvPath .\results.csv

# Higher parallelism for large environments
./Get-AFDOriginCertChains.ps1 -InputCsvPath .\input-template.csv -ThrottleLimit 20 -TlsThrottleLimit 60

# Enumerate origins only (skip TLS testing)
./Get-AFDOriginCertChains.ps1 -InputCsvPath .\input-template.csv -SkipTls

# Longer timeout for slow endpoints
./Get-AFDOriginCertChains.ps1 -InputCsvPath .\input-template.csv -TlsTimeoutMs 10000
```

## Parameters

| Parameter | Required | Default | Description |
| --- | --- | --- | --- |
| `InputCsvPath` | Yes | None | Path to the input CSV containing subscriptions and profile names. |
| `OutputCsvPath` | No | `afd-impacted-origins.csv` | Path to the output CSV. |
| `ThrottleLimit` | No | `10` | Parallelism for ARM origin-group and origin enumeration. |
| `TlsThrottleLimit` | No | `40` | Parallelism for TLS checks. |
| `TlsTimeoutMs` | No | `5000` | Timeout in milliseconds for TCP and TLS operations. |
| `SkipTls` | No | Off | Enumerate origins without performing TLS checks. |

## Output

The output CSV includes one row per Front Door origin with columns for subscription, profile, resource group, origin group, origin name, hostname, host header, enabled state, ports, priority, weight, certificate name check, and `TlsStatus`.

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

1. **Authentication** — acquires one bearer token via `Az.Accounts` and reuses it for all ARM calls.
2. **Resource Group resolution** — a single Azure Resource Graph query maps every profile name to its resource group.
3. **Origin enumeration** — lists origin groups then origins (parallelised with `ForEach-Object -Parallel`) via the ARM REST API.
4. **Target normalisation** — deduplicates TLS targets by `(HostName, OriginHostHeader)`. When `HostName` is an IP, `OriginHostHeader` is used as SNI.
5. **TLS inspection** — connects on port 443, forces TLS 1.2, captures raw handshake bytes, and parses the Certificate message to count server-sent certs. TLS 1.2 is forced because in TLS 1.3 the Certificate message is encrypted.
6. **Export** — writes the CSV and prints a console summary (profile counts, TLS breakdown, execution time).

## Notes

- Evaluates what the origin presents directly, not what Azure Front Door caches or rewrites.
- TLS testing is port `443` only.
- `PartialChain` is often acceptable — clients usually trust the root CA already — but it means the server did not send a full chain.
- `TlsError: CertMsgNotFound` can occur when the TLS Certificate message cannot be parsed.
- Requires PowerShell 7+ (`ForEach-Object -Parallel`); Windows PowerShell 5.1 is not supported.

## Troubleshooting

If the script fails early:

- verify `Az.Accounts` is installed
- verify you have signed in with `Connect-AzAccount`
- verify the CSV column names match exactly
- verify the profile names in `Profile ID(s)` are correct
- verify your account can query Azure Resource Graph and read Front Door profile configuration

If many origins return `TcpFailure` or `TlsError: Timeout`:

- confirm the machine running the script can reach the origin network
- verify NSG, firewall, proxy, and routing rules
- verify the backend actually listens on `443`
- verify the SNI hostname expected by the origin matches `OriginHostHeader`