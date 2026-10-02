# Check-AzureCerts

Checks the Windows local-computer certificate stores for a predefined set of root and intermediate certification authorities used by Microsoft Azure and Microsoft 365 services.

## Status

Usable as a point-in-time audit helper. The embedded certificate list is not dynamically synchronized with Microsoft documentation and must be reviewed periodically.

The script is read-only: it reports matching thumbprints and does not install or remove certificates.

## Requirements

- Windows PowerShell.
- Access to `Cert:\LocalMachine`.
- Run from an elevated PowerShell session if local policy restricts reading machine certificate stores.

## Usage

```powershell
./Check-AzureCerts.ps1
```

Installed certificates are printed in green. Missing certificates are printed in yellow.

## How it works

The script:

1. Defines a fixed table of certificate names and SHA-1 thumbprints.
2. Recursively searches `Cert:\LocalMachine`.
3. Reports whether each thumbprint is present.

## Limitations

- Presence does not prove that a certificate is valid, unexpired, trusted, or correctly chained.
- The search does not report which certificate store contained the match.
- SHA-1 thumbprints are identifiers here, not a signature-security choice.
- Some entries share display names but represent different issuing certificates.
- Microsoft may update its CA inventory after this repository is published.

Always compare the embedded list with the current [Azure CA details](https://learn.microsoft.com/azure/security/fundamentals/azure-ca-details) before using the result for compliance.

## Related tool

Use [Install-AzureNewCerts](../Install-AzureNewCerts/) only after reviewing its security implications and testing it outside production.
