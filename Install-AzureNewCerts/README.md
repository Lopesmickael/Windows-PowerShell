# Install-AzureNewCerts

Downloads or processes a predefined set of Azure-related CA certificates and imports eligible certificates into the local computer `Root` or `CA` store.

## Status

> [!CAUTION]
> Experimental and security-sensitive. Installing a root CA changes the machine trust boundary. Review every source, certificate thumbprint, subject, issuer, and validity period before use. Test in a disposable environment first.

The script is intended as an educational example and should not be deployed broadly without independent security review.

## Requirements

- Windows PowerShell.
- An elevated Administrator session.
- An existing local directory supplied through `-Path`.
- Internet access in `ONLINE` mode.
- TLS 1.2 access to DigiCert, Entrust, Microsoft PKI, and `crt.sh` download endpoints.

## Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `Mode` | Yes | `ONLINE` downloads the predefined files first. `OFFLINE` processes existing `.crt` files. |
| `Path` | Yes | Existing directory used as the download destination or offline certificate source. |

Parameter values are case-insensitive in PowerShell.

## Usage

Online mode:

```powershell
./Install-NewAzureCerts.ps1 -Mode ONLINE -Path C:\Temp\AzureCertificates
```

Offline mode:

```powershell
./Install-NewAzureCerts.ps1 -Mode OFFLINE -Path C:\Temp\AzureCertificates
```

## Behavior

For each `.crt` file, the script:

1. Loads PEM or DER certificate data.
2. Skips expired certificates.
3. Calls `.Verify()` to validate the certificate chain.
4. Classifies self-signed CAs as `Root` and subordinate CAs as `CA`.
5. Skips a certificate when the same thumbprint already exists and is not expired.
6. Imports with `Import-Certificate`, or uses an `X509Store` fallback.

Downloaded files remain in the supplied directory.

## Important limitations

- `.Verify()` builds a chain against the machine's current trust configuration. A legitimate new root or intermediate may fail verification specifically because it is not trusted yet, causing the script to skip it.
- The script trusts a hard-coded URL list but does not pin expected certificate thumbprints.
- A successful HTTPS download does not independently prove that the downloaded file is the expected CA certificate.
- Existing expired certificates are not removed.
- The predefined CA inventory can become outdated.
- Online mode can leave a partial download set when individual endpoints fail.
- The script changes the current location with `Push-Location` and does not restore it.

For enterprise deployment, prefer a reviewed certificate-management process such as Group Policy, Microsoft Intune, configuration management, or a signed deployment package with pinned certificate identities.

## Reference

- [Azure TLS certificate changes](https://learn.microsoft.com/azure/security/fundamentals/tls-certificate-changes)
- [Azure CA details](https://learn.microsoft.com/azure/security/fundamentals/azure-ca-details)
