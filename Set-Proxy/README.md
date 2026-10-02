# Set-Proxy

Legacy utility that writes current-user WinINet proxy settings beneath:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
```

## Status

> [!CAUTION]
> The `-Username` and `-Password` path is unsafe: the script stores credentials as plaintext registry values and prints the password to the console. Do not use those parameters.

This script affects WinINet settings for the current user. It does not configure WinHTTP, every service, or every application.

## Parameters

| Parameter | Description |
| --- | --- |
| `Task` | `Enabled` or `Disabled`. Other values make no change. |
| `ProxyFile` | PAC file URL. When set, the script writes `AutoConfigURL`. |
| `IPProxy` | Proxy server and optional port, such as `proxy.example.com:8080`. |
| `Username` | Unsafe legacy plaintext value; do not use. |
| `Password` | Unsafe legacy plaintext value; do not use. |

## Examples

Configure a static proxy:

```powershell
./Set-Proxy.ps1 -Task Enabled -IPProxy proxy.example.com:8080
```

Configure a PAC file:

```powershell
./Set-Proxy.ps1 -Task Enabled -ProxyFile https://proxy.example.com/proxy.pac
```

Disable and remove settings managed by this script:

```powershell
./Set-Proxy.ps1 -Task Disabled
```

## Limitations

- Existing registry properties may cause `New-ItemProperty` to fail because the script does not consistently use `-Force`.
- Static and PAC settings can remain together because enabling one mode does not remove the other.
- Changes may require an Internet Options refresh or application restart.
- There is no input validation, `-WhatIf`, structured output, or reliable nonzero exit status.
- Proxy authentication should use platform-supported credential mechanisms, never custom plaintext registry values.

Modernize this utility before production use by removing credential parameters, adding validated parameter sets, using `Set-ItemProperty`, and notifying WinINet of the configuration change.

