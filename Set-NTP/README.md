# Set-NTP

Legacy Windows Time configuration utility. It tests candidate NTP servers, configures reachable peers with `w32tm`, restarts `W32Time`, waits 20 seconds, checks the active source, and triggers rediscovery.

## Status

Legacy administrative script. Test on the target Windows version and domain topology before use.

## Requirements

- Windows PowerShell running as Administrator.
- The Windows Time service and `w32tm`.
- Network access to the selected NTP servers, normally UDP port 123.
- On a domain member, the Active Directory module and execution on the domain PDC emulator.

## Parameter

| Parameter | Required | Description |
| --- | --- | --- |
| `URL` | Yes | One or more NTP hostnames or IP addresses. |

## Usage

```powershell
./Set-NTP.ps1 -URL time.windows.com,0.pool.ntp.org,1.pool.ntp.org
```

On a workgroup computer, the script configures the local machine. On a domain member, it refuses to continue unless the machine is the PDC emulator.

## Side effects

- Reconfigures Windows Time to use a manual peer list.
- Restarts the `W32Time` service.
- Forces time rediscovery and resynchronization.
- Pauses for 20 seconds during validation.

## Limitations

- Peer flags such as `,0x8` are not added automatically.
- Connectivity detection parses localized `w32tm` text and may fail on non-English systems.
- The final source comparison uses a wildcard comparison against an array and may not validate multiple peers correctly.
- It does not check command exit codes or return structured results.
- Domain time hierarchy design is environment-specific; configuring only the PDC may not be sufficient documentation for the overall topology.

Use Group Policy or centrally managed Windows Time configuration for repeatable enterprise deployment.

