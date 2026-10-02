# Force-LAPSPasswordRenew

Clears the legacy Microsoft LAPS `ms-Mcs-AdmPwdExpirationTime` attribute for computer objects whose distinguished name contains a selected OU name. The legacy LAPS client-side extension generates a new local administrator password at its next policy processing cycle.

## Status

Legacy Microsoft LAPS only. This script does not target the newer Windows LAPS attributes introduced in supported Windows releases.

> [!CAUTION]
> The script can update many Active Directory computer objects. Test the filter first and use delegated permissions limited to the intended OU.

## Requirements

- Windows PowerShell.
- The Active Directory module (`RSAT-AD-PowerShell`).
- Network access to Active Directory.
- Permission to clear `ms-Mcs-AdmPwdExpirationTime` on matching computer objects.
- Legacy Microsoft LAPS deployed and configured on those computers.

## Parameters

| Parameter | Required in practice | Description |
| --- | --- | --- |
| `All` | Yes | The script exits unless this switch is provided. |
| `Filter` | Yes | Text matched against `*ou=<Filter>*` in each computer distinguished name. |

## Usage

Force renewal for computers beneath an OU named `Workstations`:

```powershell
./Force-LAPSPasswordRenew.ps1 -All -Filter Workstations
```

## Behavior and timing

The script clears the expiration attribute; it does not directly create a password or contact each endpoint. Password rotation occurs when the LAPS client processes policy.

## Limitations

- `Get-ADComputer -Filter *` loads every computer in the directory before applying the OU text match locally.
- The OU match is a simple wildcard string, not a validated search base, and can select more objects than expected.
- There is no `-WhatIf`, confirmation, batching, or structured output.
- The parameter name `-All` does not change scope; it acts as a safety acknowledgment.
- Windows LAPS uses different attributes and management cmdlets.

Before modernization, replace the text filter with an explicit `-SearchBase`, add `SupportsShouldProcess`, and support Windows LAPS separately.
