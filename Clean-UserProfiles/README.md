# Clean-UserProfiles

Prototype intended to remove non-special Windows user profiles while preserving an explicit list of profile folder names.

## Status

> [!WARNING]
> Incomplete and currently non-functional. The profile query and deletion statements are commented out, and the final output references an undefined `$Profile` variable. Running the script does not remove profiles.

Do not rely on this script for cleanup automation in its current state.

## Intended parameters

| Parameter | Description |
| --- | --- |
| `savedprofiles` | Profile folder names beneath `C:\Users` that should be preserved. Matching is case-sensitive in the original implementation. |

Intended example:

```powershell
./Clean-UserProfiles.ps1 -savedprofiles Administrator,mlopes
```

## Intended requirements

- Windows PowerShell.
- Administrator privileges.
- CIM access to `Win32_UserProfile`.

## Design risks to address

- Never remove a loaded profile.
- Exclude special/system profiles and service accounts.
- Compare normalized paths case-insensitively.
- Support `ShouldProcess`, `-WhatIf`, and per-profile confirmation.
- Validate that preservation entries resolve beneath the expected profile root.
- Return structured results and explicit errors.
- Avoid relying only on folder names; use `Win32_UserProfile` metadata and SIDs.

The deletion logic should remain disabled until these safeguards and tests are implemented.

