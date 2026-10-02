# Windows PowerShell Scripts

A collection of PowerShell utilities for Azure auditing, Windows administration, certificates, Active Directory, and legacy deployment automation.

> [!IMPORTANT]
> These scripts span several years and are not all production-ready. Review each project README before running a script. Test changes in a non-production environment and use an account with only the permissions required for the task.

## Script catalog

| Project | Purpose | Current status |
| --- | --- | --- |
| [Get-AzrObjectsLinks](./Get-AzrObjectsLinks/) | Build an interactive Azure resource dependency map | Current; PowerShell 7.2 and Az modules |
| [Check-AzureCerts](./Check-AzureCerts/) | Check whether selected Azure-related CAs exist in the local computer stores | Usable audit script; certificate list requires periodic review |
| [Install-AzureNewCerts](./Install-AzureNewCerts/) | Download or import selected Azure-related CA certificates | Experimental; elevated and security-sensitive |
| [Force-LAPSPasswordRenew](./Force-LAPSPasswordRenew/) | Clear legacy Microsoft LAPS password-expiration attributes in an OU | Legacy; not Windows LAPS |
| [Get-MsolAdmins](./Get-MsolAdmins/) | Display members of legacy Azure AD directory roles | Legacy/retired dependency; migrate to Microsoft Graph |
| [Set-AzureWebApp-AlwaysOn](./Set-AzureWebApp-AlwaysOn/) | Change App Service Always On through AzureRM | Legacy/retired dependency; migrate to Az |
| [Set-NTP](./Set-NTP/) | Configure Windows Time on a workgroup computer or domain PDC emulator | Legacy; test before use |
| [Set-Proxy](./Set-Proxy/) | Configure current-user WinINet proxy registry values | Legacy; credential parameters are unsafe |
| [Clean-UserProfiles](./Clean-UserProfiles/) | Prototype for deleting non-excluded Windows profiles | Incomplete; currently performs no deletion |

## General requirements

- Windows PowerShell 5.1 unless a project states otherwise.
- Administrator elevation for machine certificate, profile, and Windows Time changes.
- Project-specific modules such as `Az`, `ActiveDirectory`, or legacy modules.
- A review of the script source and its documented limitations before execution.

## Repository conventions

Each project README documents:

- Current support status.
- Prerequisites and permissions.
- Parameters and examples.
- Side effects and security considerations.
- Known limitations and recommended modernization work.

## Contributing

Issues and pull requests are welcome. When changing a script, update its README and add tests where practical. Avoid committing credentials, tenant information, subscription IDs, or generated reports containing environment details.
