# Set-AzureWebApp-AlwaysOn

Enables or disables the App Service `AlwaysOn` setting for a web app or deployment slot.

## Status

> [!WARNING]
> Legacy example. The script uses the retired `AzureRM` PowerShell module (`Get-AzureRmResource` and `Set-AzureRmResource`). It should be migrated to the supported `Az` module before use.

## Legacy requirements

- Windows PowerShell.
- The `AzureRM.Resources` module.
- An authenticated AzureRM session.
- Permission to read and update the target App Service resource.

## Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `ResourceGroupName` | Yes | Resource group containing the web app. |
| `WebAppName` | Yes | Name of the App Service web app. |
| `AlwaysOn` | Yes | `$true` to enable or `$false` to disable. |
| `Slot` | No | Deployment slot name. |

## Legacy usage

Web app:

```powershell
./Set-AzureWebApp-AlwaysOn.ps1 `
    -ResourceGroupName rg-app `
    -WebAppName contoso-api `
    -AlwaysOn $true
```

Deployment slot:

```powershell
./Set-AzureWebApp-AlwaysOn.ps1 `
    -ResourceGroupName rg-app `
    -WebAppName contoso-api `
    -Slot staging `
    -AlwaysOn $false
```

## Limitations

- AzureRM is retired and should not be installed alongside `Az` in the same Windows PowerShell session.
- The script updates the generic resource property object instead of using the App Service-specific Az cmdlets.
- Error handling writes a message and uses `break`, making automation failures difficult to detect reliably.
- The SKU check reads `Properties.sku`, which may not represent the App Service plan tier.
- The script rejects Basic tier, although current Always On availability must be checked against current App Service documentation.
- There is no `SupportsShouldProcess` or `-WhatIf`.

## Recommended migration

Use `Get-AzWebApp` and `Set-AzWebApp`, or the current App Service ARM API, then validate the feature against the associated App Service plan.
