# Get-MSOLAdmins

Connects to the legacy Microsoft Online service and prints the members of every Azure AD directory role.

## Status

> [!WARNING]
> Legacy example. The `MSOnline` PowerShell module and Azure AD Graph dependency are retired. This script may no longer authenticate or return data in current tenants.

For new automation, migrate the workflow to the Microsoft Graph PowerShell SDK.

## Legacy requirements

- Windows PowerShell 5.1.
- The `MSOnline` module.
- A tenant account allowed to read directory roles and their members.
- Interactive authentication through `Connect-MsolService`.

## Usage

```powershell
Install-Module MSOnline -Scope CurrentUser
./Get-MSOLAdmins.ps1
```

The script displays each role name, member count, and member display names.

## Limitations

- It does not export structured data.
- It prints only display names, which are not unique identifiers.
- It does not distinguish users, groups, and service principals in a reusable result.
- Authentication and API support depend on retired services.

## Recommended replacement

Use Microsoft Graph PowerShell with least-privilege permissions, for example:

```powershell
Connect-MgGraph -Scopes RoleManagement.Read.Directory,Directory.Read.All
Get-MgDirectoryRole | ForEach-Object {
    $role = $_
    Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All |
        Select-Object @{ Name = 'Role'; Expression = { $role.DisplayName } }, Id
}
```

Review and consent to Graph permissions according to your organization's policies.
