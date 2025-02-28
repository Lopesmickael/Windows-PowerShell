<#
.SYNOPSIS
    Script: Get-MSOLAdmins
.DESCRIPTION
    This script permit to get MSOLAdmins to audit quickly rights in Azure AD
.EXAMPLE
    C:\PS> Get-MSOLAdmins
.NOTES
    Author: M LOPES
    Date:   2017-06-06
    Version:0.1
#>
#Loggin to AzureAD
Write-Output "INFO : Connecting to AzureAD..."

try {
    $AzureAD = Connect-MsolService
    Write-Output "INFO : Connected to AzureAD successfully."
} catch {
    Write-Error "ERROR : Failed to connect to AzureAD"
    exit 1
}

try {
    $roles = Get-MsolRole
    foreach ($role in $roles) {
        try {
            $users = Get-MsolRoleMember -RoleObjectId $role.ObjectId
            Write-Host "Role :" $role.Name "| Member count:" $users.count -BackgroundColor "red" -ForegroundColor "white"
            if ($users -eq $null) {
                Write-Host "No users in this group"
            } else {
                $users.DisplayName
            }
        } catch {
            Write-Error "ERROR : Failed to get members for role $($role.Name). $_"
        }
    }
} catch {
    Write-Error "ERROR : Failed to retrieve roles."
}