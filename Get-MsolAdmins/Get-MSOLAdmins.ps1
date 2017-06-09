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
$AzureAD = Connect-MsolService

$roles = Get-MsolRole 
foreach ($role in $roles){
    $users = Get-MsolRoleMember -RoleObjectId $role.ObjectId
    Write-host "Role :"$role.Name "| Member count:" $users.count -backgroundcolor "red" -foregroundcolor "white"
    if ($users -eq $null) {Write-host "No users in this group"}
    else {
        $users.DisplayName
    }
}
