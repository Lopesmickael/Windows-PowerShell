Param(
[Parameter]
[switch]$All,
[string]$Filter
)
<#
.SYNOPSIS
	Script: Force-LAPSPasswordRenew.ps1
.DESCRIPTION
    This script permits to reset ms-Mcs-AdmPwdExpirationTime attributes in AD to force LAPS CSE to create new password.
.EXAMPLE
    C:\PS> Force-LAPSPasswordRenew.ps1 [-All] [-Target]
.NOTES
    Author: M LOPES (https://lopes.im)
    Date:   2017-06-1
	Version:0.1
#>

If ($All -eq $false) {
    Write-Error "ERROR : Please follow Force-LAPSPasswordRenew.ps1 documentation"
    break
}

if ($All -like $True) {
    Write-output "INFO : This script will force local administrator password reset"
    $AllComputers = Get-ADComputer -filter * -properties ms-Mcs-AdmPwdExpirationTime
    $FilterComputers = ($AllComputers | ? {$_.DistinguishedName -like "*ou=$Filter*"}).name
    foreach ($FilterComputer in $FilterComputers) {
        Set-ADComputer -Identity $FilterComputer -Clear ms-Mcs-AdmPwdExpirationTime
        Write-Output "INFO : AdmPwdExpirationTime for $FilterComputer have been reset"
    }
}