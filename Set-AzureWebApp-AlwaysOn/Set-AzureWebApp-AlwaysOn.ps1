Param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    [Parameter(Mandatory=$true)]
    [string]$WebAppName,
    [Parameter(Mandatory=$true)]
    [bool]$AlwaysOn,
    [string]$Slot
)

<#
.SYNOPSIS
	Script: Set-AzureWebApp-AlwaysOn.ps1
.DESCRIPTION
    This script permits to enable or disable AlwaysOn on a WebApp during deployement. Script compatible with Slot.
.EXAMPLE
    C:\PS> Set-AzureWebApp-AlwaysOn.ps1 [-ResourceGroupName] [-WepAppName] [-AlwaysOn] [-Slot]
.NOTES
    Author: M LOPES
    Date:   2017-06-09
	Version:0.1
#>

Write-Output "INFO : Preparing AlwaysOn value for WebApp $WebAppName to $AlwaysOn"
$WebAppPropertiesObject = @{"siteConfig" = @{"AlwaysOn" = $AlwaysOn}}

If ($Slot -like $null)
{
    Write-Output "INFO : No slot param"
    $WebAppResourceType = 'microsoft.web/sites'
    try {$webAppResource = Get-AzureRmResource -ResourceType $WebAppResourceType -ResourceGroupName $ResourceGroupName -ResourceName $WebAppName}
        catch {Write-Output "ERROR : ResourceNotFound : Resource $WebAppName under resource group $ResourceGroupName was not found "
        break    
        }
}else{
    Write-Output "INFO : Slot param selected $Slot"
    $WebAppResourceType = 'microsoft.web/sites/slots'
    $RessourceName = "$WebAppName/$slot"
    try {$webAppResource = Get-AzureRmResource -ResourceType $WebAppResourceType -ResourceGroupName $ResourceGroupName -ResourceName $RessourceName}
    catch {Write-Output "ERROR : ResourceNotFound : Resource $RessourceName under resource group $ResourceGroupName was not found "
        break    
        }
}

if (($webAppResource.Properties.sku -eq "Basic") -or ($webAppResource.Properties.sku -eq "Free")) {
    Write-Output "ERROR : WebApp plan tier is not compatible with AlwaysOn. Since Standard tier"
}else{
    Write-Output "INFO : Setting WebApp $WebAppName AlwaysOn param to $AlwaysOn"
    $WebAppSetting = $webAppResource | Set-AzureRmResource -PropertyObject $WebAppPropertiesObject -Force
}
