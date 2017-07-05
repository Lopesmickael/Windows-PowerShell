# TITTLE       : Set-Office365Licences.ps1
# DESCRIPTION  : This script permits licence assignement by csv input and licence selection
# AUTHOR       : Mickael LOPES
# DATE         : 20170131
# VERSION      : 0.2
# MANDATORY    : Connect Azure AD with ADAL (ADFS | MFA Support)
# http://connect.microsoft.com/site1164/Downloads/DownloadDetails.aspx?DownloadID=59185
# INPUT FORMAT : CSV file
#   Name;Firstname;Login
#   Billy;Anne;abilly
#   Adeline;Carbonnaux;acarbonn
#==================================================================================================== 

$Session = Connect-MSOLService
# Add CSV file (dev version | prod version = param)
$users = import-csv .\PowerBIPro.csv -delimiter ";"
#GET SKU with Get-MsolAccountSku
$SKU = Get-MsolAccountSku | out-gridview -passthru -title "Select one or more licences to assign"
# Start foreach for user 
foreach ($user in $users)
 {
     #Create CHANEL AAD UPN
   $upn=$user.login+"@clasp-infra.com"
   Write-Host -ForegroundColor White "Performing $UPN user"
   $msoluser = $( try {get-msoluser -UserPrincipalName $upn -ErrorAction SilentlyContinue} catch {$null})
   if (!$msoluser)
    {
        Write-host -BackgroundColor RED "Could not find User $UPN in Azure AD"
    }
   if ($msoluser) 
   {
        $usersku = (Get-MsolUser -UserPrincipalName $upn).licenses.AccountSkuId

        if ($usersku -notcontains $sku.AccountSkuId){
        Write-Host -ForegroundColor Green "Adding licence to user $upn"
        $Setlicence = Set-MsolUserLicense -UserPrincipalName $upn -AddLicenses $SKU.AccountSkuId
        }
        if($usersku -contains $sku.AccountSkuId) {Write-Host -ForegroundColor Yellow "User $upn already have the licence"}
   }
 } 