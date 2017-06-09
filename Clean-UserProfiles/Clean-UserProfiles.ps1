# =======================================================
# NAME: Clean-UserProfiles.ps1
# AUTHOR: LOPES Mickaël 
# Website: http://lopes.im
# DATE: 19/1/2016
# VERSION: 1.0
# COMMENTS: Clean user profiles on computer with filter
#
# /!\ Execute with Administrator's rights !
# =======================================================

<#
 .EXAMPLE
     [ps] c:\users> Clean-sessions -savedprofiles "mlopes","Administrateur"

WARNING : Username are case sensitive ! Please be carefull ! 

Example : Administrator =/= administrator 
  #>              

PARAM (
[parameter()] 
[String[]] $savedprofiles
)

<#
You need to change the users path. By default, the users path is C:\Users\ 
#>

$ProfilePath = "C:\Users\"

###### BODY ######

foreach ($savedprofile in $savedprofiles) {

$excludeprofiles = $excludeprofiles + $ProfilePath + $savedprofile

}

#$profile = Get-CimInstance -ClassName Win32_UserProfile  -Filter "Special = '$false'" | where {(!($excludeprofiles.Contains($_.localpath)))}

#Remove-CimInstance -InputObject $profile  

Write-Output "You removed User profiles :" $Profile.LocalPath
