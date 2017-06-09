## Set-Proxy.ps1
## Create, Modify or Delete Proxy Configuration
## Written by Mickaël LOPES
###############################################

<#
 .EXAMPLE
	[ps] c:\users> Set-Proxy.ps1 -Task Enabled -IPProxy 1.1.1.1:8080
	[ps] c:\users> Set-Proxy.ps1 -Task Enabled -IPProxy 1.1.1.1:8080 -Username mlopes -Password mlopes
	[ps] c:\users> Set-Proxy.ps1 -Task Enabled -ProxyFile http://PRDPAC/prd.pac
	[ps] c:\users> Set-Proxy.ps1 -Task Disabled
#>

Param(
  [string]$Task,
  [string]$ProxyFile,
  [string]$IPProxy,
  [string]$Username,
  [string]$Password
)

$Registry = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"


If ($Task -eq "Enabled")
{
    if([string]::IsNullOrEmpty($ProxyFile))
    {
        $REG = Set-ItemProperty -path $Registry ProxyEnable -value 1
        $REG = New-ItemProperty -path $Registry ProxyServer -PropertyType String -value $IPProxy
    }
    else
    {
        $REG = New-ItemProperty -Path $Registry -Name AutoConfigURL -PropertyType String -Value $ProxyFile
    }
    if (($Username) -and ($Password))
    {
        $REG = New-ItemProperty -path $Registry ProxyUser -PropertyType String -value $Username
        $REG = New-ItemProperty -path $Registry ProxyPass -PropertyType String -value $Password
    }
}

If ($Task -eq "Disabled")
{
    Remove-ItemProperty -path $Registry -name AutoConfigURL -ErrorAction SilentlyContinue
    Set-ItemProperty -path $Registry ProxyEnable -value 0
    Remove-ItemProperty -path $Registry -name ProxyServer -ErrorAction SilentlyContinue
    Remove-ItemProperty -path $Registry -name ProxyUser -ErrorAction SilentlyContinue
    Remove-ItemProperty -path $Registry -name ProxyPass -ErrorAction SilentlyContinue
}

$AutoConfURL = Get-ItemProperty -path $Registry AutoConfigURL -ErrorAction SilentlyContinue

$ProxyServer = Get-ItemProperty -path $Registry ProxyServer -ErrorAction SilentlyContinue

$ProxyUser = Get-ItemProperty -path $Registry ProxyUser -ErrorAction SilentlyContinue

$ProxyPwd = Get-ItemProperty -path $Registry ProxyPass -ErrorAction SilentlyContinue

If (($AutoConfURL -eq $NULL) -and ($ProxyServer -eq $NULL))
{Write-Host "No Proxy Server configuration" `n}

If (($AutoConfURL -notlike $NULL) -or ($ProxyServer -notlike $NULL))
{Write-Host `n "Proxy Server configuration is :"$proxyServer.ProxyServer$AutoConfURL.AutoConfigURL,$ProxyUser.ProxyUser,$ProxyPwd.ProxyPass `n} 