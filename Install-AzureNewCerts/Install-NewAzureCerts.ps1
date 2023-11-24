    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ONLINE','OFFLINE')]
        [string]$Type,
        
        [Parameter(Mandatory)]
        [string]$Path
    )

    function Install-Cert {
        $files = Get-ChildItem $Path
        Foreach ($file in $files){
            $filepath = $file.FullName
            if ($filepath -match "ROOT"){
                try {
                    Import-Certificate -FilePath $filepath -CertStoreLocation 'Cert:\LocalMachine\Root'
                    Write-Host "INFO : "$file.name"is installed in ROOT folder"
                }
                catch {
                    Write-Host "ERROR : "$file.name"is not installed in ROOT folder"
                }

            }else{
                try {
                    Import-Certificate -FilePath $filepath -CertStoreLocation 'Cert:\LocalMachine\CA'
                    Write-Host "INFO : "$file.name"is installed in Intermediate folder"  
                }
                catch {
                    Write-Host "ERROR : "$file.name"is not installed in Intermediate folder"
                }

            }
        }
    }

    $Certificate_Table = @(

@{Certname = "DigiCert Global Root G2"; Link = "https://cacerts.digicert.com/DigiCertGlobalRootG2.crt"},
@{Certname = "Microsoft RSA Root Certificate Authority 2017"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20RSA%20Root%20Certificate%20Authority%202017.crt"},
@{Certname = "Microsoft ECC Root Certificate Authority 2017"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20ECC%20Root%20Certificate%20Authority%202017.crt"},
@{Certname = "Microsoft Azure TLS Issuing CA 01"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20TLS%20Issuing%20CA%2001%20-%20xsign.crt"},
@{Certname = "Microsoft Azure TLS Issuing CA 02"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20TLS%20Issuing%20CA%2002%20-%20xsign.crt"},
@{Certname = "Microsoft Azure TLS Issuing CA 05"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20TLS%20Issuing%20CA%2005%20-%20xsign.crt"},
@{Certname = "Microsoft Azure TLS Issuing CA 06"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20TLS%20Issuing%20CA%2006%20-%20xsign.crt"}
)

$CertTable = $Certificate_Table
    
    if ($Type -eq "Online") {
        Write-Host "INFO : You selected Online mode, certificates will be downloaded in the folder you specified"
        Write-Host "INFO : $Path will be used to download certificates"

        Push-Location $Path

        Foreach ($Line in $CertTable){
            $certurl = $line.Link
            $certname = $line.Certname
            Write-Host "INFO : Downloading $certname"
        try {
            Invoke-WebRequest -Uri $certurl -OutFile ./$certname.crt
        }
        catch {
            Write-Host "ERROR : Error on download certificate, check Internet connexion, proxy, or go in Offline mode"
        }
        }
        Install-Cert

    } else {
        Write-Host "INFO : You selected offline mode, we will use the selected path"
        Write-Host "INFO : $Path will be used as source for certificates"
        Install-Cert
    }