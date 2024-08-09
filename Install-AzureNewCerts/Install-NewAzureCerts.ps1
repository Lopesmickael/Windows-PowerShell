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

@{Certname = "Baltimore CyberTrust Root"; Link = "https://cacerts.digicert.com/BaltimoreCyberTrustRoot.crt"},
@{Certname = "DigiCert Global Root CA"; Link = "https://cacerts.digicert.com/DigiCertGlobalRootCA.crt"},
@{Certname = "DigiCert Global Root G2"; Link = "https://cacerts.digicert.com/DigiCertGlobalRootG2.crt"},
@{Certname = "DigiCert Global Root G3"; Link = "https://cacerts.digicert.com/DigiCertGlobalRootG3.crt"},
@{Certname = "Entrust Root Certification Authority G2"; Link = "https://web.entrust.com/root-certificates/entrust_g2_ca.cer"},
@{Certname = "Microsoft ECC Root Certificate Authority 2017"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20ECC%20Root%20Certificate%20Authority%202017.crt"},
@{Certname = "Microsoft RSA Root Certificate Authority 2017"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20RSA%20Root%20Certificate%20Authority%202017.crt"},
@{Certname = "DigiCert Basic RSA CN CA G2"; Link = "https://crt.sh/?d=2545289014"},
@{Certname = "DigiCert Cloud Services CA-1"; Link = "https://crt.sh/?d=12624881"},
@{Certname = "DigiCert Cloud Services CA-1"; Link = "https://crt.sh/?d=B3F6B64A07BB9611F47174407841F564FB991F29"},
@{Certname = "DigiCert SHA2 Secure Server CA"; Link = "https://crt.sh/?d=3422153451"},
@{Certname = "DigiCert TLS Hybrid ECC SHA384 2020 CA1"; Link = "https://crt.sh/?d=3422153452"},
@{Certname = "DigiCert TLS RSA SHA256 2020 CA1"; Link = "https://crt.sh/?d=4385364571"},
@{Certname = "DigiCert TLS RSA SHA256 2020 CA1"; Link = "https://crt.sh/?d=6938FD4D98BAB03FAADB97B34396831E3780AEA1"},
@{Certname = "Entrust Certification Authority - L1K"; Link = "https://aia.entrust.net/l1k-chain256.cer"},
@{Certname = "Entrust Certification Authority - L1M"; Link = "https://aia.entrust.net/l1m-chain256.cer"},
@{Certname = "GeoTrust Global TLS RSA4096 SHA256 2022 CA1"; Link = "https://crt.sh/?d=6670931375"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 03"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2003%20-%20xsign.crt"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 03"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2003.crt"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 04"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2004%20-%20xsign.crt"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 04"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2004.crt"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 07"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2007%20-%20xsign.crt"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 07"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2007.crt"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 08"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2008%20-%20xsign.crt"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 08"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2008.crt"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 03"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2003%20-%20xsign.crt"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 03"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2003.crt"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 04"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2004%20-%20xsign.crt"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 04"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2004.crt"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 07"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2007%20-%20xsign.crt"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 07"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2007.crt"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 08"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2008%20-%20xsign.crt"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 08"; Link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2008.crt"},
@{Certname = "Microsoft ECC TLS Issuing AOC CA 01"; Link = "https://crt.sh/?d=4789656467"},
@{Certname = "Microsoft ECC TLS Issuing AOC CA 02"; Link = "https://crt.sh/?d=4814787086"},
@{Certname = "Microsoft ECC TLS Issuing EOC CA 01"; Link = "https://crt.sh/?d=4814787088"},
@{Certname = "Microsoft ECC TLS Issuing EOC CA 02"; Link = "https://crt.sh/?d=4814787085"},
@{Certname = "Microsoft RSA TLS CA 01"; Link = "https://crt.sh/?d=3124375355"},
@{Certname = "Microsoft RSA TLS CA 02"; Link = "https://crt.sh/?d=3124375356"},
@{Certname = "Microsoft RSA TLS Issuing AOC CA 01"; Link = "https://crt.sh/?d=4789678141"},
@{Certname = "Microsoft RSA TLS Issuing AOC CA 02"; Link = "https://crt.sh/?d=4814787092"},
@{Certname = "Microsoft RSA TLS Issuing EOC CA 01"; Link = "https://crt.sh/?d=4814787098"},
@{Certname = "Microsoft RSA TLS Issuing EOC CA 02"; Link = "https://crt.sh/?d=4814787087"}
)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072;
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