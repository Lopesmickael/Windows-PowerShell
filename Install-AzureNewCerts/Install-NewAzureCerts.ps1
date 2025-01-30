<#
    .SYNOPSIS
    This script demonstrates how to manage and install certificates in a Windows environment. It supports both online and offline modes for certificate handling.

    .DESCRIPTION
    The script can download certificates from a predefined list of URLs (in online mode) or process pre-provided certificates from a local folder (offline mode). It validates the certificates for expiration and signature before installing them into the appropriate certificate store (Root or CA).

    .PARAMETER Mode
    Specifies the operation mode of the script: ONLINE or OFFLINE.

    .PARAMETER Path
    Specifies the path to the folder where certificates are stored (OFFLINE) or will be downloaded (ONLINE).

    .NOTES
    This script is provided for educational and example purposes only. It is not intended for use in production environments. Users must test and adapt the script to their specific needs and ensure compliance with their organization's security policies.
    Version:        1.2
    Author:         Mickaël Lopes - Mathieu Emering
    Company:        Microsoft
    Creation Date:  Nov 24, 2023
    Last Update:    Jan 27, 2025
    Purpose/Change: 
    11/24/2023 [M.L]: 1.0 - Initial script development
    01/24/2025 [M.E]: 1.1 - Rewrite Install-Certificate function and add QoL improvments
    01/27/2025 [M.E]: 1.2 - Improved output formatting for certificate processing.
    01/27/2025 [M.E]: 1.2 - Add a validation process over the Mode provided.

    .EXAMPLE
    # Run the script in online mode:
    Install-NewAzureCerts.ps1 -Type ONLINE -Path "C:\CertFolder"

    # Run the script in offline mode:
    Install-NewAzureCerts.ps1 -Type OFFLINE -Path "C:\CertFolder"

    .LINK
    https://github.com/Lopesmickael/Windows-PowerShell/tree/master/Install-AzureNewCerts
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$mode,
        [Parameter(Mandatory)]
        [string]$path
    )
    
    if ($mode -notin @('ONLINE', 'OFFLINE')) {
        Write-Host "`n [" -ForegroundColor DarkCyan -NoNewline
        Write-Host "ERROR" -ForegroundColor Red -NoNewline
        Write-Host "] " -ForegroundColor DarkCyan -NoNewline
        Write-Host 'Parameter "Mode" must be "' -ForegroundColor Red -NoNewline
        Write-Host "ONLINE" -ForegroundColor Green -NoNewline
        Write-Host '" or "' -ForegroundColor Red -NoNewline
        Write-Host 'OFFLINE' -ForegroundColor Green -NoNewline
        Write-Host '"' -ForegroundColor Red -NoNewline
        Write-Host "`n [" -ForegroundColor DarkCyan -NoNewline
        Write-Host "ERROR" -ForegroundColor Red -NoNewline
        Write-Host "] " -ForegroundColor DarkCyan -NoNewline
        Write-Host "The script will now exit.`n" -ForegroundColor Red
        #Write-host "No .crt files found in the folder: $folderpath" -ForegroundColor Red
        exit
    }
    
    function Install-Certificate {
        param (
            [Parameter(Mandatory = $true)]
            [string]$folderpath  # Path to the folder containing CRT files
        )
        if (-Not (Test-Path -Path $folderpath)) {
            throw "The specified folder does not exist: $folderpath"
        }
        # Get all .crt files in the folder
        $crtfiles = Get-ChildItem -Path $folderpath -Filter "*.crt"
        Write-Host " [" -ForegroundColor DarkCyan -NoNewline
        Write-Host "INFO" -ForegroundColor Magenta -NoNewline
        Write-Host "] " -ForegroundColor DarkCyan -NoNewline
        if ($crtfiles.Count -eq 0) {
            Write-Host $crtfiles.Count -ForegroundColor Red -NoNewline
            Write-Host " *.CRT files found in the folder: " -ForegroundColor Magenta -NoNewline
            Write-Host $folderpath -ForegroundColor Green
            Write-Host "`n [" -ForegroundColor DarkCyan -NoNewline
            Write-Host "ERROR" -ForegroundColor Red -NoNewline
            Write-Host "] " -ForegroundColor DarkCyan -NoNewline
            Write-Host "No .crt files found, please check your directory path, or try running the script in " -ForegroundColor Red -NoNewline
            Write-Host "Online mode " -ForegroundColor Green
            Write-Host "`n [" -ForegroundColor DarkCyan -NoNewline
            Write-Host "ERROR" -ForegroundColor Red -NoNewline
            Write-Host "] " -ForegroundColor DarkCyan -NoNewline
            Write-Host "The script will now exit.`n" -ForegroundColor Red
            #Write-host "No .crt files found in the folder: $folderpath" -ForegroundColor Red
            exit
        }
        else {
            Write-Host $crtfiles.Count -ForegroundColor DarkGreen -NoNewline
            Write-Host " *.CRT files found in the folder: " -ForegroundColor Magenta -NoNewline
            Write-Host "$folderpath `n`n" -ForegroundColor Green
        }    
        # Initialize counters for certificate processing status tracking (imported, failed, skipped)
        $certimported = 0
        $certfailed = 0
        $certskipped = 0
        #Write-host "Found $($crtfiles.Count) .crt file(s) in the folder: $folderpath"
        $importcommandcvailable = Get-Command -Name Import-Certificate -ErrorAction SilentlyContinue
        if (-not $importcommandcvailable) {
            Write-Host " [" -ForegroundColor DarkCyan -NoNewline
            Write-Host "WARNING" -ForegroundColor Yellow -NoNewline
            Write-Host "] " -ForegroundColor DarkCyan -NoNewline
            Write-Host "Import-Certificate command not available. Using fallback method.`n`n" -ForegroundColor Yellow
        }
        $alllocalcerts = $crtfiles.Count
        $certsprocessed = 1
        # Define fixed-width format for aligned output
        $format = "{0,-12} {1,-6} {2,-50} {3,-7} {4,-7} {5,-7} {6,-6} {7,-25} {8,-18} {9,-10}"
        # Print header
        Write-Host ($format -f "Time", "Index", "Certificate", "Format", "Expired", "Signed", "Store", "Location", "Exist", "Status") -ForegroundColor Cyan
        Write-Host ("-" * 160) # Separator line
        $certaligned = New-Object PSObject -Property @{
            Time        = ""
            Index       = ""
            Certificate = ""
            Format      = ""
            Expired     = ""
            Signed      = ""
            Store       = ""
            Location    = ""
            Exist       = ""
            Status      = ""
        }
        foreach ($crtFile in $crtfiles) {
            $certaligned.Time = "$(get-date -Format T)"
            $certaligned.Index = "$certsprocessed/$alllocalcerts"
            $certaligned.Certificate = $crtFile.Name
            try {
                # Attempt to load the certificate
                $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                if ($PSVersionTable.PSVersion.Major -lt 5) {
                    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                }
                else {
                    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
                }
                $certcontent = Get-Content -Path $crtFile.FullName -Raw
                # Detect format (PEM or DER)
                if ($certcontent -match "-----BEGIN CERTIFICATE-----") {
                    # PEM format
                    $certaligned.Format = "PEM"
                    $certificate.Import([Text.Encoding]::ASCII.GetBytes($certcontent))
                }
                else {
                    # Assume the certificate is in DER format
                    $certaligned.Format = "DER"
                    $certificate.Import($crtFile.FullName)
                }
                # Validate if the certificate is expired
                if ($certificate.NotAfter -lt (Get-Date)) {
                    $certaligned.Expired = "YES --- SKIPPED"
                    $certskipped++
                    #Write-Warning "The certificate has expired: $($certificate.Subject)"
                    $certsprocessed++
                    continue
                }
                else {
                    $certaligned.Expired = "NO"
                }
                # Verify the certificate's signature
                if (-not $certificate.Verify()) {
                    $certaligned.Signed = "NO --- SKIPPED"
                    $certskipped++
                    #Write-Warning "The certificate failed signature verification: $($certificate.Subject)"
                    continue
                }
                else {
                    $certaligned.Signed = "YES"
                }
                # Determine the certificate's properties
                $isca = $certificate.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] } | ForEach-Object { $_.CertificateAuthority }
                $isselfsigned = $certificate.Subject -eq $certificate.Issuer
                $isroot = $isselfsigned -and $isca
                # Determine the target store based on the certificate properties
                if ($isroot) {
                    $targetstore = "Root"
                    $certaligned.Store = "Root"
                }
                elseif ($isca) {
                    $targetstore = "CA"
                    $certaligned.Store = "CA"
                }
                else {
                    $certaligned.Store = "Unknown --- SKIPPED"
                    $certskipped++
                    #Write-Host "Error processing the certificate file $($crtFile.FullName)"-ForegroundColor Red -NoNewline
                    continue
                }
                $storepath = "Cert:\LocalMachine\$targetstore"
                #Write-Output "Checking if the certificate is already in the $targetstore store ($storepath)..."
                $importcertificate = $false
                $certaligned.Location = $storepath
                $existingcert = Get-ChildItem -Path $storepath -Recurse | Where-Object { $_.Thumbprint -eq $certificate.Thumbprint } -ErrorAction SilentlyContinue
                if ($existingcert) {
                    if ($existingcert.NotAfter -lt (Get-Date)) {
                        $certaligned.Exist = "YES (Expired)"
                        #Write-Output "The existing certificate in the $targetstore store has expired (Thumbprint: $($existingcert.Thumbprint))."
                        $importcertificate = $true
                    }
                    else {
                        $certaligned.Exist = "YES (Not Expired)"
                        $certaligned.Status = "SKIPPED"
                        # DEBUG::Remove this certificate from the store
                        <# $thumbprint = $existingcert.Thumbprint
                        $store = Get-ChildItem -Path $storepath
                        $certificatetoremove = $store | Where-Object { $_.Thumbprint -eq $thumbprint }
                        if ($certificatetoremove) {
                            Remove-Item -Path $certificatetoremove.PSPath
                            $certaligned.Status = "REMOVED"
                        } #>
                        $certskipped++
                        #Write-Output "The certificate is already installed in the $targetstore store."
                    }
                }
                else {
                    $certaligned.Exist = "NO"
                    $importcertificate = $true
                }
                # Check if the Import-Certificate command is available
                # Fallback method for PowerShell 4 is used if Import-Certificate is not available
                if ($importcertificate) {
                    #Write-Output "Importing the certificate into the $targetstore store..."
                    if ($importcommandcvailable) {
                        try {
                            Import-Certificate -FilePath $crtFile.FullName -CertStoreLocation $storepath -ErrorAction Stop | Out-Null
                            $certaligned.Status = "IMPORTED"
                            $certimported++
                            #Write-Output "The certificate has been successfully installed in the $targetstore store."
                        }
                        catch {
                            $certaligned.Status = "FAILED"
                            $certfailed++
                            #Write-Error "Failed to import certificate using Import-Certificate: $_"
                        }
                    }
                    else {
                        # Fallback method for PowerShell 4
                        try {
                            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($targetstore, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                            $store.Add($certificate) | Out-Null
                            # DEBUG::Remove this certificate from the store
                            #$store.Remove($certificate) | Out-Null
                            $store.Close()
                            $certaligned.Status = "IMPORTED"
                            $certimported++
                            #Write-Output "The certificate has been successfully installed in the $targetstore store."
                        }
                        catch {
                            $certaligned.Status = "FAILED"
                            $certfailed++
                            #Write-Error "Failed to open or add the certificate to the store: $_"
                        }
                    }
                }
            }
            catch {
                # Log the error and continue processing the next certificate
                $certaligned.Status = "ERROR"
                #Write-Error "Error processing the certificate file $($crtFile.FullName): $_"
                $certsprocessed++
                $certfailed++
                continue
            }
            Write-Host ($format -f $certaligned.Time, $certaligned.Index, $certaligned.Certificate, $certaligned.Format, $certaligned.Expired, $certaligned.Signed, $certaligned.Store, $certaligned.Location, $certaligned.Exist, $certaligned.Status)
            $certsprocessed++
        }
    
        Write-Host "`n`n`t [" -ForegroundColor DarkCyan -NoNewline
        Write-Host "Processed" -ForegroundColor Magenta -NoNewline
        Write-Host "]" -ForegroundColor DarkCyan -NoNewline
        Write-Host $alllocalcerts -ForegroundColor Green -NoNewline
        Write-Host " [" -ForegroundColor DarkCyan -NoNewline
        Write-Host "Imported" -ForegroundColor Magenta -NoNewline
        Write-Host "]" -ForegroundColor DarkCyan -NoNewline
        Write-Host $certimported -ForegroundColor Green -NoNewline
        Write-Host " [" -ForegroundColor DarkCyan -NoNewline
        Write-Host "Failed" -ForegroundColor Magenta -NoNewline
        Write-Host "]" -ForegroundColor DarkCyan -NoNewline
        Write-Host $certfailed -ForegroundColor Red -NoNewline
        Write-Host " [" -ForegroundColor DarkCyan -NoNewline
        Write-Host "Skipped" -ForegroundColor Magenta -NoNewline
        Write-Host "]" -ForegroundColor DarkCyan -NoNewline
        Write-Host $certskipped -ForegroundColor Yellow
        Write-Host "`n`t Importation task completed.`n`n" -ForegroundColor DarkCyan
    }
    # Check if the script is running as Administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "This script requires Administrator privileges."
        Write-Warning "This script cannot continue without elevated privileges. Exiting..."
        exit
    }
    # This table contains the list of certificates to be downloaded or processed, with their names and download links.
    $certificate_table = @(
        @{ certname = "Baltimore CyberTrust Root"; link = "https://cacerts.digicert.com/BaltimoreCyberTrustRoot.crt" },
        @{ certname = "DigiCert Basic RSA CN CA G2"; link = "https://crt.sh/?d=2545289014" },
        @{ certname = "DigiCert Cloud Services CA-1"; link = "https://crt.sh/?d=3439320284" },
        @{ certname = "DigiCert Global Root CA"; link = "https://cacerts.digicert.com/DigiCertGlobalRootCA.crt" },
        @{ certname = "DigiCert Global Root G2"; link = "https://cacerts.digicert.com/DigiCertGlobalRootG2.crt" },
        @{ certname = "DigiCert Global Root G3"; link = "https://cacerts.digicert.com/DigiCertGlobalRootG3.crt" },
        @{ certname = "DigiCert SHA2 Secure Server CA"; link = "https://crt.sh/?d=3422153451" },
        @{ certname = "DigiCert TLS Hybrid ECC SHA384 2020 CA1"; link = "https://crt.sh/?d=3422153452" },
        @{ certname = "DigiCert TLS RSA SHA256 2020 CA1"; link = "https://crt.sh/?d=4385364571" },
        @{ certname = "Entrust Certification Authority - L1K"; link = "https://files.entrust.com/root-certificates/entrust_l1k.cer" },
        @{ certname = "Entrust Certification Authority - L1M"; link = "https://files.entrust.com/root-certificates/entrust_l1m_sha2.cer" },
        @{ certname = "Entrust Root Certification Authority G2"; link = "https://web.entrust.com/root-certificates/entrust_g2_ca.cer" },
        @{ certname = "GeoTrust Global TLS RSA4096 SHA256 2022 CA1"; link = "https://crt.sh/?d=6670931375" },
        @{ certname = "Microsoft Azure ECC TLS Issuing CA 03"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2003.crt" },
        @{ certname = "Microsoft Azure ECC TLS Issuing CA 03 - xsign"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2003%20-%20xsign.crt" },
        @{ certname = "Microsoft Azure ECC TLS Issuing CA 04"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2004.crt" },
        @{ certname = "Microsoft Azure ECC TLS Issuing CA 04 - xsign"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2004%20-%20xsign.crt" },
        @{ certname = "Microsoft Azure ECC TLS Issuing CA 07"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2007.crt" },
        @{ certname = "Microsoft Azure ECC TLS Issuing CA 07 - xsign"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2007%20-%20xsign.crt" },
        @{ certname = "Microsoft Azure ECC TLS Issuing CA 08"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2008.crt" },
        @{ certname = "Microsoft Azure ECC TLS Issuing CA 08 - xsign"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2008%20-%20xsign.crt" },
        @{ certname = "Microsoft Azure RSA TLS Issuing CA 03"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2003.crt" },
        @{ certname = "Microsoft Azure RSA TLS Issuing CA 03 - xsign"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2003%20-%20xsign.crt" },
        @{ certname = "Microsoft Azure RSA TLS Issuing CA 04"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2004.crt" },
        @{ certname = "Microsoft Azure RSA TLS Issuing CA 04 - xsign"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2004%20-%20xsign.crt" },
        @{ certname = "Microsoft Azure RSA TLS Issuing CA 07"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2007.crt" },
        @{ certname = "Microsoft Azure RSA TLS Issuing CA 07 - xsign"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2007%20-%20xsign.crt" },
        @{ certname = "Microsoft Azure RSA TLS Issuing CA 08"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2008.crt" },
        @{ certname = "Microsoft Azure RSA TLS Issuing CA 08 - xsign"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2008%20-%20xsign.crt" },
        @{ certname = "Microsoft ECC Root Certificate Authority 2017"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20ECC%20Root%20Certificate%20Authority%202017.crt" },
        @{ certname = "Microsoft ECC TLS Issuing AOC CA 01"; link = "https://crt.sh/?d=4789656467" },
        @{ certname = "Microsoft ECC TLS Issuing AOC CA 02"; link = "https://crt.sh/?d=4814787086" },
        @{ certname = "Microsoft ECC TLS Issuing EOC CA 01"; link = "https://crt.sh/?d=4814787088" },
        @{ certname = "Microsoft ECC TLS Issuing EOC CA 02"; link = "https://crt.sh/?d=4814787085" },
        @{ certname = "Microsoft RSA Root Certificate Authority 2017"; link = "https://www.microsoft.com/pkiops/certs/Microsoft%20RSA%20Root%20Certificate%20Authority%202017.crt" },
        @{ certname = "Microsoft RSA TLS CA 01"; link = "https://crt.sh/?d=3124375355" },
        @{ certname = "Microsoft RSA TLS CA 02"; link = "https://crt.sh/?d=3124375356" },
        @{ certname = "Microsoft RSA TLS Issuing AOC CA 01"; link = "https://crt.sh/?d=4789678141" },
        @{ certname = "Microsoft RSA TLS Issuing AOC CA 02"; link = "https://crt.sh/?d=4814787092" },
        @{ certname = "Microsoft RSA TLS Issuing EOC CA 01"; link = "https://crt.sh/?d=4814787098" },
        @{ certname = "Microsoft RSA TLS Issuing EOC CA 02"; link = "https://crt.sh/?d=4814787087" }
    )
    # .NET Framework 4.5
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072;
    # .NET Framework 4.5.2 and later versions
    #[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolMode]::Tls12;
    
    Write-Host "`n`t ================================================================================" -ForegroundColor Yellow
    Write-Host "`t        DISCLAIMER: This script is provided for educational purposes only." -ForegroundColor Yellow
    Write-Host "`t   Do NOT use this script in a production environment without thorough testing." -ForegroundColor Yellow
    Write-Host "`t ================================================================================`n`n" -ForegroundColor Yellow
    
    # Check if the destination path exists
    if (-not (Test-path -Path $path)) {
        Write-Host " [" -ForegroundColor DarkCyan -NoNewline
        Write-Host "ERROR" -ForegroundColor Red -NoNewline
        Write-Host "] " -ForegroundColor DarkCyan -NoNewline
        Write-Host " The specified path does not exist: " -ForegroundColor Red -NoNewline
        Write-Host $path -ForegroundColor Green
        Write-Host "`n [" -ForegroundColor DarkCyan -NoNewline
        Write-Host "ERROR" -ForegroundColor Red -NoNewline
        Write-Host "] " -ForegroundColor DarkCyan -NoNewline
        Write-Host " The script will now exit.`n" -ForegroundColor Red
        exit
    }
    # Check the operation mode (Online or Offline)
    if ($mode -eq "Online") {
        Write-Host " [" -ForegroundColor DarkCyan -NoNewline
        Write-Host "INFO" -ForegroundColor Magenta -NoNewline
        Write-Host "] " -ForegroundColor DarkCyan -NoNewline
        Write-Host "Online mode " -ForegroundColor Green -NoNewline
        Write-Host "Certificates" -ForegroundColor Magenta -NoNewline
        Write-Host " WILL BE " -ForegroundColor Red -NoNewline
        Write-Host "downloaded" -ForegroundColor Magenta
        #Write-Host "INFO : You selected Online mode, certificates will be downloaded in the folder you specified"
        Write-Host " [" -ForegroundColor DarkCyan -NoNewline
        Write-Host "INFO" -ForegroundColor Magenta -NoNewline
        Write-Host "] " -ForegroundColor DarkCyan -NoNewline
        Write-Host $path -ForegroundColor Green -NoNewline
        Write-Host " will be used to download certificates`n" -ForegroundColor Magenta
        # Download the certificates from the URLs and save them to the specified folder
        Push-Location $path
        # Define the certificate table containing the list of certificates to be downloaded or processed
        $certtable = $certificate_table
        $allcertificates = $certtable.Count
        $certsdownload = 1
        $downloadfailed = $true
        Foreach ($line in $certtable) {
            $certurl = $line.link
            $certname = $line.certname
            Write-Host " [" -ForegroundColor DarkCyan -NoNewline
            Write-Host "INFO" -ForegroundColor Magenta -NoNewline
            Write-Host "] " -ForegroundColor DarkCyan -NoNewline
            Write-Host $certsdownload -ForegroundColor Green -NoNewline
            Write-Host "/" -ForegroundColor DarkCyan -NoNewline
            Write-Host $allcertificates -ForegroundColor DarkCyan -NoNewline
            Write-Host " Downloading " -ForegroundColor Magenta -NoNewline
            Write-Host ($certname) -ForegroundColor Yellow -NoNewline
            try {
                Invoke-WebRequest -Uri $certurl -OutFile ./$certname.crt -ErrorAction Stop | Write-Progress -Activity "Downloading file" -Status "Progress"
                Write-Host " OK" -ForegroundColor Green
                $downloadfailed = $false
                $certsdownload++
            }
            catch {
                Write-Host " [" -ForegroundColor Magenta -NoNewline
                Write-Host "ERROR" -ForegroundColor Red -NoNewline
                Write-Host "] " -ForegroundColor Magenta -NoNewline
                Write-Host "Downloading " -ForegroundColor Magenta -NoNewline
                Write-Host ($certname) -ForegroundColor Yellow -NoNewline
                Write-Host " from " -ForegroundColor Magenta -NoNewline
                Write-Host ($certurl).ToUpper() -ForegroundColor Yellow
                Write-Host " [" -ForegroundColor Magenta -NoNewline
                Write-Host "ERROR" -ForegroundColor Red -NoNewline
                Write-Host "] " -ForegroundColor Magenta -NoNewline
                Write-Host  $_.Exception.Message -ForegroundColor Red
                $certsdownload++
            }
        }
        Write-Host "`n"
        if ($downloadfailed) {
            Write-Host "`n`n [" -ForegroundColor DarkCyan -NoNewline
            Write-Host "ERROR" -ForegroundColor Red -NoNewline
            Write-Host "] " -ForegroundColor DarkCyan -NoNewline
            Write-Host "All downloads failed." -ForegroundColor Red
            Write-Host " [" -ForegroundColor DarkCyan -NoNewline
            Write-Host "ERROR" -ForegroundColor Red -NoNewline
            Write-Host "] " -ForegroundColor DarkCyan -NoNewline
            Write-Host "Please check your Internet connection, proxy settings, or try running the script in " -ForegroundColor Red -NoNewline
            Write-Host "Offline mode " -ForegroundColor Green
            Write-Host "`n [" -ForegroundColor DarkCyan -NoNewline
            Write-Host "ERROR" -ForegroundColor Red -NoNewline
            Write-Host "] " -ForegroundColor DarkCyan -NoNewline
            Write-Host "The script will now exit.`n" -ForegroundColor Red
            exit
        }
        Install-Certificate -folderpath $path
    
    }
    else {
        Write-Host " [" -ForegroundColor DarkCyan -NoNewline
        Write-Host "INFO" -ForegroundColor Magenta -NoNewline
        Write-Host "] " -ForegroundColor DarkCyan -NoNewline
        Write-Host "Offline mode " -ForegroundColor Green -NoNewline
        Write-Host "Certificates will NOT be downloaded" -ForegroundColor Red
        #Write-Host "INFO : You selected offline mode, we will use the selected path"
        Write-Host " [" -ForegroundColor DarkCyan -NoNewline
        Write-Host "INFO" -ForegroundColor Magenta -NoNewline
        Write-Host "] " -ForegroundColor DarkCyan -NoNewline
        Write-Host $path -ForegroundColor Green -NoNewline
        Write-Host " will be used as source for certificates" -ForegroundColor Magenta
        #Write-Host "INFO : $path will be used as source for certificates"
        Install-Certificate -folderpath $path
    }