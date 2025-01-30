<#
    .SYNOPSIS
    This script demonstrates how to check certificates used by Azure in a Windows environment

    .DESCRIPTION
    The script will look for certificates installed on the computer using thumprint.
    .NOTES
    This script is provided for educational and example purposes only. It is not intended for use in production environments. Users must test and adapt the script to their specific needs and ensure compliance with their organization's security policies.
    Version:        1.1
    Author:         Mickaël Lopes
    Company:        Microsoft
    Creation Date:  Nov 24, 2023
    Last Update:    Jan 30, 2025
    Purpose/Change: 
    11/24/2023 [M.L]: 1.0 - Initial script development
    01/30/2025 [M.L]: 1.1 - Rewrite check and update certificate thumprint

    .EXAMPLE
    ./Check-AzureCerts.ps1 

    .LINK
    https://github.com/Lopesmickael/Windows-PowerShell/blob/master/Check-AzureCerts/Check-AzureCerts.ps1
    #>
# Certificate Table

$Certificate_Table = @(

@{Certname = "Baltimore CyberTrust Root"; Certtb = "D4DE20D05E66FC53FE1A50882C78DB2852CAE474"},
@{Certname = "DigiCert Global Root CA"; Certtb = "A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436"},
@{Certname = "DigiCert Global Root G2"; Certtb = "df3c24f9bfd666761b268073fe06d1cc8d4f82a4"},
@{Certname = "DigiCert Global Root G3"; Certtb = "7E04DE896A3E666D00E687D33FFAD93BE83D349E"},
@{Certname = "Entrust Root Certification Authority G2"; Certtb = "8cf427fd790c3ad166068de81e57efbb932272d4"},
@{Certname = "Microsoft RSA Root Certificate Authority 2017"; Certtb = "73a5e64a3bff8316ff0edccc618a906e4eae4d74"},
@{Certname = "Microsoft ECC Root Certificate Authority 2017"; Certtb = "999a64c37ff47d9fab95f14769891460eec4c3c5"},
@{Certname = "DigiCert Basic RSA CN CA G2"; Certtb = "4D1FA5D1FB1AC3917C08E43F65015E6AEA571179"},
@{Certname = "DigiCert Cloud Services CA-1"; Certtb = "81B68D6CD2F221F8F534E677523BB236BBA1DC56"},
@{Certname = "DigiCert SHA2 Secure Server CA"; Certtb = "626D44E704D1CEABE3BF0D53397464AC8080142C"},
@{Certname = "DigiCert TLS Hybrid ECC SHA384 2020 CA1"; Certtb = "51E39A8BDB08878C52D6186588A0FA266A69CF28"},
@{Certname = "DigiCert TLS RSA SHA256 2020 CA1"; Certtb = "1C58A3A8518E8759BF075B76B750D4F2DF264FCD"},
@{Certname = "DigiCert TLS RSA SHA256 2020 CA1"; Certtb = "6938fd4d98bab03faadb97b34396831e3780aea1"},
@{Certname = "Entrust Certification Authority - L1K"; Certtb = "f21c12f46cdb6b2e16f09f9419cdff328437b2d7"},
@{Certname = "Entrust Certification Authority - L1M"; Certtb = "cc136695639065fab47074d28c55314c66077e90"},
@{Certname = "GeoTrust Global TLS RSA4096 SHA256 2022 CA1"; Certtb = "7E6DB7B7584D8CF2003E0931E6CFC41A3A62D3DF"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 03"; Certtb = "56D955C849887874AA1767810366D90ADF6C8536"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 03"; Certtb = "91503BE7BF74E2A10AA078B48B71C3477175FEC3"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 04"; Certtb = "FB73FDC24F06998E070A06B6AFC78FDF2A155B25"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 04"; Certtb = "406E3B38EFF35A727F276FE993590B70F8224AED"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 07"; Certtb = "3BE6CA5856E3B9709056DA51F32CBC8970A83E28"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 07"; Certtb = "AB3490B7E37B3A8A1E715036522AB42652C3CFFE"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 08"; Certtb = "716DF84638AC8E6EEBE64416C8DD38C2A25F6630"},
@{Certname = "Microsoft Azure ECC TLS Issuing CA 08"; Certtb = "CF33D5A1C2F0355B207FCE940026E6C1580067FD"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 03"; Certtb = "F9388EA2C9B7D632B66A2B0B406DF1D37D3901F6"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 03"; Certtb = "37461AACFA5970F7F2D2BAC5A659B53B72541C68"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 04"; Certtb = "BE68D0ADAA2345B48E507320B695D386080E5B25"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 04"; Certtb = "7304022CA8A9FF7E3E0C1242E0110E643822C45E"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 07"; Certtb = "3382517058A0C20228D598EE7501B61256A76442"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 07"; Certtb = "0E5F41B697DAADD808BF55AD080350A2A5DFCA93"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 08"; Certtb = "31600991ED5FEC63D355A5484A6DCC787EAD89BC"},
@{Certname = "Microsoft Azure RSA TLS Issuing CA 08"; Certtb = "512C8F3FB71EDACF7ADA490402E710B10C73026E"},
@{Certname = "Microsoft ECC TLS Issuing AOC CA 01"; Certtb = "30ab5c33eb4b77d4cbff00a11ee0a7507d9dd316"},
@{Certname = "Microsoft ECC TLS Issuing AOC CA 02"; Certtb = "3709cd92105d074349d00ea8327f7d5303d729c8"},
@{Certname = "Microsoft ECC TLS Issuing EOC CA 01"; Certtb = "5fa13b879b2ad1b12e69d476e6cad90d01013b46"},
@{Certname = "Microsoft ECC TLS Issuing EOC CA 02"; Certtb = "58a1d8b1056571d32be6a7c77ed27f73081d6e7a"},
@{Certname = "Microsoft RSA TLS Issuing AOC CA 01"; Certtb = "4697fdbed95739b457b347056f8f16a975baf8ee"},
@{Certname = "Microsoft RSA TLS Issuing AOC CA 02"; Certtb = "90ed2e9cb40d0cb49a20651033086b1ea2f76e0e"},
@{Certname = "Microsoft RSA TLS Issuing EOC CA 01"; Certtb = "a04d3750debfccf1259d553dbec33162c6b42737"},
@{Certname = "Microsoft RSA TLS Issuing EOC CA 02"; Certtb = "697c6404399cc4e7bb3c0d4a8328b71dd3205563"}
)

$CertTable = $Certificate_Table

######################################################################
# Check certificate installed

Write-Host "Starting Certificate check"

Foreach ($Line in $CertTable){
    
    $cert = Get-ChildItem -Path Cert:\LocalMachine\ -Recurse | Where-Object {$_.Thumbprint -eq $Line.Certtb} -ErrorAction SilentlyContinue
    if ($null -eq $cert) {
        Write-Host -ForegroundColor Yellow $Line.Certname"is not installed on this server"
        Write-Host "" # Separator
    } else {
        Write-Host -ForegroundColor Green $Line.Certname"is installed"
        Clear-Variable $cert
        Write-Host "" # Separator
    }
}

Write-Host "End Certificate check"