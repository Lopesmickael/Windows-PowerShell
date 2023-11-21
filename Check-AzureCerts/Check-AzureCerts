######################################################################
# Certificate Table

$Certificate_Table = @(

@{Certname = "DigiCert Global Root G2"; Certtb = "df3c24f9bfd666761b268073fe06d1cc8d4f82a4"},
@{Certname = "Microsoft RSA Root Certificate Authority 2017"; Certtb = "73a5e64a3bff8316ff0edccc618a906e4eae4d74"},
@{Certname = "Microsoft ECC Root Certificate Authority 2017"; Certtb = "999a64c37ff47d9fab95f14769891460eec4c3c5"},
@{Certname = "Microsoft Azure TLS Issuing CA 01	"; Certtb = "2f2877c5d778c31e0f29c7e371df5471bd673173"},
@{Certname = "Microsoft Azure TLS Issuing CA 02"; Certtb = "e7eea674ca718e3befd90858e09f8372ad0ae2aa"},
@{Certname = "Microsoft Azure TLS Issuing CA 05"; Certtb = "6c3af02e7f269aa73afd0eff2a88a4a1f04ed1e5"},
@{Certname = "Microsoft Azure TLS Issuing CA 06"; Certtb = "30e01761ab97e59a06b41ef20af6f2de7ef4f7b0"}
)

$CertTable = $Certificate_Table

######################################################################
# Check certificate installed

Write-Host "Starting Certificate check"

Foreach ($Line in $CertTable){
    
    $cert = Get-ChildItem -Path Cert:\LocalMachine\ | Where-Object {$_.Thumbprint -eq $Line.Certtb} -ErrorAction SilentlyContinue
    if ($null -eq $cert) {
        Write-Host -ForegroundColor Yellow $Line.Certname"is not installed on this server"
        clear $cert
        Write-Host "" # Separator
    } else {
        Write-Host -ForegroundColor Green $Line.Certname"is installed"
        clear $cert
        Write-Host "" # Separator
    }
}

Write-Host "End Certificate check"