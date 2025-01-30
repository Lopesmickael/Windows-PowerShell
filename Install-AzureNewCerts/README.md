# Install Azure Certificates

Due to some customer strugling to understand issues on ARC agent installation, ESU installation package, or application access, some certificates where not trusted.

As show here : https://learn.microsoft.com/en-us/azure/security/fundamentals/tls-certificate-changes new ROOT and Intermediate certificates are now used by OFFICE 365 / Azure services

This script will install all needed certificates with two options : 

-ONLINE

Will download certificates on Internet

-OFFLINE

You will need to download certs before and pass in params where certs folder is 