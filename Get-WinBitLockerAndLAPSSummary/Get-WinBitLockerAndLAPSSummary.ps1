function Convert-TimeToDays {
    [CmdletBinding()]
    param (
        $StartTime,
        $EndTime,
        #[nullable[DateTime]] $StartTime,
        #[nullable[DateTime]] $EndTime,
        [string] $Ignore = '*1601*'
    )
    if ($StartTime -and $EndTime) {
        try {
            if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
                $Days = (New-TimeSpan -Start (Get-Date) -End ($EndTime)).Days
            } else {
                $Days = $null
            }
        } catch {
            $Days = $null
        }
    }
    return $Days
}
function Convert-ToDateTime {
    [CmdletBinding()]
    param (
        [string] $Timestring,
        [string] $Ignore = '*1601*'
    )
    Try {
        $DateTime = ([datetime]::FromFileTime($Timestring))
    } catch {
        $DateTime = $null
    }
    if ($null -eq $DateTime -or $DateTime -like $Ignore) {
        return $null
    } else {
        return $DateTime
    }
}
function Get-WinADForestSchemaPropertiesComputers {
    [CmdletBinding()]
    param(
    )
    $Schema = [directoryservices.activedirectory.activedirectoryschema]::GetCurrentSchema()
    @(
        $Schema.FindClass("computer").mandatoryproperties | Select-Object name, commonname, description, syntax
        $Schema.FindClass("computer").optionalproperties | Select-Object name, commonname, description, syntax #| Where-Object { $_.Name -eq 'ms-Mcs-AdmPwd' } # ft -AutoSize
    )
}
function ConvertTo-OperatingSystem {
    [CmdletBinding()]
    param(
        [string] $OperatingSystem,
        [string] $OperatingSystemVersion
    )
    if ($OperatingSystem -like 'Windows 10*') {
        $Systems = @{
            
            '10.0 (18362)' = "Windows 10 1903"
            '10.0 (17763)' = "Windows 10 1809"
            '10.0 (17134)' = "Windows 10 1803"
            '10.0 (16299)' = "Windows 10 1709"
            '10.0 (15063)' = "Windows 10 1703"
            '10.0 (14393)' = "Windows 10 1607"
            '10.0 (10586)' = "Windows 10 1511"
            '10.0 (10240)' = "Windows 10 1507"
            '10.0 (18898)' = 'Windows 10 Insider Preview'
        }
        $System = $Systems[$OperatingSystemVersion]
    } elseif ($OperatingSystem -notlike 'Windows 10*') {
        $System = $OperatingSystem
    }
    if ($System) {
        $System
    } else {
        'Unknown'
    }
}
function Get-WinBitlockerAndLapsSummary {
    [CmdletBinding()]
    param(
    )
    $ComputerProperties = Get-WinADForestSchemaPropertiesComputers
    if ($ComputerProperties.Name -contains 'ms-Mcs-AdmPwd') {
        $LapsAvailable = $true
        $Properties = @(
            'Name'
            'OperatingSystem'
            'OperatingSystemVersion'
            'DistinguishedName'
            'LastLogonDate'
            'ms-Mcs-AdmPwd'
            'ms-Mcs-AdmPwdExpirationTime'
        )
    } else {
        $LapsAvailable = $false
        $Properties = @(
            'Name'
            'OperatingSystem'
            'OperatingSystemVersion'
            'DistinguishedName'
            'LastLogonDate'
        )
    }
    $CurrentDate = Get-Date
    $Computers = Get-ADComputer -Filter * -Properties $Properties
    $FormattedComputers = foreach ($_ in $Computers) {
        if ($LapsAvailable) {
            if ($_.'ms-Mcs-AdmPwd') {
                $Laps = $true
                $LapsExpirationDays = Convert-TimeToDays -StartTime ($CurrentDate) -EndTime (Convert-ToDateTime -Timestring ($_.'ms-Mcs-AdmPwdExpirationTime'))
                $LapsExpirationTime = Convert-ToDateTime -Timestring ($_.'ms-Mcs-AdmPwdExpirationTime')
            } else {
                $Laps = $false
                $LapsExpirationDays = $null
                $LapsExpirationTime = $null
            }
        } else {
            $Laps = 'N/A'
        }
        [Array] $Bitlockers = Get-ADObject -Filter 'objectClass -eq "msFVE-RecoveryInformation"' -SearchBase $_.DistinguishedName -Properties 'WhenCreated', 'msFVE-RecoveryPassword' | Sort-Object -Descending
        if ($Bitlockers) {
            $Encrypted = $true
            $EncryptedTime = $Bitlockers[0].WhenCreated
        } else {
            $Encrypted = $false
            $EncryptedTime = $null
        }
        [PSCustomObject] @{
            Name               = $_.Name
            Enabled            = $_.Enabled
            DNSHostName        = $_.DNSHostName
            DistinguishedName  = $_.DistinguishedName
            System             = ConvertTo-OperatingSystem -OperatingSystem $_.OperatingSystem -OperatingSystemVersion $_.OperatingSystemVersion
            LastLogonDate      = $_.LastLogonDate
            Encrypted          = $Encrypted
            EncryptedTime      = $EncryptedTime
            Laps               = $Laps
            LapsExpirationDays = $LapsExpirationDays
            LapsExpirationTime = $LapsExpirationTime
        }
    }
    return $FormattedComputers
}
$FormattedComputers = Get-WinBitlockerAndLapsSummary
$FormattedComputers | Format-Table -AutoSize *