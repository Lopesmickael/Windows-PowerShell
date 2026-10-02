BeforeAll {
    . "$PSScriptRoot/../Get-AzrObjectsLinks.ps1" -SubscriptionId 'test'
    $script:TestSubscriptionId = '00000000-0000-0000-0000-000000000001'

    function New-TestResource {
        param(
            [string]$Name,
            [string]$Type,
            [object]$Properties = [pscustomobject]@{},
            [object]$Identity = $null
        )

        [pscustomobject]@{
            id             = "/subscriptions/$script:TestSubscriptionId/resourceGroups/rg-one/providers/$Type/$Name"
            name           = $Name
            type           = $Type
            subscriptionId = $script:TestSubscriptionId
            resourceGroup  = 'rg-one'
            location       = 'westeurope'
            kind           = $null
            managedBy      = $null
            identity       = $Identity
            properties     = $Properties
        }
    }
}

Describe 'ARM resource normalization and extraction' {
    It 'normalizes ARM IDs without changing non-ARM identifiers' {
        ConvertTo-NormalizedArmId -Id '/Subscriptions/ABC/ResourceGroups/RG/' |
            Should -Be '/subscriptions/abc/resourcegroups/rg'
        ConvertTo-NormalizedArmId -Id 'principal:ABC' | Should -Be 'principal:ABC'
    }

    It 'extracts nested ARM references with their evidence paths' {
        $inputObject = [pscustomobject]@{
            network = [pscustomobject]@{
                subnet = [pscustomobject]@{
                    id = "/subscriptions/$script:TestSubscriptionId/resourceGroups/network-rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/apps"
                }
            }
        }

        $references = @(Get-ArmReferences -InputObject $inputObject)

        $references.Count | Should -Be 1
        $references[0].Id | Should -Be "/subscriptions/$script:TestSubscriptionId/resourcegroups/network-rg/providers/microsoft.network/virtualnetworks/vnet/subnets/apps"
        $references[0].Path | Should -Be 'properties.network.subnet.id'
    }
}

Describe 'Graph construction' {
    It 'deduplicates identical relationships' {
        $targetId = "/subscriptions/$script:TestSubscriptionId/resourceGroups/rg-one/providers/Microsoft.Storage/storageAccounts/data"
        $resource = New-TestResource -Name 'app' -Type 'Microsoft.Web/sites'
        $graph = New-GraphState
        Add-InventoryResource -Graph $graph -Resource $resource

        Add-GraphEdge -Graph $graph -SourceId $resource.id -TargetId $targetId `
            -Relationship 'Uses storage account' -Confidence Confirmed `
            -DiscoverySource 'Test' -EvidencePath 'properties.storage.id'
        Add-GraphEdge -Graph $graph -SourceId $resource.id -TargetId $targetId `
            -Relationship 'Uses storage account' -Confidence Confirmed `
            -DiscoverySource 'Test' -EvidencePath 'properties.storage.id'

        $graph.Nodes.Count | Should -Be 2
        $graph.Edges.Count | Should -Be 1
    }

    It 'links managed identities to role-assignment scopes' {
        $resource = New-TestResource -Name 'app' -Type 'Microsoft.Web/sites' -Identity ([pscustomobject]@{
            principalId = 'principal-one'
        })
        $roleAssignment = [pscustomobject]@{
            id = "/subscriptions/$script:TestSubscriptionId/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/data/providers/Microsoft.Authorization/roleAssignments/assignment-one"
            name = 'assignment-one'
            properties = [pscustomobject]@{ principalId = 'principal-one' }
        }

        $report = New-AzureDependencyReport -Resources @($resource) `
            -RoleAssignments @($roleAssignment) -Subscriptions @($script:TestSubscriptionId)

        $roleEdge = $report.edges | Where-Object relationship -eq 'Authorized on scope'
        $roleEdge.Count | Should -Be 1
        $roleEdge.target | Should -Be "/subscriptions/$script:TestSubscriptionId/resourcegroups/rg-data/providers/microsoft.storage/storageaccounts/data"
    }
}

Describe 'Safe standalone HTML report' {
    It 'does not retain raw App Service configuration values' {
        $app = New-TestResource -Name 'app' -Type 'Microsoft.Web/sites'
        $vault = New-TestResource -Name 'audit-vault' -Type 'Microsoft.KeyVault/vaults'
        $graph = New-GraphState
        Add-InventoryResource -Graph $graph -Resource $app
        Add-InventoryResource -Graph $graph -Resource $vault
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{
                Content = @{
                    properties = @{
                        DatabasePassword = 'SuperSecret123!'
                        KeyVaultReference = '@Microsoft.KeyVault(SecretUri=https://audit-vault.vault.azure.net/secrets/database/version)'
                    }
                } | ConvertTo-Json -Compress
            }
        }

        Get-ConfigurationReferences -Resource $app -Graph $graph
        $serializedGraph = $graph | ConvertTo-Json -Depth 10

        $serializedGraph | Should -Not -Match 'SuperSecret123!'
        $serializedGraph | Should -Not -Match '/secrets/database/version'
        @($graph.Edges.Values | Where-Object relationship -eq 'References Key Vault').Count |
            Should -Be 2
    }

    It 'embeds graph data without external dependencies or secret values' {
        $resource = New-TestResource -Name 'app' -Type 'Microsoft.Web/sites'
        $report = New-AzureDependencyReport -Resources @($resource) -Subscriptions @($script:TestSubscriptionId)
        $report.metadata.testMarker = 'not-a-secret'

        $html = Get-ReportHtml -Report $report

        $html | Should -Match '<meta charset="UTF-8">'
        $html | Should -Not -Match '<script\s+src='
        $html | Should -Not -Match '<link\s+[^>]*href='
        $html | Should -Not -Match 'fetch\('
        $html | Should -Not -Match 'not-a-secret'
        $html | Should -Match 'TextDecoder'
    }
}
