# Get-AzrObjectsLinks

`Get-AzrObjectsLinks.ps1` creates an interactive dependency map for Azure resources in explicitly selected subscriptions. It is designed for a fast architecture or dependency-mapping audit, not as a runtime network trace.

The result is one self-contained HTML file. It can be opened offline and contains no CDN, external JavaScript, or network calls.

## What it discovers

The script inventories resources with Azure Resource Graph and records relationships from:

- ARM resource IDs exposed in resource properties.
- Private endpoints and private-link connections.
- Virtual networks, subnets, peerings, NICs, NSGs, public IPs, load balancers, and backend pools when their IDs are present in Azure Resource Graph.
- App Service plans, subnet integration, managed identities, and other resource references.
- Diagnostic-setting targets represented as Azure resources.
- Managed identity role assignments and their Azure scopes.
- App Service app settings and connection strings that contain ARM resource IDs or Key Vault references.

Every edge records its relationship, discovery source, evidence path, and confidence. The arrow points from the dependent resource to the resource or scope it uses.

## Prerequisites

- PowerShell 7.2 or later.
- An authenticated Azure PowerShell session (`Connect-AzAccount`).
- `Az.Accounts`.
- `Az.ResourceGraph`.
- Reader access to each requested subscription.

Install the modules if needed:

```powershell
Install-Module Az.Accounts, Az.ResourceGraph -Scope CurrentUser
```

Role assignments require permission to read `Microsoft.Authorization/roleAssignments`. App Service enrichment requires permission to read/list the selected sites' configuration. Missing permissions do not discard the inventory: the report includes explicit coverage warnings for failed optional collection.

## Usage

Scan two subscriptions and write the report to the current directory:

```powershell
./Get-AzrObjectsLinks.ps1 `
    -SubscriptionId '00000000-0000-0000-0000-000000000001',
                    '00000000-0000-0000-0000-000000000002' `
    -OutputPath ./Azure-Dependency-Map.html
```

Run a faster inventory-only scan without reading App Service configuration:

```powershell
./Get-AzrObjectsLinks.ps1 `
    -SubscriptionId '00000000-0000-0000-0000-000000000001' `
    -SkipConfigurationEnrichment
```

Increase the default App Service configuration-enrichment limit:

```powershell
./Get-AzrObjectsLinks.ps1 `
    -SubscriptionId '00000000-0000-0000-0000-000000000001' `
    -MaxConfigurationResources 1000
```

The report supports search, subscription/resource-type/relationship filters, isolated-resource hiding, node and edge details, pan, zoom, and fit-to-view.

## Confidence levels

- **Confirmed**: an explicit ARM resource ID or role assignment was returned by Azure.
- **Strong**: a configuration value explicitly referred to an inventoried service, such as a Key Vault hostname, but did not contain its full ARM ID.
- **Inferred**: reserved for supported heuristics that are not direct Azure references. The initial version does not create inferred edges.

## Security and privacy

- Raw app-setting and connection-string values are processed only in memory.
- Configuration values and secrets are never written to the report or console.
- Only the configuration key name and the identified resource relationship are retained as evidence.
- Resource names, IDs, subscription IDs, resource groups, locations, and dependency metadata are embedded in the output. Treat the report as sensitive architecture information.
- The script uses the caller's existing Azure identity and does not perform an interactive login.

## Important limitations

Azure has no universal API for every dependency. The map covers supported relationships visible to the current identity; it is not proof that no other dependency exists.

In particular, this version does not:

- Observe runtime traffic or DNS resolution.
- Decrypt application-specific configuration.
- Infer dependencies from arbitrary hostnames, IP addresses, source code, or telemetry.
- Expand resources in subscriptions that were not requested.
- Guarantee configuration access when the caller has only subscription Reader.

References outside the requested inventory are shown as dashed external nodes. A warning is shown when App Service enrichment is skipped, capped, or denied. Very large estates are best reviewed by filtering the generated map by subscription and resource type.

## Tests

The focused tests use Pester 5:

```powershell
Invoke-Pester ./Tests/Get-AzrObjectsLinks.Tests.ps1
```

