#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string[]]$SubscriptionId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path (Get-Location) 'Azure-Dependency-Map.html'),

    [Parameter()]
    [ValidateRange(1, 5000)]
    [int]$MaxConfigurationResources = 500,

    [Parameter()]
    [switch]$SkipConfigurationEnrichment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-NormalizedArmId {
    param([Parameter(Mandatory)][string]$Id)

    $normalized = $Id.Trim().TrimEnd('/')
    if (-not $normalized.StartsWith('/')) {
        return $normalized
    }

    return $normalized.ToLowerInvariant()
}

function Get-ArmResourceTypeFromId {
    param([Parameter(Mandatory)][string]$Id)

    $segments = $Id.Trim('/').Split('/')
    $providerIndex = [Array]::IndexOf($segments, 'providers')
    if ($providerIndex -lt 0 -or $segments.Count -le ($providerIndex + 2)) {
        if ($segments.Count -ge 2 -and $segments[0] -eq 'subscriptions') {
            return 'microsoft.resources/subscriptions'
        }
        return 'external/scope'
    }

    $typeSegments = [System.Collections.Generic.List[string]]::new()
    $typeSegments.Add($segments[$providerIndex + 1])
    for ($index = $providerIndex + 2; $index -lt $segments.Count; $index += 2) {
        $typeSegments.Add($segments[$index])
    }
    return ($typeSegments -join '/').ToLowerInvariant()
}

function Get-ArmResourceNameFromId {
    param([Parameter(Mandatory)][string]$Id)

    $segments = $Id.Trim('/').Split('/')
    if ($segments.Count -eq 0) {
        return $Id
    }
    return [Uri]::UnescapeDataString($segments[-1])
}

function Get-ArmIdSegment {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$SegmentName
    )

    $segments = $Id.Trim('/').Split('/')
    for ($index = 0; $index -lt ($segments.Count - 1); $index++) {
        if ($segments[$index].Equals($SegmentName, [StringComparison]::OrdinalIgnoreCase)) {
            return $segments[$index + 1]
        }
    }
    return $null
}

function Get-OptionalProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject[$Name]
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) {
        return $property.Value
    }
    return $null
}

function Get-ArmReferences {
    param(
        [AllowNull()][object]$InputObject,
        [string]$Path = 'properties'
    )

    $references = [System.Collections.Generic.List[object]]::new()

    function Visit-Value {
        param(
            [AllowNull()][object]$Value,
            [string]$CurrentPath
        )

        if ($null -eq $Value) {
            return
        }

        if ($Value -is [string]) {
            $armIdMatches = [regex]::Matches(
                $Value,
                '(?i)/subscriptions/[0-9a-f-]+(?:/resourceGroups/[^/\s"''<>,;]+)?(?:/providers/[a-z0-9.\-]+(?:/[^/\s"''<>,;]+){2,})?'
            )
            foreach ($match in $armIdMatches) {
                $references.Add([pscustomobject]@{
                    Id   = ConvertTo-NormalizedArmId -Id $match.Value
                    Path = $CurrentPath
                })
            }
            return
        }

        if ($Value -is [System.Collections.IDictionary]) {
            foreach ($key in $Value.Keys) {
                Visit-Value -Value $Value[$key] -CurrentPath "$CurrentPath.$key"
            }
            return
        }

        if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
            $index = 0
            foreach ($item in $Value) {
                Visit-Value -Value $item -CurrentPath "$CurrentPath[$index]"
                $index++
            }
            return
        }

        foreach ($property in $Value.PSObject.Properties) {
            Visit-Value -Value $property.Value -CurrentPath "$CurrentPath.$($property.Name)"
        }
    }

    Visit-Value -Value $InputObject -CurrentPath $Path
    return $references
}

function New-GraphState {
    return @{
        Nodes    = [System.Collections.Generic.Dictionary[string, object]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        Edges    = [System.Collections.Generic.Dictionary[string, object]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        Warnings = [System.Collections.Generic.List[object]]::new()
    }
}

function Add-GraphWarning {
    param(
        [Parameter(Mandatory)][hashtable]$Graph,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [string]$ResourceId
    )

    $Graph.Warnings.Add([pscustomobject]@{
        code       = $Code
        message    = $Message
        resourceId = $ResourceId
    })
}

function Add-GraphNode {
    param(
        [Parameter(Mandatory)][hashtable]$Graph,
        [Parameter(Mandatory)][string]$Id,
        [string]$Name,
        [string]$Type,
        [string]$SubscriptionId,
        [string]$ResourceGroup,
        [string]$Location,
        [string]$Kind,
        [bool]$External = $false
    )

    $normalizedId = ConvertTo-NormalizedArmId -Id $Id
    if ($Graph.Nodes.ContainsKey($normalizedId)) {
        if (-not $External -and $Graph.Nodes[$normalizedId].external) {
            $Graph.Nodes[$normalizedId].external = $false
            $Graph.Nodes[$normalizedId].name = $Name
            $Graph.Nodes[$normalizedId].type = $Type
            $Graph.Nodes[$normalizedId].subscriptionId = $SubscriptionId
            $Graph.Nodes[$normalizedId].resourceGroup = $ResourceGroup
            $Graph.Nodes[$normalizedId].location = $Location
            $Graph.Nodes[$normalizedId].kind = $Kind
        }
        return $Graph.Nodes[$normalizedId]
    }

    $node = [pscustomobject]@{
        id             = $normalizedId
        name           = if ($Name) { $Name } else { Get-ArmResourceNameFromId -Id $normalizedId }
        type           = if ($Type) { $Type.ToLowerInvariant() } else { Get-ArmResourceTypeFromId -Id $normalizedId }
        subscriptionId = if ($SubscriptionId) {
            $SubscriptionId
        } else {
            Get-ArmIdSegment -Id $normalizedId -SegmentName 'subscriptions'
        }
        resourceGroup  = if ($ResourceGroup) {
            $ResourceGroup
        } else {
            Get-ArmIdSegment -Id $normalizedId -SegmentName 'resourceGroups'
        }
        location       = $Location
        kind           = $Kind
        external       = $External
    }
    $Graph.Nodes[$normalizedId] = $node
    return $node
}

function Add-GraphEdge {
    param(
        [Parameter(Mandatory)][hashtable]$Graph,
        [Parameter(Mandatory)][string]$SourceId,
        [Parameter(Mandatory)][string]$TargetId,
        [Parameter(Mandatory)][string]$Relationship,
        [Parameter(Mandatory)][ValidateSet('Confirmed', 'Strong', 'Inferred')][string]$Confidence,
        [Parameter(Mandatory)][string]$DiscoverySource,
        [string]$EvidencePath
    )

    $source = ConvertTo-NormalizedArmId -Id $SourceId
    $target = ConvertTo-NormalizedArmId -Id $TargetId
    if ($source -eq $target) {
        return
    }

    [void](Add-GraphNode -Graph $Graph -Id $source -External (-not $Graph.Nodes.ContainsKey($source)))
    [void](Add-GraphNode -Graph $Graph -Id $target -External (-not $Graph.Nodes.ContainsKey($target)))

    $key = "$source|$target|$Relationship|$EvidencePath".ToLowerInvariant()
    if ($Graph.Edges.ContainsKey($key)) {
        return
    }

    $Graph.Edges[$key] = [pscustomobject]@{
        id              = "edge-$($Graph.Edges.Count + 1)"
        source          = $source
        target          = $target
        relationship    = $Relationship
        confidence      = $Confidence
        discoverySource = $DiscoverySource
        evidencePath    = $EvidencePath
    }
}

function Get-RelationshipName {
    param([Parameter(Mandatory)][string]$EvidencePath)

    $path = $EvidencePath.ToLowerInvariant()
    switch -Regex ($path) {
        'private.*link|private.*connection' { return 'Private link' }
        'subnet' { return 'Uses subnet' }
        'networksecuritygroup' { return 'Secured by NSG' }
        'publicipaddress' { return 'Uses public IP' }
        'backendaddresspool' { return 'Backend membership' }
        'virtualnetworkpeering|remotevirtualnetwork' { return 'VNet peering' }
        'serverfarmid' { return 'Runs on App Service plan' }
        'workspaceid|loganalytics' { return 'Sends diagnostics to workspace' }
        'storageaccountid' { return 'Uses storage account' }
        'eventhubauthorizationruleid' { return 'Sends diagnostics to Event Hub' }
        'managedby' { return 'Managed by' }
        default { return 'References resource' }
    }
}

function Add-InventoryResource {
    param(
        [Parameter(Mandatory)][hashtable]$Graph,
        [Parameter(Mandatory)][object]$Resource
    )

    [void](Add-GraphNode -Graph $Graph `
        -Id ([string]$Resource.id) `
        -Name ([string]$Resource.name) `
        -Type ([string]$Resource.type) `
        -SubscriptionId ([string]$Resource.subscriptionId) `
        -ResourceGroup ([string]$Resource.resourceGroup) `
        -Location ([string]$Resource.location) `
        -Kind ([string]$Resource.kind))
}

function Add-GenericResourceReferences {
    param(
        [Parameter(Mandatory)][hashtable]$Graph,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Resources
    )

    foreach ($resource in $Resources) {
        $sourceId = ConvertTo-NormalizedArmId -Id ([string]$resource.id)

        $managedBy = Get-OptionalProperty -InputObject $resource -Name 'managedBy'
        if ($managedBy) {
            Add-GraphEdge -Graph $Graph -SourceId $sourceId -TargetId ([string]$managedBy) `
                -Relationship 'Managed by' -Confidence 'Confirmed' -DiscoverySource 'Azure Resource Graph' `
                -EvidencePath 'managedBy'
        }

        $properties = Get-OptionalProperty -InputObject $resource -Name 'properties'
        foreach ($reference in (Get-ArmReferences -InputObject $properties)) {
            Add-GraphEdge -Graph $Graph -SourceId $sourceId -TargetId $reference.Id `
                -Relationship (Get-RelationshipName -EvidencePath $reference.Path) `
                -Confidence 'Confirmed' -DiscoverySource 'Azure Resource Graph property' `
                -EvidencePath $reference.Path
        }
    }
}

function Add-IdentityRelationships {
    param(
        [Parameter(Mandatory)][hashtable]$Graph,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Resources
    )

    $principalOwners = [System.Collections.Generic.Dictionary[string, string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($resource in $Resources) {
        $identity = Get-OptionalProperty -InputObject $resource -Name 'identity'
        if ($null -eq $identity) {
            continue
        }

        $principalId = Get-OptionalProperty -InputObject $identity -Name 'principalId'
        if ($principalId) {
            $principalOwners[[string]$principalId] = ConvertTo-NormalizedArmId -Id $resource.id
        }

        $userAssignedIdentities = Get-OptionalProperty -InputObject $identity -Name 'userAssignedIdentities'
        if ($userAssignedIdentities) {
            foreach ($property in $userAssignedIdentities.PSObject.Properties) {
                Add-GraphEdge -Graph $Graph -SourceId $resource.id -TargetId $property.Name `
                    -Relationship 'Uses managed identity' -Confidence 'Confirmed' `
                    -DiscoverySource 'Azure Resource Graph identity' `
                    -EvidencePath "identity.userAssignedIdentities.$($property.Name)"
                $userPrincipalId = Get-OptionalProperty -InputObject $property.Value -Name 'principalId'
                if ($userPrincipalId) {
                    $principalOwners[[string]$userPrincipalId] = ConvertTo-NormalizedArmId -Id $property.Name
                }
            }
        }
    }

    return $principalOwners
}

function Add-RoleAssignmentRelationships {
    param(
        [Parameter(Mandatory)][hashtable]$Graph,
        [AllowEmptyCollection()][object[]]$RoleAssignments = @(),
        [Parameter(Mandatory)][System.Collections.Generic.Dictionary[string, string]]$PrincipalOwners
    )

    foreach ($assignment in $RoleAssignments) {
        $principalId = [string]$assignment.properties.principalId
        if (-not $principalId -or -not $PrincipalOwners.ContainsKey($principalId)) {
            continue
        }

        $assignmentId = [string]$assignment.id
        $marker = '/providers/microsoft.authorization/roleassignments/'
        $markerIndex = $assignmentId.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase)
        if ($markerIndex -le 0) {
            continue
        }

        $scope = $assignmentId.Substring(0, $markerIndex)
        Add-GraphEdge -Graph $Graph -SourceId $PrincipalOwners[$principalId] -TargetId $scope `
            -Relationship 'Authorized on scope' -Confidence 'Confirmed' `
            -DiscoverySource 'Azure Resource Graph role assignment' `
            -EvidencePath "roleAssignment:$($assignment.name)"
    }
}

function Invoke-ResourceGraphPagedQuery {
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string[]]$Subscription
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $skipToken = $null
    do {
        $parameters = @{
            Query        = $Query
            Subscription = $Subscription
            First        = 1000
        }
        if ($skipToken) {
            $parameters.SkipToken = $skipToken
        }

        $page = Search-AzGraph @parameters
        foreach ($item in $page) {
            $results.Add($item)
        }
        $skipToken = $page.SkipToken
    } while ($skipToken)

    return $results
}

function Get-ValidatedSubscriptions {
    param([Parameter(Mandatory)][string[]]$RequestedSubscriptionId)

    $validated = [System.Collections.Generic.List[object]]::new()
    foreach ($id in ($RequestedSubscriptionId | Select-Object -Unique)) {
        try {
            $subscription = Get-AzSubscription -SubscriptionId $id -ErrorAction Stop
        }
        catch {
            throw "Subscription '$id' is unavailable to the current Az account. $($_.Exception.Message)"
        }

        if ($subscription.State -ne 'Enabled') {
            throw "Subscription '$id' is '$($subscription.State)', not Enabled."
        }
        $validated.Add($subscription)
    }
    return $validated
}

function Get-ConfigurationReferences {
    param(
        [Parameter(Mandatory)][object]$Resource,
        [Parameter(Mandatory)][hashtable]$Graph
    )

    $apiVersion = '2022-03-01'
    $endpoints = @(
        @{
            Name = 'app settings'
            Path = "$($Resource.id)/config/appsettings/list?api-version=$apiVersion"
        },
        @{
            Name = 'connection strings'
            Path = "$($Resource.id)/config/connectionstrings/list?api-version=$apiVersion"
        }
    )

    foreach ($endpoint in $endpoints) {
        try {
            $response = Invoke-AzRestMethod -Method POST -Path $endpoint.Path
            $content = $response.Content | ConvertFrom-Json -Depth 50
            foreach ($property in $content.properties.PSObject.Properties) {
                $evidencePath = "$($endpoint.Name).$($property.Name)"
                foreach ($reference in (Get-ArmReferences -InputObject $property.Value -Path $evidencePath)) {
                    Add-GraphEdge -Graph $Graph -SourceId $Resource.id -TargetId $reference.Id `
                        -Relationship 'Configuration references resource' -Confidence 'Strong' `
                        -DiscoverySource 'App Service configuration' -EvidencePath $evidencePath
                }

                $keyVaultMatch = [regex]::Match(
                    [string]$property.Value,
                    '(?i)https://(?<vault>[a-z0-9-]+)\.vault\.azure\.net/'
                )
                if ($keyVaultMatch.Success) {
                    $vault = $Graph.Nodes.Values |
                        Where-Object {
                            $_.type -eq 'microsoft.keyvault/vaults' -and
                            $_.name -eq $keyVaultMatch.Groups['vault'].Value
                        } |
                        Select-Object -First 1
                    if ($vault) {
                        Add-GraphEdge -Graph $Graph -SourceId $Resource.id -TargetId $vault.id `
                            -Relationship 'References Key Vault' -Confidence 'Strong' `
                            -DiscoverySource 'App Service configuration' -EvidencePath $evidencePath
                    }
                }
            }
        }
        catch {
            Add-GraphWarning -Graph $Graph -Code 'ConfigurationReadFailed' `
                -Message "Could not inspect $($endpoint.Name): $($_.Exception.Message)" `
                -ResourceId $Resource.id
        }
    }
}

function Get-ReportHtml {
    param([Parameter(Mandatory)][hashtable]$Report)

    $json = $Report | ConvertTo-Json -Depth 20 -Compress
    $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Azure Resource Dependency Map</title>
  <script>
    (() => {
      const param = new URLSearchParams(window.location.search).get("scoutTheme");
      const theme =
        param || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      document.documentElement.setAttribute("data-theme", theme);
    })();
  </script>
  <style>
    :root {
      color-scheme: light;
      --cp-bg: #f7f4ef;
      --cp-bg-elevated: #fcfbf8;
      --cp-surface: #ffffff;
      --cp-surface-soft: #f5f5f5;
      --cp-border: #dedede;
      --cp-border-strong: #919191;
      --cp-text: #242424;
      --cp-text-muted: #5c5c5c;
      --cp-text-soft: #6f6f6f;
      --cp-accent: #b11f4b;
      --cp-accent-hover: #9a1a41;
      --cp-accent-soft: rgba(177, 31, 75, 0.08);
      --cp-accent-fg: #ffffff;
      --cp-success: #16a34a;
      --cp-danger: #dc2626;
      --cp-warning: #f59e0b;
      --cp-link: #0078d4;
      --cp-shadow: 0 18px 48px rgba(0, 0, 0, 0.12);
      --cp-overlay: rgba(255, 255, 255, 0.8);
      --cp-panel: rgba(255, 255, 255, 0.86);
      --cp-panel-strong: rgba(255, 255, 255, 0.96);
      --cp-sheen: rgba(255, 255, 255, 0.55);
      --cp-highlight: rgba(177, 31, 75, 0.12);
    }
    html[data-theme="dark"] {
      color-scheme: dark;
      --cp-bg: #3d3b3a;
      --cp-bg-elevated: #343231;
      --cp-surface: #292929;
      --cp-surface-soft: #2e2e2e;
      --cp-border: #474747;
      --cp-border-strong: #5f5f5f;
      --cp-text: #dedede;
      --cp-text-muted: #919191;
      --cp-text-soft: #b0b0b0;
      --cp-accent: #fd8ea1;
      --cp-accent-hover: #fb7b91;
      --cp-accent-soft: rgba(253, 142, 161, 0.14);
      --cp-accent-fg: #1a1a1a;
      --cp-success: #4ade80;
      --cp-danger: #f87171;
      --cp-warning: #fbbf24;
      --cp-link: #4da6ff;
      --cp-shadow: 0 18px 48px rgba(0, 0, 0, 0.32);
      --cp-overlay: rgba(41, 41, 41, 0.88);
      --cp-panel: rgba(41, 41, 41, 0.72);
      --cp-panel-strong: rgba(41, 41, 41, 0.96);
      --cp-sheen: rgba(255, 255, 255, 0.04);
      --cp-highlight: rgba(253, 142, 161, 0.12);
    }
    * { box-sizing: border-box; }
    html, body { height: 100%; margin: 0; }
    body {
      background: var(--cp-bg);
      color: var(--cp-text);
      font-family: "Segoe UI", Aptos, Calibri, -apple-system, BlinkMacSystemFont, sans-serif;
      overflow: hidden;
    }
    button, input, select { font: inherit; }
    button, input, select {
      background: var(--cp-surface);
      color: var(--cp-text);
      border: 1px solid var(--cp-border);
      border-radius: 0.625rem;
      min-height: 36px;
      padding: 6px 10px;
    }
    button { cursor: pointer; }
    button:hover { border-color: var(--cp-accent); }
    button:focus-visible, input:focus-visible, select:focus-visible {
      outline: 2px solid var(--cp-accent);
      outline-offset: 2px;
    }
    .app { height: 100%; display: grid; grid-template-rows: auto auto 1fr; }
    header {
      background: var(--cp-bg-elevated);
      border-bottom: 1px solid var(--cp-border);
      padding: 16px 20px 12px;
    }
    h1 { font-size: 22px; margin: 0 0 4px; }
    .subtitle, .muted { color: var(--cp-text-muted); }
    .summary { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
    .metric {
      background: var(--cp-surface);
      border: 1px solid var(--cp-border);
      border-radius: 16px;
      padding: 8px 12px;
      min-width: 110px;
      box-shadow: 0 0 2px var(--cp-border), 0 1px 2px var(--cp-border);
    }
    .metric strong { display: block; font-size: 18px; }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      padding: 10px 20px;
      background: var(--cp-surface);
      border-bottom: 1px solid var(--cp-border);
    }
    .toolbar input { min-width: 240px; flex: 1; }
    .toolbar input[type="checkbox"] { min-width: auto; min-height: auto; }
    .workspace { min-height: 0; display: grid; grid-template-columns: 1fr 340px; }
    .canvas-wrap { position: relative; min-width: 0; background: var(--cp-bg); overflow: hidden; }
    #graph { width: 100%; height: 100%; display: block; touch-action: none; }
    .side {
      background: var(--cp-bg-elevated);
      border-left: 1px solid var(--cp-border);
      overflow: auto;
      padding: 16px;
    }
    .panel {
      background: var(--cp-surface);
      border: 1px solid var(--cp-border);
      border-radius: 16px;
      padding: 14px;
      margin-bottom: 12px;
      box-shadow: 0 0 2px var(--cp-border), 0 1px 2px var(--cp-border);
    }
    .panel h2 { font-size: 15px; margin: 0 0 10px; }
    .details { overflow-wrap: anywhere; }
    .details dt { color: var(--cp-text-muted); font-size: 12px; margin-top: 10px; }
    .details dd { margin: 2px 0; }
    .mono { font-family: Consolas, "Courier New", Courier, monospace; font-size: 12px; }
    .warning {
      border-left: 4px solid var(--cp-warning);
      padding-left: 8px;
      margin: 8px 0;
      font-size: 13px;
    }
    .badge {
      display: inline-block;
      border: 1px solid var(--cp-border);
      border-radius: 0.625rem;
      padding: 2px 7px;
      margin: 2px;
      font-size: 12px;
    }
    .legend-row { display: flex; align-items: center; gap: 8px; margin: 6px 0; font-size: 13px; }
    .line-sample { width: 32px; border-top: 2px solid var(--cp-border-strong); }
    .line-sample.strong { border-top-color: var(--cp-link); }
    .line-sample.inferred { border-top-color: var(--cp-warning); border-top-style: dashed; }
    .empty {
      position: absolute;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      color: var(--cp-text-muted);
      pointer-events: none;
    }
    .edge { stroke: var(--cp-border-strong); stroke-width: 1.5; fill: none; }
    .edge.strong { stroke: var(--cp-link); }
    .edge.inferred { stroke: var(--cp-warning); stroke-dasharray: 5 4; }
    .edge.selected { stroke: var(--cp-accent); stroke-width: 3; }
    .edge-hit { stroke: var(--cp-overlay); stroke-width: 12; fill: none; opacity: 0; cursor: pointer; }
    .node rect { fill: var(--cp-surface); stroke: var(--cp-border-strong); stroke-width: 1.5; rx: 10; }
    .node.external rect { fill: var(--cp-surface-soft); stroke-dasharray: 5 3; }
    .node.selected rect { stroke: var(--cp-accent); stroke-width: 3; fill: var(--cp-accent-soft); }
    .node text { fill: var(--cp-text); pointer-events: none; }
    .node .type { fill: var(--cp-text-muted); font-size: 10px; }
    .node { cursor: pointer; }
    .group-label { fill: var(--cp-text-muted); font-size: 12px; font-weight: 600; }
    .zoom-controls {
      position: absolute;
      left: 12px;
      bottom: 12px;
      display: flex;
      gap: 6px;
    }
    @media (max-width: 900px) {
      .workspace { grid-template-columns: 1fr; }
      .side { display: none; }
    }
  </style>
</head>
<body>
  <div class="app">
    <header>
      <h1>Azure Resource Dependency Map</h1>
      <div class="subtitle" id="scopeText"></div>
      <div class="summary">
        <div class="metric"><strong id="nodeCount">0</strong><span class="muted">Resources</span></div>
        <div class="metric"><strong id="edgeCount">0</strong><span class="muted">Relationships</span></div>
        <div class="metric"><strong id="externalCount">0</strong><span class="muted">External targets</span></div>
        <div class="metric"><strong id="warningCount">0</strong><span class="muted">Coverage warnings</span></div>
      </div>
    </header>
    <div class="toolbar">
      <input id="search" type="search" placeholder="Search resource name, type, group, or ID" aria-label="Search resources">
      <select id="subscriptionFilter" aria-label="Filter by subscription"></select>
      <select id="typeFilter" aria-label="Filter by resource type"></select>
      <select id="relationshipFilter" aria-label="Filter by relationship"></select>
      <label><input id="isolatedToggle" type="checkbox" checked> Show isolated</label>
      <button id="resetButton" type="button">Reset filters</button>
    </div>
    <main class="workspace">
      <section class="canvas-wrap" aria-label="Dependency graph">
        <svg id="graph" role="img" aria-label="Azure resource dependency graph">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="context-stroke"></path>
            </marker>
          </defs>
          <g id="viewport"><g id="groups"></g><g id="edges"></g><g id="nodes"></g></g>
        </svg>
        <div class="empty" id="emptyState">No resources match the current filters.</div>
        <div class="zoom-controls">
          <button id="zoomIn" type="button" aria-label="Zoom in">+</button>
          <button id="zoomOut" type="button" aria-label="Zoom out">−</button>
          <button id="fitView" type="button">Fit</button>
        </div>
      </section>
      <aside class="side">
        <section class="panel">
          <h2>Selection</h2>
          <div id="selection" class="muted">Select a resource or relationship.</div>
        </section>
        <section class="panel">
          <h2>Evidence confidence</h2>
          <div class="legend-row"><span class="line-sample"></span> Confirmed</div>
          <div class="legend-row"><span class="line-sample strong"></span> Strong</div>
          <div class="legend-row"><span class="line-sample inferred"></span> Inferred</div>
          <p class="muted">An arrow points from the dependent resource to the resource or scope it uses.</p>
        </section>
        <section class="panel">
          <h2>Coverage warnings</h2>
          <div id="warnings"></div>
        </section>
      </aside>
    </main>
  </div>
  <script>
    (() => {
      "use strict";
      const report = JSON.parse(new TextDecoder().decode(
        Uint8Array.from(atob("__GRAPH_DATA__"), character => character.charCodeAt(0))
      ));
      const svg = document.getElementById("graph");
      const viewport = document.getElementById("viewport");
      const nodesLayer = document.getElementById("nodes");
      const edgesLayer = document.getElementById("edges");
      const groupsLayer = document.getElementById("groups");
      const selection = document.getElementById("selection");
      const search = document.getElementById("search");
      const subscriptionFilter = document.getElementById("subscriptionFilter");
      const typeFilter = document.getElementById("typeFilter");
      const relationshipFilter = document.getElementById("relationshipFilter");
      const isolatedToggle = document.getElementById("isolatedToggle");
      const ns = "http://www.w3.org/2000/svg";
      let transform = { x: 24, y: 24, scale: 1 };
      let dragging = false;
      let pointerStart = null;
      let selectedId = null;
      let layoutBounds = { width: 1, height: 1 };

      const byId = new Map(report.nodes.map(node => [node.id, node]));
      const createSvg = (name, attributes = {}) => {
        const element = document.createElementNS(ns, name);
        Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, value));
        return element;
      };
      const setOptions = (element, values, allLabel) => {
        element.replaceChildren();
        const all = document.createElement("option");
        all.value = "";
        all.textContent = allLabel;
        element.append(all);
        values.forEach(value => {
          const option = document.createElement("option");
          option.value = value;
          option.textContent = value;
          element.append(option);
        });
      };
      const distinct = values => [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b));
      const shortType = type => type.split("/").slice(-2).join("/");
      const applyTransform = () => {
        viewport.setAttribute("transform", `translate(${transform.x} ${transform.y}) scale(${transform.scale})`);
      };
      const appendDetail = (container, label, value, mono = false) => {
        const dt = document.createElement("dt");
        dt.textContent = label;
        const dd = document.createElement("dd");
        dd.textContent = value || "—";
        if (mono) dd.className = "mono";
        container.append(dt, dd);
      };
      const showNode = node => {
        selectedId = node.id;
        const details = document.createElement("dl");
        details.className = "details";
        appendDetail(details, "Name", node.name);
        appendDetail(details, "Type", node.type);
        appendDetail(details, "Resource group", node.resourceGroup);
        appendDetail(details, "Subscription", node.subscriptionId, true);
        appendDetail(details, "Location", node.location);
        appendDetail(details, "Resource ID", node.id, true);
        appendDetail(details, "Scope", node.external ? "Outside inventory / unresolved" : "Inventoried");
        selection.replaceChildren(details);
        render();
      };
      const showEdge = edge => {
        selectedId = edge.id;
        const details = document.createElement("dl");
        details.className = "details";
        appendDetail(details, "Relationship", edge.relationship);
        appendDetail(details, "From", byId.get(edge.source)?.name || edge.source);
        appendDetail(details, "To", byId.get(edge.target)?.name || edge.target);
        appendDetail(details, "Confidence", edge.confidence);
        appendDetail(details, "Discovery source", edge.discoverySource);
        appendDetail(details, "Evidence path", edge.evidencePath, true);
        selection.replaceChildren(details);
        render();
      };

      document.getElementById("scopeText").textContent =
        `${report.metadata.subscriptions.length} subscription(s) • Generated ${new Date(report.metadata.generatedAt).toLocaleString()} • Supported evidence only`;
      setOptions(subscriptionFilter, distinct(report.nodes.map(node => node.subscriptionId)), "All subscriptions");
      setOptions(typeFilter, distinct(report.nodes.map(node => node.type)), "All resource types");
      setOptions(relationshipFilter, distinct(report.edges.map(edge => edge.relationship)), "All relationships");
      document.getElementById("warningCount").textContent = report.warnings.length;
      const warnings = document.getElementById("warnings");
      if (!report.warnings.length) {
        warnings.textContent = "No collection warnings were reported.";
        warnings.className = "muted";
      } else {
        report.warnings.slice(0, 100).forEach(warning => {
          const item = document.createElement("div");
          item.className = "warning";
          item.textContent = `${warning.code}: ${warning.message}${warning.resourceId ? ` (${warning.resourceId})` : ""}`;
          warnings.append(item);
        });
        if (report.warnings.length > 100) {
          const remainder = document.createElement("div");
          remainder.className = "muted";
          remainder.textContent = `${report.warnings.length - 100} additional warnings omitted from this panel.`;
          warnings.append(remainder);
        }
      }

      function filteredGraph() {
        const term = search.value.trim().toLowerCase();
        const subscription = subscriptionFilter.value;
        const type = typeFilter.value;
        const relationship = relationshipFilter.value;
        let edges = report.edges.filter(edge => !relationship || edge.relationship === relationship);
        const connected = new Set(edges.flatMap(edge => [edge.source, edge.target]));
        let nodes = report.nodes.filter(node => {
          const matchesText = !term || [node.name, node.type, node.resourceGroup, node.id]
            .some(value => String(value || "").toLowerCase().includes(term));
          return matchesText &&
            (!subscription || node.subscriptionId === subscription) &&
            (!type || node.type === type) &&
            (isolatedToggle.checked || connected.has(node.id));
        });
        const visible = new Set(nodes.map(node => node.id));
        edges = edges.filter(edge => visible.has(edge.source) && visible.has(edge.target));
        return { nodes, edges };
      }

      function render() {
        const graph = filteredGraph();
        nodesLayer.replaceChildren();
        edgesLayer.replaceChildren();
        groupsLayer.replaceChildren();
        document.getElementById("emptyState").style.display = graph.nodes.length ? "none" : "flex";
        document.getElementById("nodeCount").textContent = graph.nodes.length;
        document.getElementById("edgeCount").textContent = graph.edges.length;
        document.getElementById("externalCount").textContent =
          graph.nodes.filter(node => node.external).length;

        const groups = new Map();
        graph.nodes.forEach(node => {
          const key = `${node.subscriptionId || "External"} / ${node.resourceGroup || "External"}`;
          if (!groups.has(key)) groups.set(key, []);
          groups.get(key).push(node);
        });
        let y = 24;
        const positions = new Map();
        [...groups.entries()].sort(([a], [b]) => a.localeCompare(b)).forEach(([name, nodes]) => {
          const label = createSvg("text", { x: 8, y, class: "group-label" });
          label.textContent = name;
          groupsLayer.append(label);
          y += 16;
          nodes.sort((a, b) => a.name.localeCompare(b.name)).forEach((node, index) => {
            const column = index % 4;
            const row = Math.floor(index / 4);
            positions.set(node.id, { x: 8 + column * 220, y: y + row * 76 });
          });
          y += Math.ceil(nodes.length / 4) * 76 + 28;
        });
        layoutBounds = { width: 890, height: Math.max(y, 100) };

        graph.edges.forEach(edge => {
          const source = positions.get(edge.source);
          const target = positions.get(edge.target);
          if (!source || !target) return;
          const x1 = source.x + 184;
          const y1 = source.y + 28;
          const x2 = target.x;
          const y2 = target.y + 28;
          const curve = Math.max(40, Math.abs(x2 - x1) / 2);
          const pathValue = `M ${x1} ${y1} C ${x1 + curve} ${y1}, ${x2 - curve} ${y2}, ${x2} ${y2}`;
          const group = createSvg("g");
          const path = createSvg("path", {
            d: pathValue,
            class: `edge ${edge.confidence.toLowerCase()}${selectedId === edge.id ? " selected" : ""}`,
            "marker-end": "url(#arrow)"
          });
          const hit = createSvg("path", { d: pathValue, class: "edge-hit" });
          hit.addEventListener("click", event => {
            event.stopPropagation();
            showEdge(edge);
          });
          group.append(path, hit);
          edgesLayer.append(group);
        });

        graph.nodes.forEach(node => {
          const position = positions.get(node.id);
          const group = createSvg("g", {
            class: `node${node.external ? " external" : ""}${selectedId === node.id ? " selected" : ""}`,
            transform: `translate(${position.x} ${position.y})`,
            tabindex: "0",
            role: "button",
            "aria-label": `${node.name}, ${node.type}`
          });
          group.append(createSvg("rect", { width: 184, height: 56 }));
          const name = createSvg("text", { x: 10, y: 22 });
          name.textContent = node.name.length > 24 ? `${node.name.slice(0, 22)}…` : node.name;
          const type = createSvg("text", { x: 10, y: 41, class: "type" });
          const typeText = shortType(node.type);
          type.textContent = typeText.length > 28 ? `${typeText.slice(0, 26)}…` : typeText;
          group.append(name, type);
          group.addEventListener("click", event => {
            event.stopPropagation();
            showNode(node);
          });
          group.addEventListener("keydown", event => {
            if (event.key === "Enter" || event.key === " ") showNode(node);
          });
          nodesLayer.append(group);
        });
      }

      function fitView() {
        const bounds = svg.getBoundingClientRect();
        if (!bounds.width || !bounds.height) return;
        const scale = Math.min(bounds.width / layoutBounds.width, bounds.height / layoutBounds.height, 1.5) * 0.92;
        transform = {
          scale,
          x: (bounds.width - layoutBounds.width * scale) / 2,
          y: (bounds.height - layoutBounds.height * scale) / 2
        };
        applyTransform();
      }
      function zoom(multiplier, point = null) {
        const rect = svg.getBoundingClientRect();
        const center = point || { x: rect.width / 2, y: rect.height / 2 };
        const nextScale = Math.max(0.15, Math.min(4, transform.scale * multiplier));
        const ratio = nextScale / transform.scale;
        transform.x = center.x - (center.x - transform.x) * ratio;
        transform.y = center.y - (center.y - transform.y) * ratio;
        transform.scale = nextScale;
        applyTransform();
      }
      svg.addEventListener("pointerdown", event => {
        dragging = true;
        pointerStart = { x: event.clientX - transform.x, y: event.clientY - transform.y };
        svg.setPointerCapture(event.pointerId);
      });
      svg.addEventListener("pointermove", event => {
        if (!dragging) return;
        transform.x = event.clientX - pointerStart.x;
        transform.y = event.clientY - pointerStart.y;
        applyTransform();
      });
      svg.addEventListener("pointerup", () => { dragging = false; });
      svg.addEventListener("wheel", event => {
        event.preventDefault();
        const rect = svg.getBoundingClientRect();
        zoom(event.deltaY < 0 ? 1.1 : 0.9, { x: event.clientX - rect.left, y: event.clientY - rect.top });
      }, { passive: false });
      svg.addEventListener("click", () => {
        selectedId = null;
        selection.textContent = "Select a resource or relationship.";
        selection.className = "muted";
        render();
      });
      [search, subscriptionFilter, typeFilter, relationshipFilter, isolatedToggle]
        .forEach(element => element.addEventListener("input", () => {
          selectedId = null;
          render();
          fitView();
        }));
      document.getElementById("resetButton").addEventListener("click", () => {
        search.value = "";
        subscriptionFilter.value = "";
        typeFilter.value = "";
        relationshipFilter.value = "";
        isolatedToggle.checked = true;
        selectedId = null;
        render();
        fitView();
      });
      document.getElementById("zoomIn").addEventListener("click", () => zoom(1.2));
      document.getElementById("zoomOut").addEventListener("click", () => zoom(0.8));
      document.getElementById("fitView").addEventListener("click", fitView);
      window.addEventListener("resize", fitView);
      render();
      requestAnimationFrame(fitView);
    })();
  </script>
</body>
</html>
'@

    return $html.Replace('__GRAPH_DATA__', $base64)
}

function New-AzureDependencyReport {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Resources,
        [object[]]$RoleAssignments = @(),
        [string[]]$Subscriptions = @(),
        [object[]]$Warnings = @()
    )

    $graph = New-GraphState
    foreach ($resource in $Resources) {
        Add-InventoryResource -Graph $graph -Resource $resource
    }
    Add-GenericResourceReferences -Graph $graph -Resources $Resources
    $principalOwners = Add-IdentityRelationships -Graph $graph -Resources $Resources
    Add-RoleAssignmentRelationships -Graph $graph -RoleAssignments $RoleAssignments `
        -PrincipalOwners $principalOwners
    foreach ($warning in $Warnings) {
        $graph.Warnings.Add($warning)
    }

    return @{
        metadata = @{
            generatedAt   = [DateTimeOffset]::UtcNow.ToString('o')
            subscriptions = @($Subscriptions)
            coverage      = 'Supported evidence visible to the current Azure identity; not an exhaustive runtime dependency trace.'
        }
        nodes    = @($graph.Nodes.Values | Sort-Object id)
        edges    = @($graph.Edges.Values | Sort-Object source, target, relationship)
        warnings = @($graph.Warnings)
        graph    = $graph
    }
}

function Invoke-GetAzrObjectsLinks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$RequestedSubscriptionId,
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][int]$ConfigurationResourceLimit,
        [switch]$SkipConfiguration
    )

    foreach ($module in @('Az.Accounts', 'Az.ResourceGraph')) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            throw "Required module '$module' is not installed. Install it with: Install-Module $module -Scope CurrentUser"
        }
        Import-Module $module -ErrorAction Stop
    }

    $subscriptions = Get-ValidatedSubscriptions -RequestedSubscriptionId $RequestedSubscriptionId
    $subscriptionIds = @($subscriptions.Id)
    Write-Host "Collecting Azure resources from $($subscriptionIds.Count) subscription(s)..."

    $resourceQuery = @'
resources
| project id, name, type, subscriptionId, resourceGroup, location, kind, managedBy, identity, properties
'@
    $roleQuery = @'
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| project id, name, subscriptionId, properties
'@

    $resources = @(Invoke-ResourceGraphPagedQuery -Query $resourceQuery -Subscription $subscriptionIds)
    $roleAssignments = @()
    $initialWarnings = [System.Collections.Generic.List[object]]::new()
    try {
        $roleAssignments = @(Invoke-ResourceGraphPagedQuery -Query $roleQuery -Subscription $subscriptionIds)
    }
    catch {
        $initialWarnings.Add([pscustomobject]@{
            code       = 'RoleAssignmentQueryFailed'
            message    = "Role assignments could not be queried: $($_.Exception.Message)"
            resourceId = $null
        })
    }

    $report = New-AzureDependencyReport -Resources $resources -RoleAssignments $roleAssignments `
        -Subscriptions $subscriptionIds -Warnings $initialWarnings
    $graph = $report.graph

    if (-not $SkipConfiguration) {
        $webResources = @(
            $resources |
                Where-Object { $_.type -match '^microsoft\.web/sites($|/)' } |
                Sort-Object subscriptionId, id
        )
        if ($webResources.Count -gt $ConfigurationResourceLimit) {
            Add-GraphWarning -Graph $graph -Code 'ConfigurationEnrichmentLimited' `
                -Message "Configuration enrichment was limited to $ConfigurationResourceLimit of $($webResources.Count) App Service resources. Increase -MaxConfigurationResources or use -SkipConfigurationEnrichment." `
                -ResourceId $null
            $webResources = @($webResources | Select-Object -First $ConfigurationResourceLimit)
        }

        $originalContext = Get-AzContext
        try {
            foreach ($subscriptionGroup in ($webResources | Group-Object subscriptionId)) {
                Set-AzContext -SubscriptionId $subscriptionGroup.Name -ErrorAction Stop | Out-Null
                foreach ($resource in $subscriptionGroup.Group) {
                    Get-ConfigurationReferences -Resource $resource -Graph $graph
                }
            }
        }
        finally {
            if ($originalContext) {
                Set-AzContext -Context $originalContext -ErrorAction Stop | Out-Null
            }
        }
    }
    else {
        Add-GraphWarning -Graph $graph -Code 'ConfigurationEnrichmentSkipped' `
            -Message 'App Service settings and connection strings were not inspected because -SkipConfigurationEnrichment was specified.' `
            -ResourceId $null
    }

    $report.nodes = @($graph.Nodes.Values | Sort-Object id)
    $report.edges = @($graph.Edges.Values | Sort-Object source, target, relationship)
    $report.warnings = @($graph.Warnings)
    $report.Remove('graph')

    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportPath)
    $parent = Split-Path -Parent $resolvedPath
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    Get-ReportHtml -Report $report | Set-Content -LiteralPath $resolvedPath -Encoding utf8BOM
    Write-Host "Report written to: $resolvedPath"
    Write-Host "Resources: $($report.nodes.Count); relationships: $($report.edges.Count); warnings: $($report.warnings.Count)"
    return Get-Item -LiteralPath $resolvedPath
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-GetAzrObjectsLinks -RequestedSubscriptionId $SubscriptionId -ReportPath $OutputPath `
        -ConfigurationResourceLimit $MaxConfigurationResources `
        -SkipConfiguration:$SkipConfigurationEnrichment
}
