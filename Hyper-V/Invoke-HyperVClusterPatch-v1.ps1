<#
.SYNOPSIS
    Monthly patching for a Windows Server 2025 Hyper-V failover cluster using
    Cluster-Aware Updating (CAU) with the Microsoft.HotfixPlugin - no SCCM/WSUS dependency.

.DESCRIPTION
    1. (Optional) Downloads the month's cumulative update (and optionally .NET CU)
       from the Microsoft Update Catalog using the MSCatalogLTS module,
       OR uses .msu files you already downloaded (-SourceFolder).
    2. Stages them into the CAU hotfix share (<HotfixRoot>\CAUHotfix_All),
       archiving last month's files and seeding DefaultHotfixConfig.xml if missing.
    3. Pre-checks the cluster: nodes up, none paused, CSVs online, CAU readiness,
       and enough memory on N-1 nodes to absorb a drained node's VMs.
    4. Records each node's OS build, runs Invoke-CauRun (drain, live-migrate,
       install, reboot, resume - one node at a time), then records builds again.
    5. Exports the CAU report (HTML) plus a before/after build CSV, and optionally emails it.

    Run from a management server or one cluster node, as a domain account with
    local admin on every node. Requires the RSAT-Clustering-PowerShell feature
    (ClusterAwareUpdating + FailoverClusters modules) and the Hyper-V PowerShell module.

    WINDOWS SERVER 2025 CHECKPOINT UPDATES:
    Server 2025 cumulative updates can depend on an earlier "checkpoint" CU. Nodes
    patched every month are already past the checkpoint, so only the current CU is
    needed. If a node has fallen behind, use -IncludeCheckpoints with -SourceFolder
    containing the target CU plus every prior checkpoint .msu (the Catalog download
    pop-up lists them). Note that when several .msu files are staged, CAU installs
    each one; Microsoft's guidance is that they must apply in order, so test this
    case in a lab first.

.EXAMPLE
    # Scan only (no changes): shows what CAU would install
    .\Invoke-HyperVClusterPatch.ps1 -ClusterName HVCLUS01 -HotfixRoot \\FS01\CAUHotfix -SourceFolder D:\Patches\2026-10 -ScanOnly

.EXAMPLE
    # Download this month's CU from the Catalog and patch the cluster
    .\Invoke-HyperVClusterPatch.ps1 -ClusterName HVCLUS01 -HotfixRoot \\FS01\CAUHotfix -Download -ReportFolder D:\PatchReports

.EXAMPLE
    # Use files you downloaded by hand, email the report afterward
    .\Invoke-HyperVClusterPatch.ps1 -ClusterName HVCLUS01 -HotfixRoot \\FS01\CAUHotfix -SourceFolder D:\Patches\2026-10 `
        -SmtpServer smtp.corp.local -MailTo hyperv-team@corp.local -MailFrom cau@corp.local
#>
[CmdletBinding(DefaultParameterSetName = 'Local')]
param(
    [Parameter(Mandatory)]
    [string]$ClusterName,

    # UNC path to the CAU hotfix root share. Only admins should have write access - CAU enforces this.
    [Parameter(Mandatory)]
    [string]$HotfixRoot,

    # Folder containing .msu files you already downloaded.
    [Parameter(Mandatory, ParameterSetName = 'Local')]
    [string]$SourceFolder,

    # Download the CU from the Microsoft Update Catalog instead (needs internet + MSCatalogLTS module).
    [Parameter(Mandatory, ParameterSetName = 'Download')]
    [switch]$Download,

    # Patch month to download, e.g. '2026-10'. Defaults to the current month.
    [Parameter(ParameterSetName = 'Download')]
    [ValidatePattern('^\d{4}-\d{2}$')]
    [string]$PatchMonth = (Get-Date -Format 'yyyy-MM'),

    # Also download the .NET Framework cumulative update.
    [Parameter(ParameterSetName = 'Download')]
    [switch]$IncludeDotNet,

    # Allow more than one OS cumulative update in the staging set (checkpoint chains).
    [switch]$IncludeCheckpoints,

    [string]$ReportFolder = (Join-Path $PSScriptRoot 'PatchReports'),

    # Only run Invoke-CauScan - no installs, no reboots.
    [switch]$ScanOnly,

    # Skip the N-1 memory capacity check (not recommended).
    [switch]$SkipCapacityCheck,

    # Skip the Microsoft Authenticode check on the .msu files.
    [switch]$SkipSignatureCheck,

    # Require SMB encryption between nodes and the hotfix share (share must have EncryptData enabled).
    [bool]$RequireSmbEncryption = $true,

    [int]$MaxRetriesPerNode = 1,
    [int]$MaxFailedNodes = 0,

    # Hours before CAU warns / stops the run.
    [int]$WarnAfterHours = 4,
    [int]$StopAfterHours = 8,

    # Optional email of the summary.
    [string]$SmtpServer,
    [string[]]$MailTo,
    [string]$MailFrom
)

$ErrorActionPreference = 'Stop'
$runStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Path $ReportFolder -Force | Out-Null
$logFile = Join-Path $ReportFolder "CAU-$ClusterName-$runStamp.log"
Start-Transcript -Path $logFile -Append | Out-Null

function Write-Step([string]$Message) {
    Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor Cyan
}

function Get-NodeBuild([string[]]$Nodes) {
    Invoke-Command -ComputerName $Nodes -ScriptBlock {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        [pscustomobject]@{
            Node       = $env:COMPUTERNAME
            Build      = '{0}.{1}' -f $cv.CurrentBuild, $cv.UBR
            LastBoot   = $lastBoot
            LatestKB   = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).HotFixID
        }
    } | Select-Object Node, Build, LastBoot, LatestKB
}

try {
    #region Modules
    Write-Step "Loading modules"
    foreach ($m in 'FailoverClusters', 'ClusterAwareUpdating') {
        if (-not (Get-Module -ListAvailable -Name $m)) {
            throw "Module '$m' not found. Install with: Install-WindowsFeature RSAT-Clustering-PowerShell"
        }
        Import-Module $m
    }
    #endregion

    #region Gather updates
    $stagingSource = $null
    if ($Download) {
        Write-Step "Downloading $PatchMonth updates from the Microsoft Update Catalog"
        if (-not (Get-Module -ListAvailable -Name MSCatalogLTS)) {
            Write-Step "Installing MSCatalogLTS module (CurrentUser)"
            Install-Module MSCatalogLTS -Scope CurrentUser -Force
        }
        Import-Module MSCatalogLTS

        $stagingSource = Join-Path $env:TEMP "CAU-Download-$runStamp"
        New-Item -ItemType Directory -Path $stagingSource -Force | Out-Null

        # Server 2025 = "Microsoft server operating system version 24H2" in the Catalog.
        $searches = @("$PatchMonth Cumulative Update for Microsoft server operating system version 24H2 for x64")
        if ($IncludeDotNet) {
            $searches += "$PatchMonth Cumulative Update for .NET Framework Microsoft server operating system version 24H2 x64"
        }

        foreach ($s in $searches) {
            $found = Get-MSCatalogUpdate -Search $s |
                Where-Object { $_.Title -notmatch 'Preview|Dynamic|ARM64|Hotpatch' -and $_.Title -like "$PatchMonth*" } |
                Select-Object -First 1
            if (-not $found) { throw "No Catalog result for: $s  (has Patch Tuesday happened yet?)" }
            Write-Step "Found: $($found.Title)"
            Save-MSCatalogUpdate -Update $found -Destination $stagingSource
        }
    }
    else {
        if (-not (Test-Path $SourceFolder)) { throw "SourceFolder not found: $SourceFolder" }
        $stagingSource = $SourceFolder
    }

    $msuFiles = @(Get-ChildItem -Path $stagingSource -Filter *.msu -File)
    if ($msuFiles.Count -eq 0) { throw "No .msu files found in $stagingSource" }

    $osCUs = @($msuFiles | Where-Object { $_.Name -match '^windows11\.0-kb|^windows10\.0-kb' -and $_.Name -notmatch 'ndp' })
    if ($osCUs.Count -gt 1 -and -not $IncludeCheckpoints) {
        throw ("Found {0} OS update files ({1}). If these are a checkpoint chain, re-run with -IncludeCheckpoints; " +
               "otherwise remove the extras.") -f $osCUs.Count, ($osCUs.Name -join ', ')
    }

    # Verify Authenticode signatures before anything touches the hosts.
    foreach ($f in $msuFiles) {
        if ($SkipSignatureCheck) { break }
        $sig = Get-AuthenticodeSignature -FilePath $f.FullName
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
            throw "Signature check failed for $($f.Name): $($sig.Status)"
        }
    }
    Write-Step ("Update files: {0}" -f ($msuFiles.Name -join ', '))
    #endregion

    #region Stage hotfix share
    Write-Step "Staging updates to $HotfixRoot"
    if (-not (Test-Path $HotfixRoot)) { throw "Hotfix root not reachable: $HotfixRoot" }

    $configPath = Join-Path $HotfixRoot 'DefaultHotfixConfig.xml'
    if (-not (Test-Path $configPath)) {
        $sample = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\Modules\ClusterAwareUpdating\DefaultHotfixConfig.xml'
        if (-not (Test-Path $sample)) { throw "DefaultHotfixConfig.xml not found at $sample - copy it from a node with CAU installed." }
        Copy-Item $sample $configPath
        Write-Step "Seeded DefaultHotfixConfig.xml"
    }

    $allFolder = Join-Path $HotfixRoot 'CAUHotfix_All'
    New-Item -ItemType Directory -Path $allFolder -Force | Out-Null

    # Archive previous month's files so CAU only sees this month's set.
    $old = @(Get-ChildItem -Path $allFolder -File)
    if ($old.Count -gt 0) {
        $archive = Join-Path $HotfixRoot "Archive\$runStamp"
        New-Item -ItemType Directory -Path $archive -Force | Out-Null
        $old | Move-Item -Destination $archive
        Write-Step "Archived $($old.Count) old file(s) to $archive"
    }
    $msuFiles | Copy-Item -Destination $allFolder
    #endregion

    #region Pre-checks
    Write-Step "Pre-checking cluster $ClusterName"
    $nodes = @(Get-ClusterNode -Cluster $ClusterName)
    $notUp = @($nodes | Where-Object State -ne 'Up')
    if ($notUp.Count) { throw "Nodes not Up: $(($notUp | ForEach-Object { "$($_.Name)=$($_.State)" }) -join ', ')" }

    $csvBad = @(Get-ClusterSharedVolume -Cluster $ClusterName | Where-Object State -ne 'Online')
    if ($csvBad.Count) { throw "CSVs not Online: $($csvBad.Name -join ', ')" }

    $failedRes = @(Get-ClusterResource -Cluster $ClusterName | Where-Object State -eq 'Failed')
    if ($failedRes.Count) { Write-Warning "Failed cluster resources present: $($failedRes.Name -join ', ')" }

    $cauTest = Test-CauSetup -ClusterName $ClusterName
    $cauFail = @($cauTest | Where-Object { $_.State -eq 'Failed' })
    if ($cauFail.Count) {
        $cauFail | Format-Table RuleId, Title, State -AutoSize | Out-String | Write-Host
        throw "Test-CauSetup reported failures - fix them (usually firewall/WinRM/PowerShell remoting) and re-run."
    }

    if (-not $SkipCapacityCheck) {
        $nodeNames = $nodes.Name
        $nodeMem = foreach ($n in $nodeNames) {
            [pscustomobject]@{ Node = $n; Bytes = (Get-CimInstance -ComputerName $n Win32_ComputerSystem).TotalPhysicalMemory }
        }
        $vmMem = (Get-VM -ComputerName $nodeNames | Where-Object State -eq 'Running' |
                  Measure-Object -Property MemoryAssigned -Sum).Sum
        $largest = ($nodeMem | Measure-Object Bytes -Maximum).Maximum
        $hostReserve = 8GB * ($nodeNames.Count - 1)   # rough host OS reserve per remaining node
        $usable = ($nodeMem | Measure-Object Bytes -Sum).Sum - $largest - $hostReserve
        Write-Step ("Running VM memory {0:N0} GB vs N-1 usable {1:N0} GB" -f ($vmMem / 1GB), ($usable / 1GB))
        if ($vmMem -gt $usable) {
            throw "Not enough memory on N-1 nodes to drain safely. Shut down non-critical VMs or use -SkipCapacityCheck."
        }
    }
    #endregion

    $pluginArgs = @{
        'HotfixRootFolderPath' = $HotfixRoot
        'RequireSmbEncryption' = $RequireSmbEncryption.ToString()
    }

    if ($ScanOnly) {
        Write-Step "Scan only - listing what CAU would install"
        Invoke-CauScan -ClusterName $ClusterName -CauPluginName Microsoft.HotfixPlugin -CauPluginArguments $pluginArgs |
            Format-Table NodeName, UpdateTitle -AutoSize | Out-String | Write-Host
        return
    }

    #region Run
    $before = Get-NodeBuild -Nodes $nodes.Name
    Write-Step "Builds before:"
    $before | Format-Table -AutoSize | Out-String | Write-Host

    Write-Step "Starting CAU run (this drains and reboots one node at a time)"
    Invoke-CauRun -ClusterName $ClusterName `
        -CauPluginName Microsoft.HotfixPlugin `
        -CauPluginArguments $pluginArgs `
        -MaxRetriesPerNode $MaxRetriesPerNode `
        -MaxFailedNodes $MaxFailedNodes `
        -RequireAllNodesOnline `
        -EnableFirewallRules `
        -WarnAfter (New-TimeSpan -Hours $WarnAfterHours) `
        -StopAfter (New-TimeSpan -Hours $StopAfterHours) `
        -Force

    $after = Get-NodeBuild -Nodes $nodes.Name
    #endregion

    #region Report
    $compare = foreach ($a in $after) {
        $b = $before | Where-Object Node -eq $a.Node
        [pscustomobject]@{
            Node        = $a.Node
            BuildBefore = $b.Build
            BuildAfter  = $a.Build
            Rebooted    = $a.LastBoot -gt $b.LastBoot
            LatestKB    = $a.LatestKB
            Changed     = $a.Build -ne $b.Build
        }
    }
    $csvPath = Join-Path $ReportFolder "CAU-$ClusterName-$runStamp-builds.csv"
    $compare | Export-Csv -Path $csvPath -NoTypeInformation

    $report = Get-CauReport -ClusterName $ClusterName -Last -Detailed
    $htmlPath = Join-Path $ReportFolder "CAU-$ClusterName-$runStamp.html"
    $report | Export-CauReport -Format HTML -Path $htmlPath -Force

    Write-Step "Builds after:"
    $compare | Format-Table -AutoSize | Out-String | Write-Host

    $mismatched = @($compare | Where-Object { $_.BuildAfter -ne $compare[0].BuildAfter })
    $status = if ($report.ClusterResult -eq 'Succeeded' -and -not $mismatched.Count) { 'SUCCESS' } else { 'CHECK REQUIRED' }
    Write-Step "CAU result: $($report.ClusterResult)  |  Overall: $status"
    Write-Step "Report: $htmlPath"

    if ($SmtpServer -and $MailTo -and $MailFrom) {
        $body = "<p>CAU run on <b>$ClusterName</b>: <b>$status</b> (CAU result: $($report.ClusterResult))</p>" +
                ($compare | ConvertTo-Html -Fragment | Out-String)
        Send-MailMessage -SmtpServer $SmtpServer -To $MailTo -From $MailFrom `
            -Subject "[$status] Hyper-V patching - $ClusterName - $runStamp" `
            -Body $body -BodyAsHtml -Attachments $htmlPath, $csvPath
    }
    #endregion
}
catch {
    Write-Error $_
    throw
}
finally {
    if ($Download -and $stagingSource -and (Test-Path $stagingSource)) {
        Remove-Item $stagingSource -Recurse -Force -ErrorAction SilentlyContinue
    }
    Stop-Transcript | Out-Null
}