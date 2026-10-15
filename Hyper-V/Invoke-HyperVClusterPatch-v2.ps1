<#
.SYNOPSIS
    Manually initiated Windows Server 2025 Hyper-V cluster patching using
    Cluster-Aware Updating (CAU), Microsoft.HotfixPlugin, and staged MSU files.

.DESCRIPTION
    Development version 2 for Hyper-V failover clusters using Cluster Shared
    Volumes (CSV). Designed for 3-, 6-, 8-, and 13-node clusters.

    Workflow:
      1. Load FailoverClusters, ClusterAwareUpdating, and Hyper-V modules.
      2. Discover cluster nodes, CSVs, VM roles, and failed resources.
      3. Collect OS build, last boot, free memory, and reboot-pending state.
      4. Run Test-CauSetup and estimate each node's evacuation capacity.
      5. In patch/scan modes, validate local MSU signatures and package count.
      6. In patch mode, require the operator to type the cluster name.
      7. Copy MSUs to temporary CAU staging, compare SHA256 hashes, and
         rename the completed folder to CAUHotfix_All.
      8. In scan mode, invoke Invoke-CauScan without installing updates.
      9. In patch mode, invoke CAU for sequential node servicing.
     10. Attempt post-run node/cluster snapshots and a CAU HTML report.

    CAU is responsible for drain, live migration, patch installation, reboot,
    and node resumption. This script does not implement those actions itself.

    IMPORTANT:
    This is a development prototype, NOT a production-validated solution.
    Its evacuation estimate is not a guarantee of migration feasibility.
    Application-level health, CSV redirected I/O, quorum, checkpoint update
    prerequisites, and recovery handling need further implementation/testing.

.PARAMETER ClusterName
    Target failover cluster. Only one cluster is processed per invocation.

.PARAMETER SourceFolder
    Local or accessible folder containing approved .msu packages.
    Required for ScanOnly and patch modes; omitted for PreCheckOnly.

.PARAMETER HotfixRoot
    UNC root for Microsoft.HotfixPlugin, containing DefaultHotfixConfig.xml.
    Must be accessible to CAU and cluster nodes, with appropriate permissions.
    The script refuses to overwrite an existing CAUHotfix_All folder.

.PARAMETER PreCheckOnly
    Run cluster readiness checks without staging packages or invoking CAU.
    Report files and a transcript are still written locally.

.PARAMETER ScanOnly
    Run preflight, validate/stage MSUs, and invoke CAU scan only.
    Does NOT install patches or reboot nodes, but DOES modify the CAU share.

.PARAMETER ExpectedBuild
    Required target OS build string in patch mode (for example, 26100.XXXX).
    Compared against node builds after CAU. This does not independently
    prove KB installation or that application services are healthy.

.PARAMETER ReportFolder
    Parent folder for per-run timestamped reports. Defaults to PatchReports
    alongside this script.

.PARAMETER MemoryReservePercent
    Percentage of each destination node's currently free memory excluded
    from the evacuation estimate. Default: 20; accepted range: 5-50.
    The simulation is an approximation and does not account for every
    placement, CPU, affinity, or migration-network constraint.

.PARAMETER InstallerTimeoutMinutes
    HotfixPlugin installer timeout per node, default 120 minutes.
    Validate plugin support and behavior in your Server 2025 environment.

.PARAMETER WinRMConnectTimeoutSeconds
    WinRM session open timeout in seconds (default 15). Does not cover
    CIM/cluster/CAU cmdlets or all OS-level hangs.

.PARAMETER WinRMOperationTimeoutSeconds
    WinRM session operation timeout in seconds (default 60). This is not
    a guaranteed wall-clock timeout for every remote call.

.PARAMETER RequireSmbEncryption
    Passes the SMB encryption requirement to the HotfixPlugin. Default true.
    The share must be configured to support the chosen setting.

.EXAMPLE
    # Health checks only; no patch share changes
    .\Invoke-HyperVClusterPatch-v2.ps1 -ClusterName HVCLUS01 -PreCheckOnly

.EXAMPLE
    # Validate and stage approved MSUs, then run CAU scan only
    .\Invoke-HyperVClusterPatch-v2.ps1 -ClusterName HVCLUS01 -SourceFolder D:\Patches\2026-10 -HotfixRoot \\FS01\CAU\HVCLUS01 -ScanOnly

.EXAMPLE
    # Manually authorize patching with a typed cluster-name confirmation
    .\Invoke-HyperVClusterPatch-v2.ps1 -ClusterName HVCLUS01 -SourceFolder D:\Patches\2026-10 -HotfixRoot \\FS01\CAU\HVCLUS01 -ExpectedBuild 26100.XXXX

.NOTES
    STATUS: DEVELOPMENT / LAB TEST REQUIRED.
    CAU readiness rules and scan summary are exported separately. Failed
    rules are warnings in PreCheckOnly, but block scan and patch modes.
    Rule 10 (machine proxy) and Rule 11 (CAU clustered role) require
    operator review; no automatic proxy or clustered-role changes occur.
    A successful CAU scan does not mean every readiness rule passed.
    PowerShell 7 can import clustering commands via WinPSCompatSession; the
    resulting objects may be deserialized. V2 checks property availability
    explicitly and records the preflight phase for diagnosis.

    Prerequisites:
      - Windows PowerShell with FailoverClusters, ClusterAwareUpdating,
        and Hyper-V modules available on the management host.
      - Domain identity with appropriate cluster/node administration rights.
      - WinRM/PowerShell remoting to every cluster node.
      - CAU HotfixPlugin share, permissions, and DefaultHotfixConfig.xml
        configured in advance.
      - Approved and independently verified Server 2025 update packages.
      - Working live migration and sufficient cluster/CSV health.

    SAFETY / LIMITATIONS:
      - PreCheckOnly creates local reports but makes no intended cluster changes.
      - ScanOnly DOES stage files in the CAU share.
      - Existing CAUHotfix_All causes a hard stop; archive it manually.
      - Multiple OS CU files/checkpoint chains are rejected, not sequenced.
      - A Microsoft signature alone does not establish that an MSU is the
        correct approved update for the cluster.
      - Pending reboot detection checks two registry locations only.
      - No unattended scheduling, multi-cluster orchestration, automatic
        forced reboot, or automatic rollback is provided.
      - Report collection is best effort, including on failures.
      - WinRM session timeouts bound remoting operations, but cannot bound every
        CIM, cluster cmdlet, CAU call, or server-side hung operation.
      - CAU command compatibility and post-run success criteria require
        lab verification before any production use.
      - Avoid overlapping patch operations against the same CAU share.

    Expected report files (when corresponding stages are reached):
      transcript.log, nodes-before.csv, cluster-before.json, packages.csv,
      cau-scan.csv (scan), nodes-after.csv, cluster-after.json,
      cau-report.html (patch), cau-readiness-rules.csv,
      cau-readiness-summary.json, error.txt or *-error.txt (on failures).

    Design deliberately retains Microsoft's CAU as the patching engine.
#>

[CmdletBinding(DefaultParameterSetName='Patch')]
param(
 [Parameter(Mandatory)][string]$ClusterName,
 [Parameter(Mandatory,ParameterSetName='Patch')]
 [Parameter(Mandatory,ParameterSetName='Scan')][string]$SourceFolder,
 [Parameter(Mandatory,ParameterSetName='Patch')]
 [Parameter(Mandatory,ParameterSetName='Scan')]
 [ValidatePattern('^\\\\')][string]$HotfixRoot,
 [Parameter(Mandatory,ParameterSetName='Preflight')][switch]$PreCheckOnly,
 [Parameter(Mandatory,ParameterSetName='Scan')][switch]$ScanOnly,
 [Parameter(Mandatory,ParameterSetName='Patch')][string]$ExpectedBuild,
 [string]$ReportFolder=(Join-Path $PSScriptRoot 'PatchReports'),
 [ValidateRange(5,50)][int]$MemoryReservePercent=20,
 [ValidateRange(30,480)][int]$InstallerTimeoutMinutes=120,
 [bool]$RequireSmbEncryption=$true,
 [ValidateRange(5,120)][int]$WinRMConnectTimeoutSeconds=15,
 [ValidateRange(10,300)][int]$WinRMOperationTimeoutSeconds=60
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$reportDir=Join-Path $ReportFolder "$ClusterName-$stamp"
New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
$transcribing=$false
$nodes=@()
$before=@()
$after=@()
$started=$false
$failure=$null
$phase='Initialization'

function Write-Phase([string]$Message) {
 $script:phase=$Message
 Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'),$Message) -ForegroundColor Cyan
}
function Get-PropertyText($Item,[string]$Property,[string]$Context) {
 $p=$Item.PSObject.Properties[$Property]
 if($null -eq $p) {
  throw "Missing property '$Property' in $Context. Object type: $($Item.GetType().FullName); properties: $(($Item.PSObject.Properties.Name) -join ', ')"
 }
 return [string]$p.Value
}
function Assert-Ready([bool]$Condition,[string]$Message) {
 if(-not $Condition) { throw $Message }
}
function Get-NodeSnapshot([string[]]$Names) {
 $results=@()
 foreach($name in $Names) {
  Write-Phase "Remote node inventory: $name"
  try {
   $sessionOption=New-PSSessionOption -OpenTimeout ($WinRMConnectTimeoutSeconds*1000) -OperationTimeout ($WinRMOperationTimeoutSeconds*1000)
   $r=Invoke-Command -ComputerName $name -SessionOption $sessionOption -ErrorAction Stop -ScriptBlock {
    $cv=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $os=Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{
     Node=$env:COMPUTERNAME
     Build=('{0}.{1}' -f $cv.CurrentBuild,$cv.UBR)
     LastBoot=$os.LastBootUpTime
     FreeMemoryBytes=([double]$os.FreePhysicalMemory*1KB)
     PendingReboot=((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'))
    }
   }
   Assert-Ready ($null -ne $r) "No response from $name"
   $results+=($r | Select-Object Node,Build,LastBoot,FreeMemoryBytes,PendingReboot)
  } catch { throw "Remote inventory failed on $name (phase: $script:phase): $_" }
 }
 return @($results)
}
function Get-ClusterHealth([string]$Name) {
 $csv=@(Get-ClusterSharedVolume -Cluster $Name)
 $roles=@(Get-ClusterGroup -Cluster $Name | Where-Object { (Get-PropertyText $_ 'GroupType' 'cluster group') -eq 'VirtualMachine' })
 [pscustomobject]@{
  Timestamp=Get-Date
  Cluster=$Name
  CSVs=@($csv | Select-Object Name,State,OwnerNode)
  VMNotOnline=@($roles | Where-Object { (Get-PropertyText $_ 'State' 'VM cluster group') -ne 'Online' } | Select-Object Name,State,OwnerNode)
  FailedResources=@(Get-ClusterResource -Cluster $Name | Where-Object { (Get-PropertyText $_ 'State' 'cluster resource') -eq 'Failed' } | Select-Object Name,State)
 }
}
function Test-Evacuation([string[]]$Names,[object[]]$Snapshot) {
 # Conservative best-fit free-memory simulation for each possible evacuated node.
 # Affinity, CPU compatibility, migration network and application health need separate review.
 $free=@{}
 $vms=@{}
 foreach($n in $Names) {
  Write-Phase "Hyper-V VM inventory: $n"
  $free[$n]=[double](@($Snapshot | Where-Object Node -eq $n)[0].FreeMemoryBytes)*(1-$MemoryReservePercent/100)
  $vms[$n]=@(Get-VM -ComputerName $n | Where-Object State -eq 'Running')
 }
 foreach($source in $Names) {
  $available=@{}
  foreach($n in $Names) { if($n -ne $source) { $available[$n]=$free[$n] } }
  foreach($vm in @($vms[$source] | Sort-Object MemoryAssigned -Descending)) {
   $target=@($available.Keys | Where-Object { $available[$_] -ge $vm.MemoryAssigned } | Sort-Object { $available[$_] } -Descending | Select-Object -First 1)
   Assert-Ready ($target.Count -gt 0) "Evacuation capacity estimate failed for $source, VM $($vm.Name)"
   $available[$target[0]]-=[double]$vm.MemoryAssigned
  }
 }
}
function Test-Preflight([string]$Name) {
 Write-Phase 'Discovering cluster nodes'
 $clusterNodes=@(Get-ClusterNode -Cluster $Name)
 Assert-Ready ($clusterNodes.Count -ge 3) 'Expected at least three nodes'
 Assert-Ready (@($clusterNodes | Where-Object { (Get-PropertyText $_ 'State' 'cluster node') -ne 'Up' }).Count -eq 0) 'Cluster has a node not Up'
 $script:nodes=@($clusterNodes | ForEach-Object Name)
 Write-Phase 'Checking CSV health'
 $csv=@(Get-ClusterSharedVolume -Cluster $Name)
 Assert-Ready ($csv.Count -gt 0) 'No Cluster Shared Volumes found'
 Assert-Ready (@($csv | Where-Object { (Get-PropertyText $_ 'State' 'CSV') -ne 'Online' }).Count -eq 0) 'CSV not Online'
 Write-Phase 'Checking cluster resources and VM roles'
 $health=Get-ClusterHealth $Name
 Assert-Ready ($health.FailedResources.Count -eq 0) 'Failed cluster resources detected'
 Assert-Ready ($health.VMNotOnline.Count -eq 0) 'A clustered VM role is not Online'
 Write-Phase 'Collecting node health via WinRM'
 $script:before=@(Get-NodeSnapshot -Names $script:nodes)
 Assert-Ready ($script:before.Count -eq $script:nodes.Count) 'Incomplete node inventory'
 Assert-Ready (@($script:before | Where-Object PendingReboot).Count -eq 0) 'Pending reboot detected'
 Write-Phase 'Running Test-CauSetup (may take several minutes)'
 # Test-CauSetup emits CauBpaProgress entries AND a final ArrayList summary.
 # Collect progress separately from summary; never assume all output has State.
 $rawCau=@(Test-CauSetup -ClusterName $Name)
 $ruleResults=@()
 $summaries=@()
 foreach($entry in $rawCau) {
  if($null -eq $entry) { continue }
  if($null -ne $entry.PSObject.Properties['RuleId'] -and
     $null -ne $entry.PSObject.Properties['State']) {
   $ruleResults+=,$entry
   continue
  }
  if($entry -is [System.Collections.IEnumerable] -and $entry -isnot [string]) {
   foreach($nested in $entry) {
    if($null -eq $nested) { continue }
    if($null -ne $nested.PSObject.Properties['RuleId'] -and
       $null -ne $nested.PSObject.Properties['State']) {
     $ruleResults+=,$nested
    } elseif($null -ne $nested.PSObject.Properties['Success']) {
     $summaries+=,$nested
    }
   }
  }
  if($null -ne $entry.PSObject.Properties['Success']) { $summaries+=,$entry }
 }
 $latest=@($ruleResults | Group-Object RuleId | ForEach-Object {
  $_.Group | Select-Object -Last 1
 })
 $cauRows=@($latest | ForEach-Object {
  [pscustomobject]@{
   RuleId=$_.RuleId; Title=$_.Title; State=[string]$_.State
   Severity=[string]$_.Severity
   FailedMachines=([string]::Join(', ',@($_.FailedMachines)))
  }
 })
 $cauRows | Export-Csv (Join-Path $reportDir 'cau-readiness-rules.csv') -NoTypeInformation
 $failedRules=@($cauRows | Where-Object State -eq 'Failed')
 foreach($rule in $failedRules) {
  Write-Warning ("CAU rule {0}: {1}; severity={2}; affected={3}" -f $rule.RuleId,$rule.Title,$rule.Severity,$rule.FailedMachines)
 }
 $scanSuccess=@($summaries | Where-Object { $_.Success -eq $true }).Count -gt 0
 $scanFailed=@($summaries | Where-Object { $_.Success -eq $false }).Count -gt 0
 [pscustomobject]@{
  ScanReportedSuccess=$scanSuccess; ScanReportedFailure=$scanFailed
  RuleCount=$cauRows.Count; FailedRuleCount=$failedRules.Count
  SummaryCount=$summaries.Count
 } | ConvertTo-Json | Set-Content (Join-Path $reportDir 'cau-readiness-summary.json')
 Assert-Ready ($cauRows.Count -gt 0) 'CAU returned no recognizable rule results'
 Assert-Ready (-not $scanFailed) 'CAU setup summary reported failure'
 # Precheck reports findings but does not approve patching. Fail closed on any
 # failed rule in scan/patch mode until the environment has been reviewed.
 if(-not $PreCheckOnly) {
  Assert-Ready ($scanSuccess) 'CAU setup did not report successful completion'
  Assert-Ready ($failedRules.Count -eq 0) 'CAU readiness rules failed. Review cau-readiness-rules.csv before staging or patching.'
 }
 Write-Phase 'Estimating N-1 evacuation capacity'
 Test-Evacuation -Names $script:nodes -Snapshot $script:before
 $health | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $reportDir 'cluster-before.json')
 $script:before | Export-Csv (Join-Path $reportDir 'nodes-before.csv') -NoTypeInformation
}
function Get-ApprovedPackages([string]$Folder) {
 Assert-Ready (Test-Path -LiteralPath $Folder -PathType Container) 'Source folder unavailable'
 $files=@(Get-ChildItem -LiteralPath $Folder -File -Filter '*.msu')
 Assert-Ready ($files.Count -gt 0) 'No MSU packages found'
 $os=@($files | Where-Object Name -match '^windows(10|11)\.0-kb')
 Assert-Ready ($os.Count -eq 1) 'Exactly one OS CU required; checkpoint chains must be handled separately'
 foreach($f in $files) {
  $sig=Get-AuthenticodeSignature -LiteralPath $f.FullName
  Assert-Ready ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation') "Invalid signature: $($f.Name)"
 }
 return @($files)
}
function Stage-ApprovedPackages([object[]]$Files,[string]$Root) {
 Assert-Ready (Test-Path -LiteralPath $Root -PathType Container) 'CAU hotfix root missing'
 Assert-Ready (Test-Path -LiteralPath (Join-Path $Root 'DefaultHotfixConfig.xml')) 'CAU config must be preconfigured'
 $active=Join-Path $Root 'CAUHotfix_All'
 # Fail closed instead of replacing a patch set used by another operation.
 Assert-Ready (-not (Test-Path -LiteralPath $active)) "Active staging folder exists: $active. Archive it manually after review."
 $temporary=Join-Path $Root "CAUStaging-$stamp"
 New-Item -ItemType Directory -Path $temporary | Out-Null
 try {
  foreach($f in $Files) {
   $dest=Join-Path $temporary $f.Name
   Copy-Item -LiteralPath $f.FullName -Destination $dest
   $a=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
   $b=(Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
   Assert-Ready ($a -eq $b) "Hash mismatch: $($f.Name)"
  }
  Rename-Item -LiteralPath $temporary -NewName 'CAUHotfix_All'
 } finally {
  if(Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
 }
}
try {
 Start-Transcript -Path (Join-Path $reportDir 'transcript.log') | Out-Null
 $transcribing=$true
 Write-Phase "PowerShell $($PSVersionTable.PSVersion); importing required modules"
 foreach($module in 'FailoverClusters','ClusterAwareUpdating','Hyper-V') {
  Write-Phase "Importing $module"
  Import-Module $module -ErrorAction Stop
 }
 Write-Phase 'Validating CAU commands'
 foreach($cmd in 'Test-CauSetup','Invoke-CauScan','Invoke-CauRun') {
  Assert-Ready ($null -ne (Get-Command $cmd -ErrorAction SilentlyContinue)) "Missing command: $cmd"
 }
 Test-Preflight $ClusterName
 Write-Host "Preflight passed for $ClusterName ($($nodes.Count) nodes)"
 if(-not $PreCheckOnly) {
  $packages=@(Get-ApprovedPackages $SourceFolder)
  $packages | ForEach-Object { [pscustomobject]@{Name=$_.Name;SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash} } | Export-Csv (Join-Path $reportDir 'packages.csv') -NoTypeInformation
  $pluginArgs=@{HotfixRootFolderPath=$HotfixRoot;RequireSmbEncryption=$RequireSmbEncryption.ToString();HotfixInstallerTimeoutMinutes=$InstallerTimeoutMinutes.ToString()}
  if(-not $ScanOnly) {
   Write-Host "Target cluster $ClusterName; expected build $ExpectedBuild; nodes $($nodes -join ', ')"
   $approval=Read-Host "Type $ClusterName to approve patching"
   Assert-Ready ($approval -ceq $ClusterName) 'Approval not granted'
  }
  Write-Phase 'Staging signed MSUs to CAU share'
  Stage-ApprovedPackages -Files $packages -Root $HotfixRoot
  if($ScanOnly) {
   Write-Phase 'Running CAU scan'
   Invoke-CauScan -ClusterName $ClusterName -CauPluginName Microsoft.HotfixPlugin -CauPluginArguments $pluginArgs | Export-Csv (Join-Path $reportDir 'cau-scan.csv') -NoTypeInformation
  } else {
   $started=$true
   $runParams=@{ClusterName=$ClusterName;CauPluginName='Microsoft.HotfixPlugin';CauPluginArguments=$pluginArgs;MaxRetriesPerNode=1;MaxFailedNodes=0;RequireAllNodesOnline=$true;WarnAfter=(New-TimeSpan -Hours 4);StopAfter=(New-TimeSpan -Hours 8);Force=$true}
   Write-Phase 'Starting CAU patch run'
   Invoke-CauRun @runParams
  }
 }
} catch {
 $failure="Phase '$phase': $($_.ToString())"
 Write-Warning $failure
 $failure | Set-Content (Join-Path $reportDir 'error.txt')
} finally {
 if($nodes.Count -gt 0) {
  try {
   Write-Phase 'Collecting postflight node health'
   $after=@(Get-NodeSnapshot -Names $nodes)
   $after | Export-Csv (Join-Path $reportDir 'nodes-after.csv') -NoTypeInformation
   (Get-ClusterHealth $ClusterName) | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $reportDir 'cluster-after.json')
   if($started -and (@($after | Where-Object Build -ne $ExpectedBuild).Count -gt 0 -or $after.Count -ne $nodes.Count)) {
    if(-not $failure) { $failure="Target build $ExpectedBuild was not verified on all nodes" }
   }
  } catch {
   $_.ToString() | Set-Content (Join-Path $reportDir 'postflight-error.txt')
   if(-not $failure) { $failure=$_.ToString() }
  }
 }
 if($started) {
  try {
   Write-Phase 'Exporting CAU report'
   $cau=Get-CauReport -ClusterName $ClusterName -Last -Detailed
   $cau | Export-CauReport -Format HTML -Path (Join-Path $reportDir 'cau-report.html') -Force
  } catch {
   $_.ToString() | Set-Content (Join-Path $reportDir 'report-error.txt')
   if(-not $failure) { $failure=$_.ToString() }
  }
 }
 if($transcribing) { Stop-Transcript | Out-Null }
}
if($failure) { throw "Review $reportDir : $failure" }
Write-Host "Workflow finished; reports: $reportDir"
