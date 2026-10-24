<#
.SYNOPSIS
    Manually initiated Windows Server 2025 Hyper-V cluster patching using
    Cluster-Aware Updating (CAU), Microsoft.HotfixPlugin, and staged MSU files.

.DESCRIPTION
    Development version 2 for Hyper-V failover clusters using Cluster Shared
    Volumes (CSV). Designed for 3-, 6-, 8-, and 13-node clusters.

    Workflow:
      - ValidateFilesOnly independently checks local MSUs, without CAU.
      - ValidateStagingOnly checks the share and node read access, without CAU.
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
    Required for ValidateFilesOnly, ScanOnly and patch modes; omitted for PreCheckOnly.

.PARAMETER HotfixRoot
    UNC root for Microsoft.HotfixPlugin, containing DefaultHotfixConfig.xml.
    Must be accessible to CAU and cluster nodes, with appropriate permissions.
    The script refuses to overwrite an existing CAUHotfix_All folder.

.PARAMETER PreCheckOnly
    Run cluster readiness checks without staging packages or invoking CAU.
    Report files and a transcript are still written locally.

.PARAMETER ValidateFilesOnly
    Validate locally downloaded MSU files without loading cluster modules,
    contacting nodes, running CAU, or writing to the CAU staging share.
    Requires SourceFolder; ClusterName and HotfixRoot are not needed.
    Creates a packages.csv inventory with PackageType, file size, signature status,
    Microsoft signer, and SHA256 hash. Enforces the existing conservative
    single-OS-package check; this does NOT verify KB applicability or
    checkpoint update prerequisites. The operator must review those.

.PARAMETER ValidateStagingOnly
    Read-only validation of the CAU UNC staging root and per-node access.
    Requires ClusterName and HotfixRoot, but not SourceFolder.
    Checks the share and DefaultHotfixConfig.xml from the management host
    and attempts per-node read checks over WinRM. Remote authentication
    failures are Inconclusive (possible second hop), not proven denial.
    Fails if CAUHotfix_All already exists. Does not test write permissions,
    SMB encryption enforcement, CAU plugin behavior, or update applicability.
    No files are copied to the CAU share and CAU is not invoked.
    Creates staging-validation.csv with Passed, Failed, or Inconclusive
    statuses. Inconclusive is NOT approval to patch; verify directly.

.PARAMETER ScanOnly
    Run preflight, validate/stage MSUs, and invoke CAU scan only.
    Does NOT install patches or reboot nodes, but DOES modify the CAU share.

.PARAMETER CleanupScanStaging
    Optional with ScanOnly. Removes only staging created by this scan after
    successful scan and postflight, and only if package hashes still match.
    Without this switch the staging folder is preserved.

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

.PARAMETER AllowedCauWarningRuleIds
    Optional explicit CAU warning-rule exceptions, for example 10,11.
    Only rules whose latest state is Failed AND severity is Warning may
    be excepted. All failed Error/Critical rules and any other failed
    warning rule still block scan and patch modes. Every exception is
    logged in the CAU readiness CSV and summary JSON. Review Rule 10
    proxy settings and Rule 11 self-updating role relevance first.
    Default: no exceptions. PreCheckOnly never needs exceptions.

.PARAMETER RequireSmbEncryption
    Passes the SMB encryption requirement to the HotfixPlugin. Default true.
    The share must be configured to support the chosen setting.

.EXAMPLE
    # Health checks only; no patch share changes
    .\Invoke-HyperVClusterPatch-v2.ps1 -ClusterName HVCLUS01 -PreCheckOnly

.EXAMPLE
    # Validate downloaded MSUs only; no cluster or CAU share access
    .\Invoke-HyperVClusterPatch-v2.ps1 -SourceFolder D:\Patches\2026-10 -ValidateFilesOnly

.EXAMPLE
    # Read-only check of the CAU staging share from all cluster nodes
    .\Invoke-HyperVClusterPatch-v2.ps1 -ClusterName HVCLUS01 -HotfixRoot \\FS01\CAU\HVCLUS01 -ValidateStagingOnly

.EXAMPLE
    # Validate and stage approved MSUs, then run CAU scan only
    .\Invoke-HyperVClusterPatch-v2.ps1 -ClusterName HVCLUS01 -SourceFolder D:\Patches\2026-10 -HotfixRoot \\FS01\CAU\HVCLUS01 -ScanOnly

.EXAMPLE
    # Manually authorize patching with a typed cluster-name confirmation
    .\Invoke-HyperVClusterPatch-v2.ps1 -ClusterName HVCLUS01 -SourceFolder D:\Patches\2026-10 -HotfixRoot \\FS01\CAU\HVCLUS01 -ExpectedBuild 26100.XXXX

.EXAMPLE
    # After separately verifying warnings 10/11 are acceptable in your environment
    .\Invoke-HyperVClusterPatch-v2.ps1 -ClusterName HVCLUS01 -SourceFolder D:\Patches\2026-10 -HotfixRoot \\FS01\CAU\HVCLUS01 -ScanOnly -AllowedCauWarningRuleIds 10,11

.NOTES
    STATUS: DEVELOPMENT / LAB TEST REQUIRED.
    CAU readiness rules and scan summary are exported separately. Failed
    rules are warnings in PreCheckOnly, but block scan and patch modes.
    Rule 10 (machine proxy) and Rule 11 (CAU clustered role) require
    operator review. To allow only these two warning-level failures for
    a manually initiated, staged-MSU workflow, specify:
      -AllowedCauWarningRuleIds 10,11
    No automatic proxy or clustered-role changes occur.
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
      - ValidateFilesOnly reads local MSUs and writes local reports only.
      - ValidateStagingOnly reads the share and uses WinRM, but makes no
        intended changes to the CAU share or cluster.
      - ScanOnly DOES stage files in the CAU share.
      - Existing CAUHotfix_All causes a hard stop; archive it manually.
      - Multiple OS CU files/checkpoint chains are rejected, not sequenced.
      - Filename-based classification distinguishes Windows OS and .NET Framework
        MSUs; it does not validate update applicability or prerequisites.
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
      staging-validation.csv (staging check),
      cau-scan.csv (scan), nodes-after.csv, cluster-after.json,
      cau-report.html (patch), cau-readiness-rules.csv,
      cau-readiness-summary.json, error.txt or *-error.txt (on failures).

    Design deliberately retains Microsoft's CAU as the patching engine.
#>

[CmdletBinding(DefaultParameterSetName='Patch')]
param(
 [Parameter(Mandatory,ParameterSetName='Patch')]
 [Parameter(Mandatory,ParameterSetName='Scan')]
 [Parameter(Mandatory,ParameterSetName='Preflight')]
 [Parameter(Mandatory,ParameterSetName='Staging')][string]$ClusterName,
 [Parameter(Mandatory,ParameterSetName='Patch')]
 [Parameter(Mandatory,ParameterSetName='Scan')]
 [Parameter(Mandatory,ParameterSetName='Files')][string]$SourceFolder,
 [Parameter(Mandatory,ParameterSetName='Patch')]
 [Parameter(Mandatory,ParameterSetName='Scan')]
 [Parameter(Mandatory,ParameterSetName='Staging')]
 [ValidatePattern('^\\\\')][string]$HotfixRoot,
 [Parameter(Mandatory,ParameterSetName='Preflight')][switch]$PreCheckOnly,
 [Parameter(Mandatory,ParameterSetName='Files')][switch]$ValidateFilesOnly,
 [Parameter(Mandatory,ParameterSetName='Staging')][switch]$ValidateStagingOnly,
 [Parameter(Mandatory,ParameterSetName='Scan')][switch]$ScanOnly,
 [Parameter(ParameterSetName='Scan')][switch]$CleanupScanStaging,
 [Parameter(Mandatory,ParameterSetName='Patch')][string]$ExpectedBuild,
 [string]$ReportFolder=(Join-Path $PSScriptRoot 'PatchReports'),
 [ValidateRange(5,50)][int]$MemoryReservePercent=20,
 [ValidateRange(30,480)][int]$InstallerTimeoutMinutes=120,
 [bool]$RequireSmbEncryption=$true,
 [ValidateRange(5,120)][int]$WinRMConnectTimeoutSeconds=15,
 [ValidateRange(10,300)][int]$WinRMOperationTimeoutSeconds=60,
 [int[]]$AllowedCauWarningRuleIds=@()
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$reportLabel=if($ValidateFilesOnly) { 'LocalMSUValidation' } elseif($ValidateStagingOnly) { "$ClusterName-StagingValidation" } else { $ClusterName }
$reportDir=Join-Path $ReportFolder "$reportLabel-$stamp"
New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
$transcribing=$false
$nodes=@()
$before=@()
$after=@()
$started=$false
$failure=$null
$scanStageOwned=$false
$scanFinished=$false
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
  FailedResources=@(Get-ClusterResource -Cluster $Name | Where-Object { (Get-PropertyText $_ 'State' 'cluster resource') -eq 'Failed' } | Select-Object Name,ResourceType,State,OwnerGroup,OwnerNode)
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
 if($health.FailedResources.Count -gt 0) {
  $details=@($health.FailedResources | ForEach-Object {
   "Resource='$($_.Name)'; Host='$($_.OwnerNode)'; Group='$($_.OwnerGroup)'; Type='$($_.ResourceType)'; State='$($_.State)'"
  }) -join '; '
  Assert-Ready $false "Failed cluster resources detected on $Name : $details"
 }
 # Offline VM roles can represent intentionally powered-off VMs; do not block CAU.
 # Failed cluster resources are checked above independently and remain fatal.
 $offlineRoles=@($health.VMNotOnline | Where-Object { [string]$_.State -eq 'Offline' })
 if($offlineRoles.Count -gt 0) {
  $offlineDetails=@($offlineRoles | ForEach-Object { "VM='$($_.Name)'; Host='$($_.OwnerNode)'; State='$($_.State)'" }) -join '; '
  Write-Warning "Intentionally offline clustered VM roles ($($offlineRoles.Count)) on $Name (verify these are expected): $offlineDetails"
 }
 $unexpectedRoles=@($health.VMNotOnline | Where-Object { [string]$_.State -ne 'Offline' })
 if($unexpectedRoles.Count -gt 0) {
  $unexpectedDetails=@($unexpectedRoles | ForEach-Object { "VM='$($_.Name)'; Host='$($_.OwnerNode)'; State='$($_.State)'" }) -join '; '
  Assert-Ready $false "Clustered VM roles in unexpected states on $Name : $unexpectedDetails"
 }
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
   ExceptionApplied=($null -ne $_.PSObject.Properties['Severity'] -and
    [string]$_.State -eq 'Failed' -and [string]$_.Severity -eq 'Warning' -and
    [int]$_.RuleId -in $AllowedCauWarningRuleIds)
  }
 })
 $cauRows | Export-Csv (Join-Path $reportDir 'cau-readiness-rules.csv') -NoTypeInformation
 $failedRules=@($cauRows | Where-Object State -eq 'Failed')
 foreach($rule in $failedRules) {
  Write-Warning ("CAU rule {0}: {1}; severity={2}; affected={3}" -f $rule.RuleId,$rule.Title,$rule.Severity,$rule.FailedMachines)
 }
 $exceptedRules=@($failedRules | Where-Object ExceptionApplied)
 $blockingRules=@($failedRules | Where-Object { -not $_.ExceptionApplied })
 foreach($rule in $exceptedRules) {
  Write-Warning ("CAU rule {0} explicitly excepted (warning only): {1}" -f $rule.RuleId,$rule.Title)
 }
 $scanSuccess=@($summaries | Where-Object { $_.Success -eq $true }).Count -gt 0
 $scanFailed=@($summaries | Where-Object { $_.Success -eq $false }).Count -gt 0
 [pscustomobject]@{
  ScanReportedSuccess=$scanSuccess; ScanReportedFailure=$scanFailed
  RuleCount=$cauRows.Count; FailedRuleCount=$failedRules.Count
  ExceptedRuleCount=$exceptedRules.Count; BlockingRuleCount=$blockingRules.Count
  AllowedCauWarningRuleIds=@($AllowedCauWarningRuleIds)
  SummaryCount=$summaries.Count
 } | ConvertTo-Json | Set-Content (Join-Path $reportDir 'cau-readiness-summary.json')
 Assert-Ready ($cauRows.Count -gt 0) 'CAU returned no recognizable rule results'
 Assert-Ready (-not $scanFailed) 'CAU setup summary reported failure'
 # Precheck reports findings but does not approve patching. Fail closed on any
 # failed rule in scan/patch mode until the environment has been reviewed.
 if(-not $PreCheckOnly) {
  Assert-Ready ($scanSuccess) 'CAU setup did not report successful completion'
  Assert-Ready ($blockingRules.Count -eq 0) 'Unexcepted CAU readiness rules failed. Review cau-readiness-rules.csv before staging or patching.'
 }
 Write-Phase 'Estimating N-1 evacuation capacity'
 Test-Evacuation -Names $script:nodes -Snapshot $script:before
 $health | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $reportDir 'cluster-before.json')
 $script:before | Export-Csv (Join-Path $reportDir 'nodes-before.csv') -NoTypeInformation
}
function Get-MsuPackageType([string]$Name) {
 # Filename classification only; it does not establish applicability.
 if($Name -match '(?i)-ndp(?:48|481)[^\\/]*\.msu$') { return 'DotNetFramework' }
 if($Name -match '(?i)^windows(?:10|11)\.0-kb\d+-.+\.msu$') { return 'WindowsOS' }
 return 'Unknown'
}
function Get-PackageInventory([object[]]$Files) {
 @($Files | ForEach-Object {
  $signature=Get-AuthenticodeSignature -LiteralPath $_.FullName
  [pscustomobject]@{
   Name=$_.Name
   PackageType=(Get-MsuPackageType $_.Name)
   SizeMB=[math]::Round($_.Length / 1MB,2)
   SignatureStatus=[string]$signature.Status
   Signer=[string]$signature.SignerCertificate.Subject
   SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
  }
 })
}
function Get-ApprovedPackages([string]$Folder) {
 Assert-Ready (Test-Path -LiteralPath $Folder -PathType Container) 'Source folder unavailable'
 $files=@(Get-ChildItem -LiteralPath $Folder -File -Filter '*.msu')
 Assert-Ready ($files.Count -gt 0) 'No MSU packages found'
 $types=@($files | ForEach-Object { Get-MsuPackageType $_.Name })
 Assert-Ready (@($types | Where-Object { $_ -eq 'Unknown' }).Count -eq 0) 'Unrecognized MSU filename; review package type before proceeding'
 Assert-Ready (@($types | Where-Object { $_ -eq 'WindowsOS' }).Count -eq 1) 'Exactly one OS CU required; checkpoint chains must be handled separately'
 foreach($f in $files) {
  $sig=Get-AuthenticodeSignature -LiteralPath $f.FullName
  Assert-Ready ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation') "Invalid signature: $($f.Name)"
 }
 return @($files)
}
function Test-StagingReadiness([string]$Name,[string]$Root) {
 # A remoted user's SMB access is not proof of the CAU plugin's execution identity.
 # In particular, a WinRM second hop can produce Access Denied.
 Write-Phase 'Checking CAU share from management host (read-only)'
 $results=@()
 $checks=@(
  @{ Label='Root'; Path=$Root; Type='Container' },
  @{ Label='Config'; Path=(Join-Path $Root 'DefaultHotfixConfig.xml'); Type='Leaf' },
  @{ Label='Active'; Path=(Join-Path $Root 'CAUHotfix_All'); Type='Any' }
 )
 $localValues=@{}
 $localError=''
 foreach($check in $checks) {
  try {
   $localValues[$check.Label]=if($check.Type -eq 'Any') { Test-Path -LiteralPath $check.Path -ErrorAction Stop } else { Test-Path -LiteralPath $check.Path -PathType $check.Type -ErrorAction Stop }
  } catch { $localError=[string]$_; break }
 }
 $localStatus=if($localError) { 'Failed' } elseif(-not $localValues.Root -or -not $localValues.Config -or $localValues.Active) { 'Failed' } else { 'Passed' }
 $results+= [pscustomobject]@{
  Computer=$env:COMPUTERNAME; Scope='ManagementHost'; Status=$localStatus
  RootAccessible=[bool]$localValues.Root; ConfigAccessible=[bool]$localValues.Config
  ActiveFolderExists=[bool]$localValues.Active; Error=$localError
  Note='Checks current management identity; no writes performed'
 }
 Write-Phase 'Discovering cluster nodes for staging access'
 $clusterNodes=@(Get-ClusterNode -Cluster $Name)
 Assert-Ready ($clusterNodes.Count -gt 0) 'No cluster nodes returned'
 foreach($node in $clusterNodes) {
  $nodeName=[string]$node.Name
  Write-Phase "Checking read access from $nodeName"
  try {
   $sessionOption=New-PSSessionOption -OpenTimeout ($WinRMConnectTimeoutSeconds*1000) -OperationTimeout ($WinRMOperationTimeoutSeconds*1000)
   $result=Invoke-Command -ComputerName $nodeName -SessionOption $sessionOption -ArgumentList $Root -ErrorAction Stop -ScriptBlock {
    param([string]$ShareRoot)
    $rootOk=$false; $configOk=$false; $active=$false; $errorText=''
    try {
     $rootOk=Test-Path -LiteralPath $ShareRoot -PathType Container -ErrorAction Stop
     if($rootOk) {
      $configOk=Test-Path -LiteralPath (Join-Path $ShareRoot 'DefaultHotfixConfig.xml') -PathType Leaf -ErrorAction Stop
      $active=Test-Path -LiteralPath (Join-Path $ShareRoot 'CAUHotfix_All') -ErrorAction Stop
     }
    } catch { $errorText=[string]$_ }
    [pscustomobject]@{
     Computer=$env:COMPUTERNAME; RootAccessible=$rootOk
     ConfigAccessible=$configOk; ActiveFolderExists=$active; Error=$errorText
    }
   }
   if($null -eq $result) { throw "No response from $nodeName" }
   $errorText=[string]$result.Error
   # A false Test-Path on a remote UNC path may conceal authentication errors.
   # Do not assert a genuine permission failure or successful access without evidence.
   $status=if($result.RootAccessible -and $result.ConfigAccessible -and -not $result.ActiveFolderExists -and -not $errorText) {
    'Passed'
   } elseif($result.RootAccessible -and $result.ActiveFolderExists) {
    'Failed'
   } elseif($result.RootAccessible -and -not $result.ConfigAccessible -and -not $errorText) {
    'Failed'
   } else { 'Inconclusive' }
   $note=if($status -eq 'Inconclusive') { 'Remote UNC access not verified; WinRM second-hop or permissions may be involved. Verify directly on node.' } else { 'Remote read check only; CAU identity not tested' }
   $results+= [pscustomobject]@{
    Computer=$nodeName;Scope='RemoteWinRM';Status=$status
    RootAccessible=[bool]$result.RootAccessible;ConfigAccessible=[bool]$result.ConfigAccessible
    ActiveFolderExists=[bool]$result.ActiveFolderExists;Error=$errorText;Note=$note
   }
  } catch {
   $results+= [pscustomobject]@{
    Computer=$nodeName;Scope='RemoteWinRM';Status='Inconclusive'
    RootAccessible=$false;ConfigAccessible=$false;ActiveFolderExists=$false
    Error=[string]$_
    Note='Remote check failed; may be WinRM authentication or transport. Verify directly on node.'
   }
  }
 }
 $results | Export-Csv (Join-Path $reportDir 'staging-validation.csv') -NoTypeInformation
 $results | Format-Table Computer,Scope,Status,RootAccessible,ConfigAccessible,ActiveFolderExists -AutoSize | Out-Host
 $failed=@($results | Where-Object Status -eq 'Failed')
 $inconclusive=@($results | Where-Object Status -eq 'Inconclusive')
 if($failed.Count -gt 0) { throw 'Staging checks failed. Review staging-validation.csv' }
 if($inconclusive.Count -gt 0) {
  Write-Warning "$($inconclusive.Count) node check(s) inconclusive. Verify share access directly on each node and under the CAU execution identity before patching. Review staging-validation.csv."
 }
 Write-Warning 'Read-only checks do NOT verify staging write permissions, SMB encryption, or CAU plugin execution identity.'
}
function Test-CauSharePermissions([string]$Root) {
 # This check is deliberately read-only. It requires the share to be hosted locally.
 $unc=[regex]::Match($Root,'^\\\\([^\\]+)\\([^\\]+)(?:\\|$)')
 Assert-Ready $unc.Success "Invalid CAU share path: $Root"
 $server=$unc.Groups[1].Value
 $shareName=$unc.Groups[2].Value
 Assert-Ready ($server -ieq $env:COMPUTERNAME) "Cannot inspect remote share ACLs for $server from this host; refusing to stage."
 $share=Get-SmbShare -Name $shareName -ErrorAction Stop
 $shareAcl=@(Get-SmbShareAccess -Name $shareName -ErrorAction Stop)
 $folderAcl=(Get-Acl -LiteralPath $share.Path -ErrorAction Stop).Access
 $trusted=@('BUILTIN\Administrators','NT AUTHORITY\SYSTEM')
 $broad=@('Everyone','NT AUTHORITY\Everyone','NT AUTHORITY\Authenticated Users','BUILTIN\Users')
 $unsafeShare=@($shareAcl | Where-Object {
  $_.AccessControlType -eq 'Allow' -and $_.AccessRight -ne 'Read' -and $_.AccountName -notin $trusted
 })
 # WriteData, AppendData, WriteAttributes, WriteExtendedAttributes, Delete,
 # ChangePermissions and TakeOwnership all grant potentially dangerous control.
  # Composite Modify includes read bits. Check individual write-capable flags only.
  $writeRights=[System.Security.AccessControl.FileSystemRights]::WriteData -bor
   [System.Security.AccessControl.FileSystemRights]::AppendData -bor
   [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
   [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
   [System.Security.AccessControl.FileSystemRights]::Delete -bor
   [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
   [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
   [System.Security.AccessControl.FileSystemRights]::TakeOwnership
 $writers=@($folderAcl | Where-Object {
  $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notin $trusted -and
  (($_.FileSystemRights -band $writeRights) -ne 0)
 })
 $broadWriters=@($writers | Where-Object { $_.IdentityReference.Value -in $broad -or
  $_.IdentityReference.Value -match '^S-1-1-0$|^S-1-5-11$|^S-1-5-32-545$' })
 $namedWriters=@($writers | Where-Object { $_.IdentityReference.Value -notin $broad -and
  $_.IdentityReference.Value -notmatch '^S-1-1-0$|^S-1-5-11$|^S-1-5-32-545$' })
 $shareAcl | Select-Object AccountName,AccessControlType,AccessRight |
  Export-Csv (Join-Path $reportDir 'cau-share-acl.csv') -NoTypeInformation
 $folderAcl | Select-Object IdentityReference,AccessControlType,FileSystemRights,IsInherited |
  Export-Csv (Join-Path $reportDir 'cau-ntfs-acl.csv') -NoTypeInformation
 Assert-Ready ($unsafeShare.Count -eq 0) 'CAU SMB share has unexpected write permissions. Review cau-share-acl.csv.'
 # The hotfix share needs Read on BOTH SMB and NTFS; a share-only Read ACE is not enough.
 $authSid='S-1-5-11'
 $authNames=@('NT AUTHORITY\Authenticated Users',$authSid)
 $authShareRead=@($shareAcl | Where-Object {
  $_.AccountName -in $authNames -and $_.AccessControlType -eq 'Allow' -and
  $_.AccessRight -in @('Read','Change','Full')
 })
 $authNtfsRead=@($folderAcl | Where-Object {
  $_.IdentityReference.Value -in $authNames -and $_.AccessControlType -eq 'Allow' -and
  (($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadAndExecute) -eq
   [System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
 })
 $authDeny=@($shareAcl | Where-Object {
  $_.AccountName -in $authNames -and $_.AccessControlType -eq 'Deny'
 })
 $authDeny+=@($folderAcl | Where-Object {
  $_.IdentityReference.Value -in $authNames -and $_.AccessControlType -eq 'Deny'
 })
 Assert-Ready ($authShareRead.Count -gt 0 -and $authDeny.Count -eq 0) 'CAU SMB share must allow Authenticated Users Read without an explicit Deny. Review cau-share-acl.csv.'
 Assert-Ready ($authNtfsRead.Count -gt 0) 'CAU NTFS root must allow Authenticated Users ReadAndExecute. Review cau-ntfs-acl.csv.'
 Assert-Ready ($broadWriters.Count -eq 0) 'CAU NTFS folder grants write permissions to a broad group. Review cau-ntfs-acl.csv.'
 if($namedWriters.Count -gt 0) {
  $names=(@($namedWriters | ForEach-Object { $_.IdentityReference.Value } | Select-Object -Unique) -join ', ')
  Write-Warning "Additional CAU NTFS write account(s): $names. Verify these accounts are authorized. Review cau-ntfs-acl.csv."
  if(-not $ScanOnly) {
   $ack=Read-Host 'Type ACKNOWLEDGE to accept these NTFS permissions and continue'
   Assert-Ready ($ack -ceq 'ACKNOWLEDGE') 'CAU NTFS permission warning not acknowledged; patching stopped.'
  }
 } else {
  Write-Host 'CAU share and NTFS write-permission precheck passed.'
 }
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
  if($ScanOnly) { $script:scanStageOwned=$true }
 } finally {
  if(Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
 }
}
try {
 Start-Transcript -Path (Join-Path $reportDir 'transcript.log') | Out-Null
 $transcribing=$true
 if($ValidateFilesOnly) {
  Write-Phase 'Validating local MSU files only (no cluster or CAU access)'
  $packages=@(Get-ApprovedPackages $SourceFolder)
  $rows=@(Get-PackageInventory -Files $packages)
  $rows | Export-Csv (Join-Path $reportDir 'packages.csv') -NoTypeInformation
  Write-Host "Validated $($rows.Count) MSU file(s); report: $reportDir"
 } elseif($ValidateStagingOnly) {
  Write-Phase 'Validating CAU staging share only (read-only)'
  Import-Module FailoverClusters -ErrorAction Stop
  Test-StagingReadiness -Name $ClusterName -Root $HotfixRoot
 } else {
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
  Get-PackageInventory -Files $packages | Export-Csv (Join-Path $reportDir 'packages.csv') -NoTypeInformation
  $pluginArgs=@{HotfixRootFolderPath=$HotfixRoot;RequireSmbEncryption=$RequireSmbEncryption.ToString();HotfixInstallerTimeoutMinutes=$InstallerTimeoutMinutes.ToString()}
  if(-not $ScanOnly) {
   Write-Host "Target cluster $ClusterName; expected build $ExpectedBuild; nodes $($nodes -join ', ')"
   $approval=Read-Host "Type $ClusterName to approve patching"
   Assert-Ready ($approval -ceq $ClusterName) 'Approval not granted'
  }
  Write-Phase 'Validating CAU share permissions'
  Test-CauSharePermissions -Root $HotfixRoot
  Write-Phase 'Staging signed MSUs to CAU share'
  Stage-ApprovedPackages -Files $packages -Root $HotfixRoot
  if($ScanOnly) {
   Write-Phase 'Running CAU scan'
   # Preserve original CAU objects before flattening them for CSV.
   $scanResults = @(Invoke-CauScan -ClusterName $ClusterName -CauPluginName Microsoft.HotfixPlugin -CauPluginArguments $pluginArgs -ErrorAction Stop)
   $scanResults | Export-Clixml (Join-Path $reportDir 'cau-scan-raw.clixml')
   $metadataNames = @('PSComputerName','RunspaceId','PSShowComputerName')
   $scanRows = @(
    foreach($item in $scanResults) {
     if($null -eq $item) { continue }
     $fields = [ordered]@{ ObjectType = [string]($item.PSObject.TypeNames | Select-Object -First 1) }
     foreach($property in $item.PSObject.Properties) {
      if($property.Name -in $metadataNames) { continue }
      if($property.MemberType -notin @('NoteProperty','Property','AliasProperty','ScriptProperty')) { continue }
      try {
       $value = $property.Value
       if($null -eq $value) { $fields[$property.Name] = '' }
       elseif($value -is [string] -or $value -is [ValueType]) { $fields[$property.Name] = [string]$value }
       else { $fields[$property.Name] = ($value | ConvertTo-Json -Depth 8 -Compress) }
      } catch { $fields[$property.Name] = "[Property read failed: $($_.Exception.Message)]" }
     }
     if($fields.Count -gt 1) { [pscustomobject]$fields }
    }
   )
   if($scanRows.Count -eq 0) {
    throw 'CAU scan returned no usable fields (only remoting metadata or empty output). Raw results saved as cau-scan-raw.clixml; scan NOT verified.'
   }
   # Different CAU result types can expose different property sets.
   $columns = @('ObjectType') + @($scanRows | ForEach-Object { $_.PSObject.Properties.Name } | Where-Object { $_ -ne 'ObjectType' } | Select-Object -Unique)
   $scanRows | Select-Object -Property $columns | Export-Csv (Join-Path $reportDir 'cau-scan.csv') -NoTypeInformation
   Write-Host "CAU scan returned $($scanResults.Count) object(s); exported $($scanRows.Count) rows. Review cau-scan.csv before patching."
   $scanFinished=$true
  } else {
   $started=$true
   $runParams=@{ClusterName=$ClusterName;CauPluginName='Microsoft.HotfixPlugin';CauPluginArguments=$pluginArgs;MaxRetriesPerNode=1;MaxFailedNodes=0;StopOnPluginFailure=$true;RequireAllNodesOnline=$true;WarnAfter=(New-TimeSpan -Hours 4);StopAfter=(New-TimeSpan -Hours 8)}
   Write-Phase 'Starting CAU patch run'
   Invoke-CauRun @runParams
  }
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
 if($ScanOnly -and $CleanupScanStaging -and $scanStageOwned) {
  $active=Join-Path $HotfixRoot 'CAUHotfix_All'
  if(-not $scanFinished -or $failure) {
   Write-Warning "Scan not fully successful; preserving staging: $active"
  } else {
   try {
    $staged=@(Get-ChildItem -LiteralPath $active -Force -ErrorAction Stop)
    Assert-Ready ($staged.Count -eq $packages.Count) 'Staging contents changed; cleanup refused.'
    foreach($pkg in $packages) {
     $dest=Join-Path $active $pkg.Name
     Assert-Ready (Test-Path -LiteralPath $dest -PathType Leaf) "Staging file missing: $($pkg.Name)"
     Assert-Ready ((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $pkg.FullName -Algorithm SHA256).Hash) "Staging hash changed: $($pkg.Name)"
    }
    Write-Phase 'Cleaning verified scan-only staging'
    Remove-Item -LiteralPath $active -Recurse -Force -ErrorAction Stop
    Write-Host "Removed scan-only staging: $active"
   } catch {
    $cleanupError="Scan staging cleanup not completed: $_"
    Write-Warning $cleanupError
    $cleanupError | Set-Content (Join-Path $reportDir 'cleanup-error.txt')
    if(-not $failure) { $failure=$cleanupError }
   }
  }
 }
 if($transcribing) { Stop-Transcript | Out-Null }
}
if($failure) { throw "Review $reportDir : $failure" }
Write-Host "Workflow finished; reports: $reportDir"
