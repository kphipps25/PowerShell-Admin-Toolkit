<#
.SYNOPSIS
  Development v2 for manually initiated Windows Server 2025 Hyper-V CSV cluster CAU.
.NOTES
  LAB TEST REQUIRED. Supports preflight, staging, scan and manual CAU execution.
  Deliberately rejects checkpoint chains and refuses to replace active staging.
  Does not guarantee migration placement or application-level health.
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
 [bool]$RequireSmbEncryption=$true
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

function Assert-Ready([bool]$Condition,[string]$Message) {
 if(-not $Condition) { throw $Message }
}
function Get-NodeSnapshot([string[]]$Names) {
 $results=@()
 foreach($name in $Names) {
  try {
   $r=Invoke-Command -ComputerName $name -ErrorAction Stop -ScriptBlock {
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
  } catch { throw "Remote inventory failed on $name : $_" }
 }
 return @($results)
}
function Get-ClusterHealth([string]$Name) {
 $csv=@(Get-ClusterSharedVolume -Cluster $Name)
 $roles=@(Get-ClusterGroup -Cluster $Name | Where-Object GroupType -eq 'VirtualMachine')
 [pscustomobject]@{
  Timestamp=Get-Date
  Cluster=$Name
  CSVs=@($csv | Select-Object Name,State,OwnerNode)
  VMNotOnline=@($roles | Where-Object State -ne 'Online' | Select-Object Name,State,OwnerNode)
  FailedResources=@(Get-ClusterResource -Cluster $Name | Where-Object State -eq 'Failed' | Select-Object Name,State)
 }
}
function Test-Evacuation([string[]]$Names,[object[]]$Snapshot) {
 # Conservative best-fit free-memory simulation for each possible evacuated node.
 # Affinity, CPU compatibility, migration network and application health need separate review.
 $free=@{}
 $vms=@{}
 foreach($n in $Names) {
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
 $clusterNodes=@(Get-ClusterNode -Cluster $Name)
 Assert-Ready ($clusterNodes.Count -ge 3) 'Expected at least three nodes'
 Assert-Ready (@($clusterNodes | Where-Object State -ne 'Up').Count -eq 0) 'Cluster has a node not Up'
 $script:nodes=@($clusterNodes | ForEach-Object Name)
 $csv=@(Get-ClusterSharedVolume -Cluster $Name)
 Assert-Ready ($csv.Count -gt 0) 'No Cluster Shared Volumes found'
 Assert-Ready (@($csv | Where-Object State -ne 'Online').Count -eq 0) 'CSV not Online'
 $health=Get-ClusterHealth $Name
 Assert-Ready ($health.FailedResources.Count -eq 0) 'Failed cluster resources detected'
 Assert-Ready ($health.VMNotOnline.Count -eq 0) 'A clustered VM role is not Online'
 $script:before=@(Get-NodeSnapshot -Names $script:nodes)
 Assert-Ready ($script:before.Count -eq $script:nodes.Count) 'Incomplete node inventory'
 Assert-Ready (@($script:before | Where-Object PendingReboot).Count -eq 0) 'Pending reboot detected'
 $test=@(Test-CauSetup -ClusterName $Name)
 Assert-Ready (@($test | Where-Object State -eq 'Failed').Count -eq 0) 'CAU setup failed'
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
 foreach($module in 'FailoverClusters','ClusterAwareUpdating','Hyper-V') { Import-Module $module -ErrorAction Stop }
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
  Stage-ApprovedPackages -Files $packages -Root $HotfixRoot
  if($ScanOnly) {
   Invoke-CauScan -ClusterName $ClusterName -CauPluginName Microsoft.HotfixPlugin -CauPluginArguments $pluginArgs | Export-Csv (Join-Path $reportDir 'cau-scan.csv') -NoTypeInformation
  } else {
   $started=$true
   $runParams=@{ClusterName=$ClusterName;CauPluginName='Microsoft.HotfixPlugin';CauPluginArguments=$pluginArgs;MaxRetriesPerNode=1;MaxFailedNodes=0;RequireAllNodesOnline=$true;WarnAfter=(New-TimeSpan -Hours 4);StopAfter=(New-TimeSpan -Hours 8);Force=$true}
   Invoke-CauRun @runParams
  }
 }
} catch {
 $failure=$_.ToString()
 Write-Warning $failure
 $failure | Set-Content (Join-Path $reportDir 'error.txt')
} finally {
 if($nodes.Count -gt 0) {
  try {
   $after=@(Get-NodeSnapshot -Names $nodes)
   $after | Export-Csv (Join-Path $reportDir 'nodes-after.csv') -NoTypeInformation
   (Get-ClusterHealth $ClusterName) | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $reportDir 'cluster-after.json')
   if($started -and (@($after | Where-Object Build -ne $ExpectedBuild).Count -gt 0 -or $after.Count -ne $nodes.Count)) {
    $failure="Target build $ExpectedBuild was not verified on all nodes"
   }
  } catch {
   $_.ToString() | Set-Content (Join-Path $reportDir 'postflight-error.txt')
   if(-not $failure) { $failure=$_.ToString() }
  }
 }
 if($started) {
  try {
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
