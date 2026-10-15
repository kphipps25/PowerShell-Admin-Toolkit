# Hyper-V Cluster-Aware Updating

Development branch for Windows Server 2025 Hyper-V failover cluster patching.

## Scope
- Cluster sizes: 3, 6, 8, and 13 nodes
- Cluster Shared Volumes (CSV)
- Manually initiated patching, one cluster per run
- Microsoft.HotfixPlugin using preapproved MSU packages
- One-node-at-a-time CAU orchestration

## Planned files
- `Invoke-HyperVClusterPatch-v1.ps1`: exact original supplied script, unchanged
- `Invoke-HyperVClusterPatch-v2.ps1`: revised script with preflight, safe staging, CAU execution, postflight and reporting

## Safety
**Do not use for production patching until the scripts have been committed, reviewed, and lab-tested.**

Key v2 acceptance criteria: fail-closed preflight; CSV and VM checks; per-node evacuation feasibility; checkpoint update prerequisite validation; no forced reboot on WinRM timeout; reporting on failure; explicit typed confirmation before patching.
