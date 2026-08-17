---
slug: refactor-delete-candidates
status: awaiting-approval
intent: unclear
review_required: true
plan_path: .omo/plans/refactor-delete-candidates.md
plan_sha256: null
review_round_id: null
pending-action: write and review .omo/plans/refactor-delete-candidates.md
review:
  momus:
    status: pending
    workspace_root: null
    runtime_home: null
    target: .omo/plans/refactor-delete-candidates.md
    round_id: null
    plan_sha256: null
    launch_id: null
    session: null
    result: null
  independent:
    status: pending
    workspace_root: null
    runtime_home: null
    target: .omo/plans/refactor-delete-candidates.md
    round_id: null
    plan_sha256: null
    launch_id: null
    session: null
    result: null
approach: 两波执行：Wave A 零风险删除（孤儿目录+死代码+tests/bin清理），Wave B 浅层重构（合并归档扫描器+外部化硬编码配置+签名统一+命名修复）；ViewModel 拆分因改动面大暂不纳入本计划。
---

# Draft: refactor-delete-candidates

## Components (topology ledger)
| id | outcome | status | evidence |
|----|---------|--------|----------|
| C1 | 删除三个已提交的构建产物孤儿目录 | active | Xdows-Driver/ (33 files, bin/obj only), Xdows-Driver-Caller/ (19 files, obj only), ZipDiag/ (24 files, bin/obj only) — 真实驱动在 ../Xdows-Security-Driver |
| C2 | 删除四处死代码模块/方法 | active | DllScan.cs (0 callers), QuarantineManager.CalculateFileHashAsync (private unused), TrustManagerHelper.CreateTrustItemJson (0 callers), Core.ScanAsync (fake async) |
| C3 | 清理 tests/bin/ 中的第三方 DLL 提交物 | active | tests/.../bin/Release/ 包含 ~50+ 第三方 DLL 和 .source 文件 |
| C4 | 合并 ZipScanner 写入方法到 ArchiveScanner，删除 ZipScanner | active | SecurityPage.xaml.cs 调用 ZipScanner 3 次（line 681, 714, 2505）|
| C5 | 外部化 ScanEngine.cs 硬编码云扫描端点和 API key 到 LocalSettings | active | Helper/ScanEngine.cs:10-12 |
| C6 | 修复 DriverInstaller.FindAsset 中 D:\Code\ 硬编码开发路径 | active | Protection/DriverInstaller.cs:167-175, 188 |
| C7 | 重命名 Helper.Linker.CallBack.InterceptCallBack 消除歧义 | active | 与 Protection.CallBack.InterceptCallBack 签名不同 |
| C8 | Core.ScanAsync 改名 Core.Scan，删除假 async 方法 | active | Xdows-Local/Core.cs:42 |
| C9 | 确认并删除冗余根目录 JsonContext.cs | active | 与 Views/JsonContext.cs (BugReportJsonContext) 功能重叠 |

## Open assumptions (announced defaults)
| assumption | adopted default | rationale | reversible? |
|-----------|----------------|-----------|-------------|
| ViewModel 拆分不在本计划内 | 暂不拆分 SecurityPage/SettingsPage | 两个文件合计 5000+ 行，涉及大量 x:Bind 绑定，属于独立大型重构 | yes |
| ZipScanner 桥接策略 | 在 ArchiveScanner 中新增 zip 写入/删除方法，保持相同接口签名 | 最小化 SecurityPage 改动量 | yes |
| 硬编码配置迁移到 LocalSettings | 与现有 ModelMode 等设置一致 | 已有模式可循 | yes |
| InterceptCallBack 重命名而非统一 | 保留两个不同签名，重命名 Helper 版为 TcpInterceptCallBack | 语义不同，强制统一破坏契约 | yes |
| Core.ScanAsync → Core.Scan | 删除假 async 包装 | 消除误导，调用方无需逻辑变更 | yes |
| 删除 Xdows-Local-Caller 项目 | 纯 pass-through CLI，62 行 | 无独立价值 | yes |

## Findings (cited - path:lines)
See plan for full citations. Key evidence:
- C1: Xdows-Driver/ (33 bin/obj files), Xdows-Driver-Caller/ (19 obj files), ZipDiag/ (24 bin/obj files, .NET 8.0)
- C2: DllScan.cs 0 callers; QuarantineManager.CalculateFileHashAsync private unused; CreateTrustItemJson 0 callers; Core.ScanAsync line 42
- C4: ZipScanner called at SecurityPage.xaml.cs:681,714,2505
- C5: ScanEngine.cs:10-12 hardcoded IPs and API key
- C6: DriverInstaller.cs:167-175,188 hardcoded D:\Code\ paths
- C7: Protection/CallBack.cs:7 vs Helper/Linker.cs:13
- C8: Core.cs:42 ScanAsync => Scan pass-through
- C9: Root JsonContext.cs vs Views/JsonContext.cs (BugReportJsonContext)

## Decisions (with rationale)
1. ViewModel 拆分推迟 — 独立大型重构
2. ZipScanner 桥接到 ArchiveScanner — 最小化改动
3. LocalSettings 为配置载体 — 与现有模式一致
4. InterceptCallBack 重命名 — 语义不同
5. Core.ScanAsync → Core.Scan — 消除误导
6. 删除 Xdows-Local-Caller — 纯 pass-through

## Scope IN
- Delete Xdows-Driver/, Xdows-Driver-Caller/, ZipDiag/ directories
- Delete DllScan.cs, QuarantineManager.CalculateFileHashAsync, TrustManagerHelper.CreateTrustItemJson
- Clean tests/bin/ and tests/obj/ committed artifacts
- Add zip write/delete methods to ArchiveScanner, update SecurityPage callers, delete ZipScanner.cs
- Externalize ScanEngine.cs cloud endpoints + API key to LocalSettings
- Fix DriverInstaller.FindAsset hardcoded D:\Code\ paths
- Rename Helper.Linker.CallBack.InterceptCallBack → TcpInterceptCallBack
- Rename Core.ScanAsync → Core.Scan, delete fake async method
- Delete Xdows-Local-Caller project
- Confirm and remove redundant root JsonContext.cs

## Scope OUT (Must NOT have)
- Do NOT split SecurityPage.xaml.cs or SettingsPage.xaml.cs into ViewModels
- Do NOT modify Protection/DriverProtocol.cs or cross-repo protocol
- Do NOT add unit tests
- Do NOT modify .gitignore structure

## Open questions
None — all forks resolved by evidence and best-practice defaults.

## Approval gate
status: approved
<!-- User 2026-08-17 approved execution of Wave A (deletion) + Wave B (refactor) and requested 10 feature-granularity large refactor/delete candidates.
     This turn is now the EXECUTION turn. The 10 candidates are enumerated below and recorded in the plan. -->
<!-- 10 LARGE-SCALE FEATURE CANDIDATES (feature granularity, for future planning):
  L1. Deprecate the 4 Legacy* fallback protection models (LegacyProcess 147L, LegacyFiles 154L, LegacyRegistryProtection 372L, LegacyBootProtection 1286L) — crude PID-polling & FileSystemWatcher, overlap the driver path. Delete or gate behind a feature flag.
  L2. Split App.xaml.cs (1104L) — currently mixes bootstrap, single-instance, Updater, ProtectionStatus coordinator, Statistics. Extract Updater (lines 41-~150) and ProtectionStatus coordinator.
  L3. Split SecurityPage.xaml.cs (2781L) — the scan orchestrator. Extract the shared RunScansOnFileAsync + ScanResult (per CONTEXT.md) into a ScanCoordinator module; extract virus-row handling & archive operations.
  L4. Split SettingsPage.xaml.cs (1757L) — settings UI. Extract protection-state polling (DispatcherTimer + UpdateDriverProtectionState) into a ProtectionStatusViewModel.
  L5. Extract the InterceptWindow feature (InterceptWindow.xaml.cs 467L + Helper/Linker.cs 136L + InterceptWindowHelper.cs) into a self-contained interception module with a defined seam.
  L6. Extract the BugReport feature (BugReportPage.xaml.cs + Messages.cs 525L + Dialogs.cs + Connection.cs) into an independent module.
  L7. Split ProcessManagerView (xaml.cs 1596L + AdvancedKill.cs 725L) — the process-manager plugin. Extract process list/refresh from kill logic.
  L8. Replace FileSystemWatcher-based LegacyFilesProtection with a real userland filesystem monitor, or fold into the driver path and delete.
  L9. Rebuild the tests project — currently a source-text-scanning harness (Program.cs reads .cs files and greps for patterns). Add behavioral tests for Xdows-Local scan engines.
  L10. Consolidate the two protection decision paths (DriverProtection 2000+ lines vs the Legacy* models) behind one ProtectionCoordinator interface so the driver/legacy choice is a single seam.
-->
