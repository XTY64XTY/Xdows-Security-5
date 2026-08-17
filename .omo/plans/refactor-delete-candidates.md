# refactor-delete-candidates - Work Plan

## TL;DR (For humans)

**What you'll get:** 删除 3 个孤儿目录（纯构建产物、源码在兄弟仓库）、4 处死代码、tests/bin 里提交的第三方 DLL；合并两个重复的归档扫描器（ZipScanner + ArchiveScanner）为一个；把硬编码的云扫描 IP/API key 和开发机 `D:\Code\` 路径改成可配置；消除 `InterceptCallBack` 命名冲突；删除一个假的 `async` 方法和一个纯透传的 CLI 项目。最终得到一个更干净、更安全、可移植的代码库。

**另外交付 10 个大型重构/删除候选（以功能为单位，供未来规划）：**
- L1. 淘汰 4 个 Legacy* 回退保护模型（LegacyProcess 147行 / LegacyFiles 154行 / LegacyRegistryProtection 372行 / LegacyBootProtection 1286行）— 粗陋的 PID 轮询 + FileSystemWatcher，与驱动路径重叠
- L2. 拆分 App.xaml.cs（1104行）— 混合了启动引导、单实例、Updater、ProtectionStatus 协调器、Statistics
- L3. 拆分 SecurityPage.xaml.cs（2781行）— 提取共享的 RunScansOnFileAsync + ScanResult 为 ScanCoordinator 模块
- L4. 拆分 SettingsPage.xaml.cs（1757行）— 提取保护状态轮询（DispatcherTimer + UpdateDriverProtectionState）为 ProtectionStatusViewModel
- L5. 提取 InterceptWindow 功能（InterceptWindow.xaml.cs 467行 + Helper/Linker.cs + InterceptWindowHelper.cs）为独立拦截模块
- L6. 提取 BugReport 功能（BugReportPage + Messages.cs 525行 + Dialogs.cs + Connection.cs）为独立模块
- L7. 拆分 ProcessManagerView（xaml.cs 1596行 + AdvancedKill.cs 725行）— 提取进程列表/刷新与终止逻辑
- L8. 用真正的用户态文件系统监控替换 FileSystemWatcher 版 LegacyFilesProtection，或并入驱动路径后删除
- L9. 重建 tests 项目 — 当前是源码文本扫描（Program.cs 读 .cs 文件做 grep），改为 Xdows-Local 扫描引擎的行为测试
- L10. 将两条保护决策路径（DriverProtection 2000+行 vs Legacy* 模型）统一到单一 ProtectionCoordinator 接口

**Why this approach:** 删除类改动零功能风险（复杂度直接归零），重构类全部保持接口签名不变（调用方无需改动）。拆成两波：先做无风险的删除，再做浅层重构，每波独立可验证，出问题可单独回滚。

**What it will NOT do:** 不拆分两个巨型 code-behind（SecurityPage 2781 行 / SettingsPage 1757 行）为 ViewModel —— 那是独立大型重构，涉及大量 x:Bind 绑定；不改动跨仓库驱动协议（DriverProtocol，需与 Xdows-Security-Driver 协调）；不新增单元测试基础设施；不修改 .gitignore 结构。

**Effort:** Medium
**Risk:** Low - 删除类零功能影响，重构类接口签名保持不变

**Decisions I made for you:**
1. ZipScanner 桥接到 ArchiveScanner：在 ArchiveScanner 中新增 zip 写入/删除方法（与 ZipScanner 相同接口签名），然后删除 ZipScanner.cs —— 最小化 SecurityPage 改动量
2. 硬编码云扫描配置迁移到 LocalSettings：与现有 ModelMode 等设置一致，不新建配置文件
3. `InterceptCallBack` 重命名而非强制统一：Protection 版（`void`，UI 拦截）和 Helper 版（`Task<string>`，TCP 回调）语义不同，强制统一会破坏调用契约；重命名 Helper 版为 `TcpInterceptCallBack`
4. 删除 `Xdows-Local-Caller` 项目：纯透传 CLI（62 行），只调用假 async 的 `Core.ScanAsync`
5. `Core.ScanAsync` 改名 `Core.Scan`：删除假 async 包装，调用方（ScanEngine 已用 `Task.Run` 包装）无需逻辑变更
6. 删除冗余的根目录 `JsonContext.cs`：与 `Views/BugReportJsonContext` 功能完全重叠

Your next move: approve, then run the dual high-accuracy review before execution.

---

> TL;DR (machine): Medium effort, Low risk - delete 3 orphan dirs + 4 dead-code sites + tests/bin artifacts, merge ZipScanner→ArchiveScanner, externalize hardcoded config, rename InterceptCallBack/Core.ScanAsync, delete Xdows-Local-Caller, remove redundant JsonContext.

## Scope
### Must have
- Wave A (deletion, zero-risk):
  - A1. Delete `Xdows-Driver/`, `Xdows-Driver-Caller/`, `ZipDiag/` directories (committed build artifacts, no source)
  - A2. Delete `Xdows-Local/DllScan.cs` (0 callers)
  - A3. Delete `QuarantineManager.CalculateFileHashAsync` (private, unused) and `TrustManagerHelper.CreateTrustItemJson` (0 callers)
  - A4. Delete root `Xdows-Security/JsonContext.cs` (redundant, confirms `BugReportJsonContext` in Views/ is the one used)
  - A5. Delete `Xdows-Local-Caller/` project (pure pass-through CLI) + remove from solution
  - A6. Clean committed `tests/**/bin/` and `tests/**/obj/` artifacts (third-party DLLs + .source files)
- Wave B (refactor, interface-preserving):
  - B1. Rename `Core.ScanAsync` → `Core.Scan`; update call sites
  - B2. Merge `ZipScanner` write/delete methods into `ArchiveScanner`; update SecurityPage callers; delete `ZipScanner.cs`
  - B3. Externalize `ScanEngine.cs` cloud endpoints + API key to LocalSettings
  - B4. Fix `DriverInstaller.FindAsset` hardcoded `D:\Code\` paths
  - B5. Rename `Helper.Linker.CallBack.InterceptCallBack` → `TcpInterceptCallBack`; update references

### Must NOT have (guardrails, anti-slop, scope boundaries)
- Do NOT split `SecurityPage.xaml.cs` or `SettingsPage.xaml.cs` into ViewModels (separate large refactor)
- Do NOT modify `Protection/DriverProtocol.cs` or any cross-repo protocol contract
- Do NOT add unit-test infrastructure or behavioral tests
- Do NOT modify `.gitignore` structure (only remove already-committed files)
- Do NOT touch `Protection/Legacy*` files, `DriverProtection.cs`, `App.xaml.cs` business logic
- Do NOT change any public interface signature that has external callers (only renames that are mechanically safe)
- Do NOT change cloud scan behavior (endpoints still point to same IPs, just configurable)

## Verification strategy
> Zero human intervention - all verification is agent-executed.
- Test decision: none (no test framework in repo; the existing tests are source-text-scanning). Verification is by build + grep + compile.
- Build command: `& 'D:\Visual-Studio\MSBuild\Current\Bin\amd64\MSBuild.exe' 'D:\Code\Xdows-Security\Xdows-Security.slnx' /p:Configuration=Debug /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.28000.0 /p:SignMode=Off /m`
- Evidence: `.omo/evidence/task-<N>-refactor-delete-candidates.<ext>` (attemptDir = .omo/evidence/)

## Execution strategy
### Parallel execution waves
- Wave A (deletion): tasks 1-7, all parallelizable (independent file deletions)
- Wave B (refactor): tasks 8-12, sequential within B (shared callers), but B1 (Core.Scan rename) is independent of B2/B3/B4/B5
- Dependency: B2 must run after all A tasks (ZipScanner usage must be fully resolved); B5 must run after A5 (Linker not in Xdows-Local-Caller)

### Dependency matrix
| Todo | Depends on | Blocks | Can parallelize with |
| --- | --- | --- | --- |
| 1 (del dirs) | none | 6 | 2,3,4,5 |
| 2 (del DllScan) | none | none | 1,3,4,5,6 |
| 3 (del dead methods) | none | none | 1,2,4,5,6 |
| 4 (del JsonContext) | none | none | 1,2,3,5,6 |
| 5 (del Local-Caller) | none | 8 (B1) | 1,2,3,4,6 |
| 6 (clean tests/bin) | 1 | none | 2,3,4,5 |
| 7 (rm from solution) | 5 | none | 6 |
| 8 (B1 Core.Scan rename) | 5 | none | 9,10,11,12 |
| 9 (B2 ZipScanner merge) | none | none | 8,10,11,12 |
| 10 (B3 externalize config) | none | none | 8,9,11,12 |
| 11 (B4 Fix FindAsset) | none | none | 8,9,10,12 |
| 12 (B5 rename InterceptCallBack) | none | none | 8,9,10,11 |

## Todos
> Implementation + Test = ONE todo. Never separate.
<!-- APPEND TASK BATCHES BELOW THIS LINE WITH edit/apply_patch - never rewrite the headers above. -->

- [ ] 1. Delete three orphan directories (Xdows-Driver/, Xdows-Driver-Caller/, ZipDiag/)
  What to do / Must NOT do: Remove the entire directories `D:\Code\Xdows-Security\Xdows-Driver\`, `Xdows-Driver-Caller\`, `ZipDiag\` from disk AND git index. These contain only committed `bin/obj` build artifacts (no source). Verify with git that these are NOT referenced by the solution `Xdows-Security.slnx` before deleting. Must NOT delete the real driver source in sibling repo `../Xdows-Security-Driver`.
  Parallelization: Wave A | Blocked by: none | Blocks: 6
  References: glob showed `Xdows-Driver/`=33 files, `Xdows-Driver-Caller/`=19 files, `ZipDiag/`=24 files, ALL bin/obj. README.md confirms real driver lives in `../Xdows-Security-Driver`. Solution: `D:\Code\Xdows-Security\Xdows-Security.slnx`.
  Acceptance criteria (agent-executable): `git status` shows the 3 directories staged for deletion; `git ls-files | grep -E 'Xdows-Driver|Xdows-Driver-Caller|ZipDiag'` returns nothing after commit; `Test-Path D:\Code\Xdows-Security\Xdows-Driver` returns False.
  QA scenarios: happy = `git rm -r Xdows-Driver Xdows-Driver-Caller ZipDiag` succeeds, build passes. failure = if solution references these (verify `git grep -l 'Xdows-Driver' Xdows-Security.slnx` first) — if referenced, abort and report. Evidence `.omo/evidence/task-1-refactor-delete-candidates.txt`.
  Commit: Y | `chore(cleanup): remove orphan build-artifact directories`

- [ ] 2. Delete dead code: Xdows-Local/DllScan.cs
  What to do / Must NOT do: Delete the file `D:\Code\Xdows-Security\Xdows-Local\DllScan.cs`. Verify NO caller exists first (`grep -r "DllScan" D:\Code\Xdows-Security --include=*.cs` should return only the definition line). Must NOT touch Heuristic.cs (it does inline DLL analysis, not via DllScan).
  Parallelization: Wave A | Blocked by: none | Blocks: none
  References: `D:\Code\Xdows-Security\Xdows-Local\DllScan.cs` (lines 1-51). Grep returned only 1 match (own definition).
  Acceptance criteria: `grep -r "DllScan" D:\Code\Xdows-Security` returns nothing; project compiles.
  QA scenarios: happy = file deleted, build succeeds. failure = if build references DllScan (shouldn't), restore file. Evidence `.omo/evidence/task-2-refactor-delete-candidates.txt`.
  Commit: Y | `chore(cleanup): remove unused DllScan class`

- [ ] 3. Delete dead methods: QuarantineManager.CalculateFileHashAsync + TrustManagerHelper.CreateTrustItemJson
  What to do / Must NOT do: In `D:\Code\Xdows-Security\TrustQuarantine\QuarantineManager.cs` lines 251-257 delete the private method `CalculateFileHashAsync` (verify no callers — `grep "CalculateFileHashAsync"` should return only the definition and the TrustManager.cs calls which are a DIFFERENT private method). In `D:\Code\Xdows-Security\TrustQuarantine\TrustManagerHelper.cs` lines 65-83 delete the public method `CreateTrustItemJson` (verify 0 callers). Must NOT delete `TrustManagerHelper.CalculateFileHashAsync` (line 27) — that IS called by TrustManager.cs:63,154.
  Parallelization: Wave A | Blocked by: none | Blocks: none
  References: `TrustQuarantine/QuarantineManager.cs:251-257`; `TrustQuarantine/TrustManagerHelper.cs:65-83`.
  Acceptance criteria: `grep "CreateTrustItemJson"` returns nothing; `grep "private static async Task<string> CalculateFileHashAsync" TrustQuarantine/QuarantineManager.cs` returns nothing; build compiles.
  QA scenarios: happy = both removed, compile passes. failure = if QuarantineManager.CalculateFileHashAsync still referenced, restore. Evidence `.omo/evidence/task-3-refactor-delete-candidates.txt`.
  Commit: Y | `chore(cleanup): remove unused hash/trust helpers`

- [ ] 4. Delete redundant root Xdows-Security/JsonContext.cs
  What to do / Must NOT do: Verify `D:\Code\Xdows-Security\Xdows-Security\JsonContext.cs` (namespace `Xdows_Security`, class `JsonContext`) is NOT referenced anywhere (`grep -r "JsonContext" --include=*.cs` excluding the file itself and Views/JsonContext.cs which defines `BugReportJsonContext`). If 0 references, delete it. Keep `Views/JsonContext.cs` (BugReportJsonContext). Must NOT delete if referenced.
  Parallelization: Wave A | Blocked by: none | Blocks: none
  References: `Xdows-Security/JsonContext.cs` (lines 1-15); `Xdows-Security/Views/JsonContext.cs` (BugReportJsonContext, keep).
  Acceptance criteria: `grep -rn "JsonContext" --include=*.cs` returns only `BugReportJsonContext` (in Views/) and `QuarantineJsonContext` (in TrustQuarantine); no bare `JsonContext` reference; build compiles.
  QA scenarios: happy = file deleted, no references. failure = if some code references `Xdows_Security.JsonContext`, restore and report (may need to point to BugReportJsonContext). Evidence `.omo/evidence/task-4-refactor-delete-candidates.txt`.
  Commit: Y | `chore(cleanup): remove redundant JsonContext`

- [ ] 5. Delete Xdows-Local-Caller project
  What to do / Must NOT do: Delete the entire `D:\Code\Xdows-Security\Xdows-Local-Caller\` directory (contains only `Program.cs` 62 lines + csproj). Remove its project entry from `D:\Code\Xdows-Security\Xdows-Security.slnx`. Verify no other project references it. Must NOT delete Xdows-Local/ (the actual library it wraps).
  Parallelization: Wave A | Blocked by: none | Blocks: 8
  References: `Xdows-Local-Caller/Program.cs` (lines 1-62); solution `Xdows-Security.slnx`.
  Acceptance criteria: `Test-Path D:\Code\Xdows-Security\Xdows-Local-Caller` returns False; solution builds without it; `grep -r "Xdows-Local-Caller" --include=*.csproj` returns nothing.
  QA scenarios: happy = dir gone, solution builds. failure = if solution or a csproj references it, remove the reference too. Evidence `.omo/evidence/task-5-refactor-delete-candidates.txt`.
  Commit: Y | `chore(cleanup): remove pass-through Xdows-Local-Caller CLI`

- [ ] 6. Clean committed tests/bin and tests/obj artifacts
  What to do / Must NOT do: Remove from git index the committed `tests/**/bin/` and `tests/**/obj/` directories (they contain ~50 third-party DLLs and .source files that violate the existing `[Bb]in/`/`[Oo]bj/` gitignore rules). Use `git rm -r --cached` to untrack without deleting working files, OR `git rm -r` to delete. Prefer untracking with `git rm -r --cached` then keep the working dir (builds regenerate). Must NOT modify .gitignore itself. Must NOT delete `tests/Xdows-Security-StartupTests/Program.cs` or the csproj.
  Parallelization: Wave A | Blocked by: 1 | Blocks: none
  References: `tests/Xdows-Security-StartupTests/bin/` and `obj/` glob results.
  Acceptance criteria: `git status` shows tests/bin + tests/obj untracked; `git ls-files | grep 'tests/.*/bin/'` returns nothing; `.gitignore` has `[Bb]in/` and `[Oo]bj/` patterns (lines 31-32).
  QA scenarios: happy = artifacts untracked, build regenerates them. failure = if untracking breaks build (shouldn't — bin/obj are regenerated). Evidence `.omo/evidence/task-6-refactor-delete-candidates.txt`.
  Commit: Y | `chore(cleanup): untrack committed tests build artifacts`

- [ ] 7. Remove Xdows-Local-Caller from solution file
  What to do / Must NOT do: Edit `D:\Code\Xdows-Security\Xdows-Security.slnx` to remove the `Xdows-Local-Caller` project entry (Project + EndProject block). This is part of task 5 but may need a separate .slnx edit if the project file deletion doesn't auto-clean. Must NOT touch other solution entries.
  Parallelization: Wave A | Blocked by: 5 | Blocks: none
  References: `D:\Code\Xdows-Security\Xdows-Security.slnx`.
  Acceptance criteria: `grep "Xdows-Local-Caller" Xdows-Security.slnx` returns nothing; `dotnet build Xdows-Security.slnx` or MSBuild succeeds.
  QA scenarios: happy = slnx clean, build succeeds. failure = slnx malformed, restore from git. Evidence `.omo/evidence/task-7-refactor-delete-candidates.txt`.
  Commit: Y | (folded into task 5 commit)

- [ ] 8. Rename Core.ScanAsync → Core.Scan, update callers
  What to do / Must NOT do: In `D:\Code\Xdows-Security\Xdows-Local\Core.cs` line 42, delete the `ScanAsync` method (a fake async pass-through `=> Scan(path, deep, extraData)`). The synchronous `Scan` (line 15) already exists. Update call sites that call `Core.ScanAsync`: `Helper/ScanEngine.cs:16` (inside `LocalScanAsync`) — change to `Core.Scan`. Verify `grep "ScanAsync"` — the remaining matches after change should be `LocalScanAsync`/`LocalScanFromBytesAsync`/`StartScanAsync` (distinct names, not `Core.ScanAsync`). Must NOT rename `ScanEngine.LocalScanAsync` (that's a different, genuinely-async method). Xdows-Local-Caller is already deleted in task 5.
  Parallelization: Wave B | Blocked by: 5 | Blocks: none
  References: `Xdows-Local/Core.cs:42`; `Helper/ScanEngine.cs:14-17`.
  Acceptance criteria: `grep -rn "Core.ScanAsync" --include=*.cs` returns nothing; `grep -rn "ScanAsync" --include=*.cs` returns only `LocalScanAsync`/`LocalScanFromBytesAsync`/`StartScanAsync`/`InfectorScanAsync`/`CloudScanAsync`/`ExactRuleEngineBatchScanAsync` (all distinct real-async methods); build compiles.
  QA scenarios: happy = rename done, build passes, all callers still work. failure = if any call site still uses Core.ScanAsync, compiler error (good — it's a breaking rename by design). Evidence `.omo/evidence/task-8-refactor-delete-candidates.txt`.
  Commit: Y | `refactor(xdows-local): rename misleading Core.ScanAsync to Core.Scan`

- [ ] 9. Merge ZipScanner write/delete methods into ArchiveScanner, delete ZipScanner.cs
  What to do / Must NOT do: Port these 4 public methods from `Helper/ZipScanner.cs` into `Helper/ArchiveScanner.cs` with IDENTICAL signatures: `ExtractEntryAsync(string zipPath, string entryPath)` (line 308), `DeleteEntryFromZipAsync` (line 230), `DeleteMultipleEntriesFromZipAsync` (line 265), `GetEntryInfoAsync` (line 333). These methods use `System.IO.Compression` (ZipArchive) which ArchiveScanner already references. Copy the implementations verbatim into ArchiveScanner. Then update `SecurityPage.xaml.cs` call sites (line 681, 714, 2505) from `ZipScanner.X` to `ArchiveScanner.X`. Then delete `Helper/ZipScanner.cs`. Must NOT change method signatures or behavior. Must NOT delete the zip-reading logic that overlaps (ReadZipEntriesAsync in ZipScanner is NOT used by ArchiveScanner's ReadArchiveEntriesAsync — keep ArchiveScanner's version).
  Parallelization: Wave B | Blocked by: none | Blocks: none
  References: `Helper/ZipScanner.cs` (lines 230-333 for the 4 methods); `Helper/ArchiveScanner.cs`; `SecurityPage.xaml.cs:681,714,2505`.
  Acceptance criteria: `grep -r "ZipScanner" --include=*.cs` returns nothing; `grep -r "ArchiveScanner.ExtractEntryAsync|ArchiveScanner.DeleteEntryFromZipAsync|ArchiveScanner.DeleteMultipleEntriesFromZipAsync|ArchiveScanner.GetEntryInfoAsync"` returns the 3 SecurityPage call sites; build compiles.
  QA scenarios: happy = 4 methods in ArchiveScanner, 3 call sites updated, build passes. failure = if ArchiveScanner references a symbol not in scope, compiler catches it. Evidence `.omo/evidence/task-9-refactor-delete-candidates.txt`.
  Commit: Y | `refactor(helper): merge ZipScanner into ArchiveScanner`

- [ ] 10. Externalize ScanEngine.cs cloud endpoints + API key to LocalSettings
  What to do / Must NOT do: In `D:\Code\Xdows-Security\Helper\ScanEngine.cs` lines 10-12, replace the hardcoded consts `CloudScanBaseUrl`, `CloudScanApiKey`, `ExactRuleBaseUrl` with lazy reads from `ApplicationData.GetForUnpackaged("Xdows-Software", "Xdows-Security").LocalSettings`, falling back to the current hardcoded values as defaults. Follow the existing `s_settingsLazy` pattern already in the file (lines 57-60). Also update `Xdows-Security/FeedbackTCPClient.cs:26` `_serverHost = "103.118.245.82"` to read from LocalSettings (key `FeedbackServerHost`). Must NOT change the actual endpoint values (defaults stay the same). Must NOT remove the cloud scan functionality.
  Parallelization: Wave B | Blocked by: none | Blocks: none
  References: `Helper/ScanEngine.cs:10-12` (consts), `:57-60` (s_settingsLazy pattern to follow), `:207-234` (CloudScanAsync), `:291-355` (ExactRuleEngineBatchScan); `Xdows-Security/FeedbackTCPClient.cs:26`.
  Acceptance criteria: `grep "103.118.245.82" Helper/ScanEngine.cs` returns matches only inside default-value fallbacks (in a config read helper), not bare consts; build compiles; cloud scan still works with default values.
  QA scenarios: happy = endpoints now read from settings with defaults. failure = if LocalSettings access throws, PublicationOnly Lazy pattern already guards. Evidence `.omo/evidence/task-10-refactor-delete-candidates.txt`.
  Commit: Y | `refactor(helper): externalize hardcoded cloud scan endpoints to settings`

- [ ] 11. Fix DriverInstaller.FindAsset hardcoded D:\Code\ paths
  What to do / Must NOT do: In `D:\Code\Xdows-Security\Protection\DriverInstaller.cs` lines 158-195, the `FindAsset` method has hardcoded `D:\Code\Xdows-Model\...` paths (lines 167-175) and a recursive `Directory.EnumerateFiles(@"D:\Code\Xdows-Model", ...)` (line 188). Replace the hardcoded array entries with a configurable root read from LocalSettings (key `ModelSourceRoot`, default empty = skip) OR simply remove the `D:\Code\` entries and rely only on the portable roots (`AppContext.BaseDirectory` + relative). Recommended: keep the portable relative roots, remove the absolute `D:\Code\` ones, and add a single optional LocalSettings `ModelSourceRoot` for the recursive search. Must NOT break the dev-machine workflow — devs can set the setting; must NOT delete the whole fallback mechanism.
  Parallelization: Wave B | Blocked by: none | Blocks: none
  References: `Protection/DriverInstaller.cs:158-195`.
  Acceptance criteria: `grep "D:\\\\Code" Protection/DriverInstaller.cs` returns nothing; build compiles; `FindAsset` still searches AppContext.BaseDirectory + relative roots.
  QA scenarios: happy = hardcoded D:\Code\ paths removed, portable roots remain, optional setting for devs. failure = if a dev machine relies on D:\Code\ without setting it, model copy may fail — but that's the intended production fix (rely on published output). Evidence `.omo/evidence/task-11-refactor-delete-candidates.txt`.
  Commit: Y | `refactor(protection): remove hardcoded dev machine paths from FindAsset`

- [ ] 12. Rename Helper.Linker.CallBack.InterceptCallBack → TcpInterceptCallBack
  What to do / Must NOT do: In `D:\Code\Xdows-Security\Helper\Linker.cs` line 13, rename the nested delegate `InterceptCallBack` (inside the static `CallBack` class) to `TcpInterceptCallBack` to disambiguate from `Protection.CallBack.InterceptCallBack` (Protection/CallBack.cs:7). Update all references to `Helper.Linker.CallBack.InterceptCallBack` (the `Linker.Start` and `HandleClientAsync` signatures at lines 20, 42, and the `using static Helper.Linker.CallBack;` at line 6). Must NOT touch `Protection/CallBack.cs` — that's the UI-side callback and stays as `InterceptCallBack`.
  Parallelization: Wave B | Blocked by: none | Blocks: none
  References: `Helper/Linker.cs:6,13,20,42`; `Protection/CallBack.cs:7` (do NOT change).
  Acceptance criteria: `grep -rn "TcpInterceptCallBack" Helper/Linker.cs` returns the definition + call sites; `grep -rn "Helper.Linker.CallBack.InterceptCallBack\|Linker.CallBack.InterceptCallBack"` returns nothing; build compiles.
  QA scenarios: happy = rename done, all references updated, build passes. failure = if any external file uses `Linker.CallBack.InterceptCallBack` (grep whole repo first), update it. Evidence `.omo/evidence/task-12-refactor-delete-candidates.txt`.
  Commit: Y | `refactor(helper): disambiguate InterceptCallBack from Protection's`

## Final verification wave
> Runs in parallel after ALL todos. ALL must APPROVE. Surface results and wait for the user's explicit okay before declaring complete.
- [ ] F1. Plan compliance audit — every todo's acceptance criteria met; grep each deleted symbol confirms gone; each renamed symbol confirms present.
- [ ] F2. Code quality review — no new `as any`/`@ts-ignore` (this is C#, so: no swallowed exceptions added, no new hardcoded paths, no broken contracts).
- [ ] F3. Real manual QA — full MSBuild solution build passes (Debug/x64); app launches; USB auto-scan and cloud-scan settings still functional; archive scanning still quarantines zip entries.
- [ ] F4. Scope fidelity — nothing outside Wave A/B changed; the 10 large-scale candidates (L1-L10 in draft) are NOT implemented, only documented for future planning.

## Commit strategy
- One commit per todo (12 commits), each atomic and independently revertable.
- Wave A commits first (chore(cleanup)), then Wave B (refactor). No code in a commit breaks the build.
- Do NOT commit the 10 large-scale candidate changes — they are future work, documented only.

## Success criteria
- All 3 orphan directories, 4 dead-code sites, Xdows-Local-Caller, redundant JsonContext, and committed tests/bin+obj artifacts are gone from the repo.
- ZipScanner merged into ArchiveScanner; SecurityPage callers updated; cloud config externalized; hardcoded dev paths removed; InterceptCallBack disambiguated; Core.ScanAsync renamed.
- Full MSBuild solution build passes (Debug/x64).
- The 10 feature-granularity large refactor/delete candidates are documented in the draft and presented to the user for future prioritization.