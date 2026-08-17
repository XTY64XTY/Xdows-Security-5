# fix-zip-path-parsing - Work Plan
## TL;DR (For humans)
**What**: 修复 `SecurityPage.xaml.cs` 中三处硬编码 `.zip\` 字面量路径解析 bug，改用同文件已有的 `TryParseArchiveEntry` 方法。
**Why**: `IndexOf(".zip\\")` 会在文件名含 `.zip` 但非压缩包、或嵌套路径多层 `.zip\` 时截断错误。
**What it will NOT do**: 不改变扫描/隔离逻辑、不引入新依赖、不修改其他文件、不新增测试文件。
**Effort**: 单文件 3 处替换，约 20 行净变化，完全自包含。
**Risk**: 极低。`TryParseArchiveEntry`（第 2390 行）已在同文件第 2488 行生产使用，行为已知。
**Decisions**: 位置 3 使用 `out String`（非 nullable）模式，因 `TryParseArchiveEntry` 返回 true 时保证两值非空；位置 1/2 因变量逃逸到闭包，保留外层 nullable + 块内赋值模式。

## Scope
- **IN**: `Xdows-Security/Views/SecurityPage.xaml.cs` 中 3 处 `.zip\` 字面量替换为 `TryParseArchiveEntry`
- **OUT**: 不修改 `TryParseArchiveEntry` 本体；不修改 `ZipScanner`/`ArchiveScanner`；不处理压缩扫描的其他问题（嵌套深度、内存、临时文件）
- **预期行为变更（有意为之）**: 旧代码仅凭路径含 `.zip\` 即进入压缩包分支；新代码 `TryParseArchiveEntry` 内部调用 `ArchiveScanner.IsArchiveFile` 做文件存在性 + 魔数校验——压缩包文件已被删除时，威胁条目将回退到普通文件处理分支而非压缩包分支。这是更正确的行为，属于修复的一部分。

## Verification strategy
- F1: grep 确认 `.zip\` 字面量归零
- F2: 构建通过，零新增警告
- F3: 确认原有 `TryParseArchiveEntry` 调用未被改动（无回归）

## Execution strategy
单文件原地替换。三处独立提交，每处提交后构建验证。
（执行偏差记录：子代理基础设施失效，由编排者直接执行；三处编辑批量完成后单提交 + 单次终验构建。）

## Todos
- [x] 1. 替换位置 1（第 567-574 行，威胁处理对话框内结果移除块）
  - **References**: `Xdows-Security/Views/SecurityPage.xaml.cs:567-574`；现有方法 `TryParseArchiveEntry` 定义于同文件第 2390 行；既有调用示例第 2488 行
  - **Acceptance**: 第 567-574 行不再包含 `IndexOf(".zip\\"`；`zipPath`/`entryPath` 保持外层 nullable 声明；第 576 行 `if (handled && zipPath != null && entryPath != null)` 及后续代码不变
  - **QA Happy**: grep `.zip\` 计数 3→2；构建成功
  - **QA Failure**: 若编译报错，回退该处改动并重新读取上下文，绝不强推
  - **Commit**: 合并入 `fix: replace hardcoded .zip\ path parsing with TryParseArchiveEntry (3 sites)`（见执行偏差）

- [x] 2. 替换位置 2（第 644-653 行，`HandleSingleThreatAsync` 内）
  - **References**: `Xdows-Security/Views/SecurityPage.xaml.cs:642-662`；`TryParseArchiveEntry` 第 2390 行
  - **Acceptance**: 第 648-653 行不再含 `IndexOf(".zip\\"`；第 662 行闭包内 `zipPath != null && entryPath != null && _zipFileThreats.TryGetValue(zipPath, ...)` 逻辑不变
  - **QA Happy**: grep `.zip\` 计数 2→1；构建成功
  - **QA Failure**: 闭包捕获变量 nullability 警告出现时，保持外层 nullable 模式不动
  - **Commit**: 合并入同一提交（见执行偏差）

- [x] 3. 替换位置 3（第 886-891 行，批量处理威胁列表块）
  - **References**: `Xdows-Security/Views/SecurityPage.xaml.cs:886-916`；`TryParseArchiveEntry` 第 2390 行
  - **Acceptance**: 第 887-891 行不再含 `IndexOf(".zip\\"`；`else` 分支保持原样；第 893-915 行块内代码逐字不变
  - **QA Happy**: grep `.zip\` 计数 1→0；构建成功且无 CS8600/CS8602 新警告
  - **QA Failure**: 若 `out String` 与下游空键冲突，改回 `out String?` + 空值守卫
  - **Commit**: 合并入同一提交（见执行偏差）

## Final verification wave
- [x] F1. 证据: grep 结果 0 匹配（实际执行：`IndexOf(".zip` 归零，4 处 `TryParseArchiveEntry(displayPath` 调用 = 3 处新替换 + 1 处原有）
- [x] F2. 证据: MSBuild Debug/x64 全解决方案构建成功（0 错误，8 警告均为预先存在：C4819×3 来自外部 Xdows-Model 原生仓库、CS8604 在 2674 行原始 2680 行区域，与本次改动无关）
- [x] F3. 证据: 原有调用（现第 2482 行）`Boolean isArchiveEntry = TryParseArchiveEntry(displayPath, out archivePath, out entryPath);` 原样保留，`TryParseArchiveEntry`/`ArchiveScanner` 本体未改动

## Commit strategy
三个原子提交，每个位置一个，按 1 → 2 → 3 顺序，每个提交后跑一次构建。
（执行偏差：子代理基础设施失效（4 次派发全部失联）导致编排者直接执行；三处编辑作为一批应用，最终以单提交 `9bb2767` 交付，含全部三处修改 +7/-13。构建在终验波统一执行一次。）

## Success criteria
- [x] grep 证实 `.zip\` 硬编码字面量三处全部替换为 `TryParseArchiveEntry`
- [x] 构建通过、零新增警告
- [x] 原有 `TryParseArchiveEntry` 调用及 `TryParseArchiveEntry`/`ArchiveScanner` 本体无回归
- [x] 压缩包文件已删除时的行为回退（见 Scope 预期行为变更）作为有意变更接受