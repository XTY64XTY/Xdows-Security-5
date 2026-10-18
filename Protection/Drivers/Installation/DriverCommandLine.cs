using System.Diagnostics;

namespace Protection;

/// <summary>
/// 命令行执行的唯一入口。环境检测（bcdedit 查询/设置）与安装流程（pnputil）共用，
/// 避免两处各写一份 Process 样板。
/// </summary>
internal static class DriverCommandLine
{
    public static async Task<CommandResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        CancellationToken token)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };

            foreach (string argument in arguments)
                process.StartInfo.ArgumentList.Add(argument);

            if (!process.Start())
                return new CommandResult(false, -1, string.Empty);

            // 必须先并行读取两条流再等待退出：管道缓冲区写满时，
            // 单独 WaitForExit 会与子进程互相等待。
            Task<string> outputTask = process.StandardOutput.ReadToEndAsync(token);
            Task<string> errorTask = process.StandardError.ReadToEndAsync(token);
            await process.WaitForExitAsync(token).ConfigureAwait(false);

            string output = await outputTask.ConfigureAwait(false);
            string error = await errorTask.ConfigureAwait(false);
            return new CommandResult(true, process.ExitCode, output + error);
        }
        catch (Exception ex) when (
            ex is InvalidOperationException or System.ComponentModel.Win32Exception or OperationCanceledException)
        {
            return new CommandResult(false, -1, ex.GetType().Name);
        }
    }
}

internal sealed record CommandResult(bool Started, int ExitCode, string Output)
{
    public bool Success => Started && ExitCode == 0;

    public string ShortOutput
    {
        get
        {
            string value = Output.Trim();
            if (value.Length == 0)
                return "No command output.";

            return value.Length <= 700 ? value : value[..700];
        }
    }
}
