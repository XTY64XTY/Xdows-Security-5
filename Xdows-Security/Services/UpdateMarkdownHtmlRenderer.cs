using Markdig;

namespace Xdows_Security.Services;

internal static class UpdateMarkdownHtmlRenderer
{
    private static readonly MarkdownPipeline Pipeline = new MarkdownPipelineBuilder()
        .UseAdvancedExtensions()
        .DisableHtml()
        .Build();

    public static string RenderDocument(string markdown, bool useDarkTheme)
    {
        string foreground = useDarkTheme ? "#f3f3f3" : "#1f1f1f";
        string secondaryForeground = useDarkTheme ? "#c8c8c8" : "#5d5d5d";
        string surface = useDarkTheme ? "#202020" : "#ffffff";
        string subtleSurface = useDarkTheme ? "#2d2d2d" : "#f5f5f5";
        string border = useDarkTheme ? "#454545" : "#d6d6d6";
        string link = useDarkTheme ? "#75b6ff" : "#005fb8";
        string renderedMarkdown = Markdown.ToHtml(markdown ?? string.Empty, Pipeline);

        return $$"""
            <!doctype html>
            <html>
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src https: data:; style-src 'unsafe-inline'">
              <style>
                :root { color-scheme: {{(useDarkTheme ? "dark" : "light")}}; }
                * { box-sizing: border-box; }
                html, body { margin: 0; padding: 0; background: {{surface}}; color: {{foreground}}; }
                body { padding: 12px; font: 14px/1.55 "Segoe UI Variable Text", "Segoe UI", sans-serif; overflow-wrap: anywhere; }
                body > :first-child { margin-top: 0; }
                body > :last-child { margin-bottom: 0; }
                h1, h2, h3, h4, h5, h6 { line-height: 1.25; margin: 1.1em 0 0.45em; }
                h1 { font-size: 1.55em; }
                h2 { font-size: 1.35em; }
                h3 { font-size: 1.15em; }
                p, ul, ol, blockquote, pre, table { margin: 0.65em 0; }
                ul, ol { padding-left: 1.6em; }
                a { color: {{link}}; }
                blockquote { margin-left: 0; padding: 0.1em 0.9em; color: {{secondaryForeground}}; border-left: 3px solid {{border}}; }
                code { padding: 0.12em 0.3em; border-radius: 4px; background: {{subtleSurface}}; font-family: "Cascadia Mono", Consolas, monospace; }
                pre { padding: 10px; overflow-x: auto; border: 1px solid {{border}}; border-radius: 6px; background: {{subtleSurface}}; }
                pre code { padding: 0; background: transparent; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 6px 8px; border: 1px solid {{border}}; text-align: left; }
                img { max-width: 100%; height: auto; }
                hr { border: 0; border-top: 1px solid {{border}}; }
                input[type="checkbox"] { vertical-align: middle; }
              </style>
            </head>
            <body>
            {{renderedMarkdown}}
            </body>
            </html>
            """;
    }
}
