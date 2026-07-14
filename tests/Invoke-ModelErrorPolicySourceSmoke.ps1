$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$protectionPath = Join-Path $repoRoot "Protection\DriverProtection.cs"
$text = Get-Content -LiteralPath $protectionPath -Raw

if ($text -match 'ModelExtractionError') {
    throw "Model infrastructure errors are still presented as threats."
}

$errorBranch = [regex]::Match(
    $text,
    'if\s*\(!string\.IsNullOrWhiteSpace\(scan\.ErrorMessage\)\)(?<body>(?s:.*?))\r?\n\s*if\s*\(!scan\.IsThreat\)')
if (!$errorBranch.Success) {
    throw "Process model-error policy branch was not found."
}

$body = $errorBranch.Groups['body'].Value
if ($body -match 'AskUserForThreatDecisionAsync|ProtectionUserDecision|XdowsSecurityDecisionType\.Block') {
    throw "Process model infrastructure errors still enter threat decision UI or blocking policy."
}
if ($body -notmatch 'Cache\(processCacheKey,\s*XdowsSecurityDecisionType\.Allow,\s*"model-infrastructure-error-allow"') {
    throw "Process model infrastructure error short allow-cache was not found."
}
if ($body -notmatch 'return\s+Allow\(driverEvent\.EventId,\s*"model-infrastructure-error-allow"\)') {
    throw "Process model infrastructure error fail-open verdict was not found."
}

Write-Host "Model infrastructure error policy source smoke passed."
