param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$repo = "llm-supermarket/cli-qwen36plus-csharp"
$exePath = Join-Path $PSScriptRoot "artifacts" "cli-qwen36plus-csharp-windows-x64.exe"

if (-not (Test-Path $exePath)) {
    throw "Unable to locate cli-qwen36plus-csharp-windows-x64.exe at $exePath"
}

$hash = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash.ToLower()

Write-Host "Hash: $hash"

$url = "https://github.com/$repo/releases/download/v$Version/cli-qwen36plus-csharp-windows-x64.exe"

$manifestPath = Join-Path $PSScriptRoot "cli-qwen36plus-csharp.json"

$manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json

$manifest.version = $Version

$manifest.architecture."64bit".url = $url

$manifest.architecture."64bit".hash = $hash

$manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath -NoNewline

Write-Host "Updated cli-qwen36plus-csharp.json to v$Version"
