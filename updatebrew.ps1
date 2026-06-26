param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$repo = "llm-supermarket/cli-qwen36plus-csharp"
$platforms = @("darwin-x64", "darwin-arm64", "linux-x64", "linux-arm64")
$formulaPath = "$PSScriptRoot/Formula/cli-qwen36plus-csharp.rb"
$base = "https://github.com/$repo/releases/download/v$Version"

$hash = @{}
foreach ($platform in $platforms) {
    $url = "$base/cli-qwen36plus-csharp-$platform.tar.gz"
    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "cli-qwen36plus-csharp-$platform.tar.gz"

    Write-Host "Downloading $url ..."
    Invoke-WebRequest -Uri $url -OutFile $tempFile

    $hash[$platform] = (Get-FileHash -Path $tempFile -Algorithm SHA256).Hash.ToLower()
    Write-Host "SHA256 for ${platform}: $($hash[$platform])"

    Remove-Item $tempFile
}

$formula = @"
class CliQwen36plusCsharp < Formula
  desc "Encrypt and decrypt files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt)"
  homepage "https://github.com/$repo"
  version "$Version"

  on_macos do
    if Hardware::CPU.arm?
      url "$base/cli-qwen36plus-csharp-darwin-arm64.tar.gz"
      sha256 "$($hash['darwin-arm64'])"
    else
      url "$base/cli-qwen36plus-csharp-darwin-x64.tar.gz"
      sha256 "$($hash['darwin-x64'])"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "$base/cli-qwen36plus-csharp-linux-arm64.tar.gz"
      sha256 "$($hash['linux-arm64'])"
    else
      url "$base/cli-qwen36plus-csharp-linux-x64.tar.gz"
      sha256 "$($hash['linux-x64'])"
    end
  end

  def install
    bin.install "cli-qwen36plus-csharp-darwin-arm64" => "cli-qwen36plus-csharp" if OS.mac? && Hardware::CPU.arm?
    bin.install "cli-qwen36plus-csharp-darwin-x64" => "cli-qwen36plus-csharp" if OS.mac? && !Hardware::CPU.arm?
    bin.install "cli-qwen36plus-csharp-linux-arm64" => "cli-qwen36plus-csharp" if OS.linux? && Hardware::CPU.arm?
    bin.install "cli-qwen36plus-csharp-linux-x64" => "cli-qwen36plus-csharp" if OS.linux? && !Hardware::CPU.arm?
  end

  test do
    assert_match "cli-qwen36plus-csharp #{version}", shell_output("#{bin}/cli-qwen36plus-csharp version")
  end
end
"@

Set-Content -Path $formulaPath -Value $formula -NoNewline
Write-Host "Wrote $formulaPath for version $Version"
