class CliQwen36plusCsharp < Formula
  desc "Encrypt and decrypt files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt)"
  homepage "https://github.com/llm-supermarket/cli-qwen36plus-csharp"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket/cli-qwen36plus-csharp/releases/download/v1.0.0/cli-qwen36plus-csharp-darwin-arm64.tar.gz"
      sha256 ""
    else
      url "https://github.com/llm-supermarket/cli-qwen36plus-csharp/releases/download/v1.0.0/cli-qwen36plus-csharp-darwin-x64.tar.gz"
      sha256 ""
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket/cli-qwen36plus-csharp/releases/download/v1.0.0/cli-qwen36plus-csharp-linux-arm64.tar.gz"
      sha256 ""
    else
      url "https://github.com/llm-supermarket/cli-qwen36plus-csharp/releases/download/v1.0.0/cli-qwen36plus-csharp-linux-x64.tar.gz"
      sha256 ""
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
