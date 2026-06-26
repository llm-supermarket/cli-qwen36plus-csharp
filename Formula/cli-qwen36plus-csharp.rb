class CliQwen36plusCsharp < Formula
  desc "Encrypt and decrypt files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt)"
  homepage "https://github.com/llm-supermarket/cli-qwen36plus-csharp"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket/cli-qwen36plus-csharp/releases/download/v1.0.0/cli-qwen36plus-csharp-darwin-arm64.tar.gz"
      sha256 "96620643e68598c4dd4de20f9d9ff384618a1d39607d7cd23860e6dfb91aba09"
    else
      url "https://github.com/llm-supermarket/cli-qwen36plus-csharp/releases/download/v1.0.0/cli-qwen36plus-csharp-darwin-x64.tar.gz"
      sha256 "58fbe9c16d03b9418aa5ba4de7dc2d9bbb144950300f4952c37c65af6195b42f"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket/cli-qwen36plus-csharp/releases/download/v1.0.0/cli-qwen36plus-csharp-linux-arm64.tar.gz"
      sha256 "50c5d66184170c57b5775b655839e0fdb75bad664efc3bd455d3f7e2089081ce"
    else
      url "https://github.com/llm-supermarket/cli-qwen36plus-csharp/releases/download/v1.0.0/cli-qwen36plus-csharp-linux-x64.tar.gz"
      sha256 "8546d33ba235fc409019a409ce5c876216c2626c27277a4266c7e256faa93c66"
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