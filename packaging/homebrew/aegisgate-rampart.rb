# AegisGate Rampart Homebrew Formula
# Install: brew tap aegisgatesecurity/tap && brew install aegisgate-rampart

class AegisgateRampart < Formula
  desc "Local AI security proxy — intercept, detect, block"
  homepage "https://github.com/aegisgatesecurity/aegisgate-rampart"
  url "https://github.com/aegisgatesecurity/aegisgate-rampart/archive/v0.11.0.tar.gz"
  sha256 "030f7c7d1c7526624853e32d8cd9cefb5ce6b8c63b332eb34818f6af8a29f077"  # Update with actual SHA256 of tarball
  license "Apache-2.0"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args, "./cmd/rampart"
    bin.install "rampart"
  end

  def caveats
    <<~EOS
      AegisGate Rampart requires CA certificate trust for HTTPS interception.
      
      After installation, run:
        rampart --trust
      
      Then trust the CA certificate in your system:
      - macOS: Keychain Access → trust ca.crt
      - Linux: See rampart --trust output
      - Windows: certutil -addstore root ca.crt
      
      For daemon mode with system tray:
        rampart --daemon
    EOS
  end

  test do
    system "#{bin}/rampart", "version"
    system "#{bin}/rampart", "--help"
  end
end
