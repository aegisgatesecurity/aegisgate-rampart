# AegisGate Rampart Homebrew Formula
# Install: brew tap aegisgatesecurity/tap && brew install aegisgate-rampart

class AegisgateRampart < Formula
  desc "Local AI security proxy — intercept, detect, block"
  homepage "https://github.com/aegisgatesecurity/aegisgate-rampart"
  url "https://github.com/aegisgatesecurity/aegisgate-rampart/archive/v0.6.1.tar.gz"
  sha256 "0019dfc4b32d63c1392aa264aed2253c1e0c2fb09216f8e2cc269bbfb8bb49b5"  # Update with actual SHA256 of tarball
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
