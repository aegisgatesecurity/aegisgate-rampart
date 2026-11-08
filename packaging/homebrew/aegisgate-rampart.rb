# AegisGate Rampart Homebrew Formula
# Install: brew tap aegisgatesecurity/tap && brew install aegisgate-rampart

class AegisgateRampart < Formula
  desc "Local AI security proxy — intercept, detect, block"
  homepage "https://github.com/aegisgatesecurity/aegisgate-rampart"
  url "https://github.com/aegisgatesecurity/aegisgate-rampart/archive/v0.10.0.tar.gz"
  sha256 "1448f134f2c363d2593c1abbc9464d7896cf60499fdab527bbd1106d9be082e2"  # Update with actual SHA256 of tarball
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
