class Argos < Formula
  desc "Web Security Scanner for Healthcare Environments"
  homepage "https://github.com/rvielma/argos"
  version "2.1.1"
  license "MIT"

  on_macos do
    on_intel do
      url "https://github.com/rvielma/argos/releases/download/v#{version}/argos-v#{version}-x86_64-apple-darwin.tar.gz"
      # sha256 will be updated on release
    end

    on_arm do
      url "https://github.com/rvielma/argos/releases/download/v#{version}/argos-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "c01ad63e5897b72f5709ea6e81029850a86c5551c98803751133aaed677741ad"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/rvielma/argos/releases/download/v#{version}/argos-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      # sha256 will be updated on release
    end
  end

  def install
    bin.install "argos"
  end

  test do
    assert_match "templates", shell_output("#{bin}/argos modules")
  end
end
