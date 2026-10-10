class Argos < Formula
  desc "Web Security Scanner for Healthcare Environments"
  homepage "https://github.com/rvielma/argos"
  version "2.4.0"
  license "MIT"

  on_macos do
    on_intel do
      url "https://github.com/rvielma/argos/releases/download/v#{version}/argos-v#{version}-x86_64-apple-darwin.tar.gz"
      # sha256 will be updated on release
    end

    on_arm do
      url "https://github.com/rvielma/argos/releases/download/v#{version}/argos-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "75fc74428d1445971a02b4dfe79d3c99c78a2716a9c735fb21f78003d0091f77"
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
