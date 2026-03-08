class Argos < Formula
  desc "Web Security Scanner for Healthcare Environments"
  homepage "https://github.com/rvielma/argos"
  version "2.2.2"
  license "MIT"

  on_macos do
    on_intel do
      url "https://github.com/rvielma/argos/releases/download/v#{version}/argos-v#{version}-x86_64-apple-darwin.tar.gz"
      # sha256 will be updated on release
    end

    on_arm do
      url "https://github.com/rvielma/argos/releases/download/v#{version}/argos-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "51d370c72454de860c6df0efa66be5eddc65dccc4c9992ecae8c5cfe8c36e168"
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
