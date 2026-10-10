class Argos < Formula
  desc "Web Security Scanner for Healthcare Environments"
  homepage "https://github.com/rvielma/argos"
  version "2.6.0"
  license "MIT"

  on_macos do
    on_intel do
      url "https://github.com/rvielma/argos/releases/download/v#{version}/argos-v#{version}-x86_64-apple-darwin.tar.gz"
      # sha256 will be updated on release
    end

    on_arm do
      url "https://github.com/rvielma/argos/releases/download/v#{version}/argos-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "d6716584d5fbca07a7055f4b68cd76b4a423b8abc593f7423b4b9c7cea49e302"
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
