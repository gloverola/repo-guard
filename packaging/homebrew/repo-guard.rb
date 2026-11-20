# Homebrew formula for the gloverola/homebrew-tap repository (Formula/repo-guard.rb).
# After each release, set `url` to the new sdist and `sha256` to the value printed by the
# release workflow (also in SHA256SUMS on the GitHub release).
class RepoGuard < Formula
  include Language::Python::Virtualenv

  desc "Scan every git clone for hidden malware before any of its code can run"
  homepage "https://github.com/gloverola/repo-guard"
  url "https://files.pythonhosted.org/packages/source/g/git-repo-guard/git_repo_guard-1.0.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"

  depends_on "python@3.13"

  def install
    virtualenv_install_with_resources
  end

  def caveats
    <<~EOS
      To scan every future clone automatically (from any app that uses git), run:
        repo-guard setup
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/repo-guard --version")
    system bin/"repo-guard", "selftest"
  end
end
