# Homebrew formula for the gloverola/homebrew-tap repository (Formula/repo-guard.rb).
# After each release, set `url` to the sdist's permanent URL (`urls` in
# https://pypi.org/pypi/git-repo-guard/<version>/json) and `sha256` to its hash (also in
# SHA256SUMS on the GitHub release).
class RepoGuard < Formula
  include Language::Python::Virtualenv

  desc "Scan every git clone for hidden malware before any of its code can run"
  homepage "https://github.com/gloverola/repo-guard"
  url "https://files.pythonhosted.org/packages/72/de/bc4b8bb7b2ed9f900be4860729963541aec25f70b61350c3877af437f4d1/git_repo_guard-1.0.0.tar.gz"
  sha256 "b2defd34e26b01af16dcc0b5709fd5813c31baaa1929c6e1b0a40568ad2e55fb"
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
