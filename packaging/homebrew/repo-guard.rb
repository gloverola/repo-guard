# Homebrew formula for the gloverola/homebrew-tap repository (Formula/repo-guard.rb).
# After each release, set `url` to the sdist's permanent URL (`urls` in
# https://pypi.org/pypi/git-repo-guard/<version>/json) and `sha256` to its hash (also in
# SHA256SUMS on the GitHub release).
class RepoGuard < Formula
  include Language::Python::Virtualenv

  desc "Scan every git clone for hidden malware before any of its code can run"
  homepage "https://github.com/gloverola/repo-guard"
  url "https://files.pythonhosted.org/packages/e4/df/037c0ac8af7c7bc7950b92e9e78e46ff1ab02e76966eb171ee6b44382ff2/git_repo_guard-1.1.0.tar.gz"
  sha256 "e388bfa8a895be7c5c9ad2332bbf54f015c23978ec4f9a7f9f5b825003463666"
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
