# repo-guard installer for Windows (PowerShell 5.1+ and Git Bash).
#
#   powershell -ExecutionPolicy Bypass -File .\install.ps1              install or update
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -NoHook      command only
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall   remove everything
#
# Installs to %LOCALAPPDATA%\repo-guard, adds it to your user PATH, runs
# `repo-guard setup` (git template hooks: every new clone from any app is scanned), and
# adds a marked git clone/pull wrapper to your PowerShell profiles and ~/.bashrc (Git Bash).

param([switch]$Uninstall, [switch]$NoHook)
$ErrorActionPreference = 'Stop'

$Build = Join-Path $PSScriptRoot 'scripts\build_pyz.py'
$Dir = Join-Path $env:LOCALAPPDATA 'repo-guard'
$Begin = '# >>> repo-guard >>>'
$End = '# <<< repo-guard <<<'
$Docs = [Environment]::GetFolderPath('MyDocuments')
$Profiles = @(
    (Join-Path $Docs 'WindowsPowerShell\profile.ps1'),  # Windows PowerShell 5.1
    (Join-Path $Docs 'PowerShell\profile.ps1')          # PowerShell 7+
)
$BashRc = Join-Path $HOME '.bashrc'

# Replace (or with -Block $null, remove) the marked block in a file. Writes UTF-8 without
# a BOM and with the given newline: Git Bash breaks on a BOM or CRLF in ~/.bashrc.
function Set-Block([string]$File, [string]$Block, [string]$NewLine) {
    $out = New-Object System.Collections.Generic.List[string]
    if (Test-Path -LiteralPath $File) {
        $skip = $false
        foreach ($line in [IO.File]::ReadAllLines($File)) {
            if ($line -eq $Begin) { $skip = $true; continue }
            if ($line -eq $End) { $skip = $false; continue }
            if (-not $skip) { $out.Add($line) }
        }
    } elseif (-not $Block) { return }
    if ($Block) { foreach ($l in ($Block -split "`r?`n")) { $out.Add($l) } }
    New-Item -ItemType Directory -Force -Path (Split-Path $File) | Out-Null
    [IO.File]::WriteAllText($File, (($out -join $NewLine) + $NewLine), (New-Object Text.UTF8Encoding $false))
}

function Set-UserPath([string]$Add, [switch]$Remove) {
    $parts = @(([Environment]::GetEnvironmentVariable('Path', 'User') -split ';') | Where-Object { $_ -and $_ -ne $Add })
    if (-not $Remove) { $parts += $Add }
    [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
}

if ($Uninstall) {
    $OldShim = Join-Path $Dir 'repo-guard.cmd'
    if (Test-Path $OldShim) { try { & $OldShim setup --uninstall | Out-Null } catch { } }
    if (Test-Path $Dir) { Remove-Item -LiteralPath $Dir -Recurse -Force }
    Set-UserPath $Dir -Remove
    foreach ($p in $Profiles) { Set-Block $p $null "`r`n" }
    Set-Block $BashRc $null "`n"
    Write-Host 'repo-guard removed. Open a new terminal for the change to take effect.'
    exit 0
}

if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) {
    throw 'git is not installed (https://git-scm.com/download/win).'
}
if (-not (Test-Path $Build)) { throw 'Run this from the repo-guard folder (scripts\build_pyz.py not found).' }

# Find a real Python 3.8+ (the Microsoft Store "python.exe" stub doesn't count).
$Python = $null
foreach ($cand in @(@('py', '-3'), @('python'), @('python3'))) {
    $cmd = Get-Command $cand[0] -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cmd -or $cmd.Source -like '*\WindowsApps\*') { continue }
    $pre = @($cand | Select-Object -Skip 1)
    try {
        # No double quotes in the code: PowerShell 5.1 mangles them when calling native programs.
        $exe = & $cmd.Source @pre -c 'import sys; print(sys.executable if sys.version_info >= (3, 8) else str())' 2>$null
    } catch { continue }
    if ($exe -and (Test-Path $exe)) { $Python = $exe.Trim(); break }
}
if (-not $Python) {
    throw 'Python 3.8+ not found. Install it from https://www.python.org/downloads/ (tick "Add python.exe to PATH"), then run this installer again.'
}

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$Pyz = Join-Path $Dir 'repo-guard.pyz'
& $Python -I $Build $Pyz
if ($LASTEXITCODE -ne 0) { throw 'Could not build repo-guard.' }
$OldPy = Join-Path $Dir 'repo-guard.py'
if (Test-Path $OldPy) { Remove-Item -LiteralPath $OldPy -Force }  # pre-1.0 single-file install
$Shim = Join-Path $Dir 'repo-guard.cmd'
Set-Content -LiteralPath $Shim -Encoding ASCII -Value "@`"$Python`" -I `"%~dp0repo-guard.pyz`" %*"
Set-UserPath $Dir
if (($env:Path -split ';') -notcontains $Dir) { $env:Path = "$Dir;$env:Path" }
Write-Host "Installed $Shim (Python: $Python)"

if (-not $NoHook) {
    $psHook = @"
$Begin
# Scans repos for hidden malware: ``git clone`` checks files out only if every
# branch is clean, and ``git pull`` rescans. Bypass once: `$env:REPO_GUARD_OFF=1
function git {
    `$real = (Get-Command git -CommandType Application | Select-Object -First 1).Source
    if (-not `$env:REPO_GUARD_OFF -and `$args.Count -gt 0 -and `$args[0] -eq 'clone') {
        & '$Shim' clone @(`$args | Select-Object -Skip 1); return
    }
    if (-not `$env:REPO_GUARD_OFF -and `$args.Count -gt 0 -and `$args[0] -eq 'pull') {
        & `$real @args
        if (`$LASTEXITCODE -ne 0) { return }
        & '$Shim' scan --worktree-only --quiet (& `$real rev-parse --show-toplevel)
        return
    }
    & `$real @args
}
$End
"@
    foreach ($p in $Profiles) {
        Set-Block $p $psHook "`r`n"
        Write-Host "Added the git hook to $p"
    }

    # Git Bash: same hook in ~/.bashrc, calling the Python script directly.
    $pyPosix = $Python -replace '\\', '/'
    $scriptPosix = $Pyz -replace '\\', '/'
    $bashHook = @"
$Begin
# Scans repos for hidden malware (see repo-guard --help). Bypass once: REPO_GUARD_OFF=1 git clone ...
function repo-guard { "$pyPosix" -I "$scriptPosix" "`$@"; }
function git {
  if [ -z "`${REPO_GUARD_OFF:-}" ] && [ "`${1:-}" = clone ]; then
    shift; repo-guard clone "`$@"
  elif [ -z "`${REPO_GUARD_OFF:-}" ] && [ "`${1:-}" = pull ]; then
    command git "`$@" || return `$?
    repo-guard scan --worktree-only --quiet "`$(command git rev-parse --show-toplevel)"
  else
    command git "`$@"
  fi
}
$End
"@
    Set-Block $BashRc $bashHook "`n"
    Write-Host "Added the git hook to $BashRc (Git Bash)"

    $policy = Get-ExecutionPolicy -Scope CurrentUser
    if ($policy -in @('Undefined', 'Restricted', 'AllSigned') -and (Get-ExecutionPolicy) -in @('Restricted', 'AllSigned')) {
        Write-Warning ("PowerShell won't load your profile under the '$(Get-ExecutionPolicy)' execution policy, " +
            'so the PowerShell hook stays off. To allow local profiles, run: ' +
            'Set-ExecutionPolicy -Scope CurrentUser RemoteSigned   (Git Bash works either way.)')
    }
}

if (-not $NoHook) {
    & $Shim setup
    if ($LASTEXITCODE -ne 0) { throw 'repo-guard setup failed.' }
}

Write-Host ''
& $Shim selftest
if ($LASTEXITCODE -ne 0) { throw 'selftest failed. Please report the output above: https://github.com/gloverola/repo-guard/issues' }
Write-Host ''
Write-Host 'Done. Open a new terminal, then try: repo-guard --help'
