<#
.SYNOPSIS
  Update/Install PowerShell 7 on Windows 11 using official GitHub releases.

.DESCRIPTION
  - Auto-detects latest Stable/Preview/LTS release from GitHub API.
  - Downloads the matching Windows MSI for your OS architecture.
  - Verifies SHA256 (from hashes.sha256) and Authenticode signature.
  - Installs silently via msiexec with full logging.
  - Optionally updates common modules and help.

  This script is designed to be run from Windows PowerShell 5.1 or PowerShell 7.

.PARAMETER Channel
  stable | preview | lts

.PARAMETER Silent
  Non-interactive mode (no prompts). Fails fast on risky conditions.

.PARAMETER Force
  Override safety prompts (still does NOT bypass hash/signature verification).

.PARAMETER SkipModules
  Skip module updates after install.

.PARAMETER SkipHelp
  Skip Update-Help after install.

.PARAMETER NoToast
  Disable toast notifications.

.EXAMPLE
  .\update-powershell.ps1

.EXAMPLE
  .\update-powershell.ps1 -Channel stable -Silent

.NOTES
  GitHub release source: https://github.com/PowerShell/PowerShell/releases
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
  [ValidateSet('stable','preview','lts')]
  [string]$Channel = 'stable',

  [switch]$Silent,
  [switch]$Force,
  [switch]$SkipModules,
  [switch]$SkipHelp,
  [switch]$NoToast,

  [ValidateRange(30,3600)]
  [int]$DownloadTimeoutSec = 300,

  [ValidateRange(1,10)]
  [int]$Retries = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# -------------------------------
# Logging
# -------------------------------
$ScriptName = 'update-powershell.ps1'
$RunId      = (Get-Date).ToString('yyyyMMdd_HHmmss')
$WorkDir    = Join-Path $env:TEMP "PowerShellUpdater_$RunId"
$null = New-Item -ItemType Directory -Path $WorkDir -Force

$LogFile    = Join-Path $WorkDir "update_powershell_$RunId.log"
$MsiLog     = Join-Path $WorkDir "msiexec_$RunId.log"

function Write-Log {
  param(
    [Parameter(Mandatory)] [string]$Message,
    [ValidateSet('INFO','WARN','ERROR','OK','STEP')] [string]$Level = 'INFO'
  )
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $line = "[$ts] [$Level] $Message"
  Add-Content -Path $LogFile -Value $line -Encoding UTF8

  $color = switch ($Level) {
    'STEP' { 'Cyan' }
    'OK'   { 'Green' }
    'WARN' { 'Yellow' }
    'ERROR'{ 'Red' }
    default{ 'Gray' }
  }
  Write-Host $line -ForegroundColor $color
}

# -------------------------------
# Safety helpers
# -------------------------------
function Test-IsAdmin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-PendingReboot {
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
  )
  foreach ($p in $paths) {
    if (Test-Path $p) { return $true }
  }
  try {
    $sess = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($null -ne $sess.PendingFileRenameOperations) { return $true }
  } catch {}
  return $false
}

function Assert-Admin {
  if (-not (Test-IsAdmin)) {
    throw 'Run this script in an elevated (Administrator) PowerShell session.'
  }
}

function Assert-NoPendingReboot {
  if (Test-PendingReboot) {
    $msg = 'Windows has a pending reboot (updates/installer). Reboot first to avoid MSI failures.'
    if ($Force) {
      Write-Log "$msg (Force enabled; continuing)" 'WARN'
    } else {
      throw $msg
    }
  }
}

# -------------------------------
# Toast (best-effort)
# -------------------------------
function Show-Toast {
  param([string]$Title, [string]$Body)
  if ($NoToast) { return }
  try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null
    $xml = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>$Title</text>
      <text>$Body</text>
    </binding>
  </visual>
</toast>
"@
    $doc = New-Object Windows.Data.Xml.Dom.XmlDocument
    $doc.LoadXml($xml)
    $toast = [Windows.UI.Notifications.ToastNotification]::new($doc)
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('PowerShell Updater')
    $notifier.Show($toast)
  } catch {
    # ignore
  }
}

# -------------------------------
# GitHub helpers
# -------------------------------
function Invoke-GitHubJson {
  param([Parameter(Mandatory)][string]$Uri)

  $headers = @{
    'User-Agent' = 'PowerShellUpdaterScript'
    'Accept'     = 'application/vnd.github+json'
  }

  return Invoke-RestMethod -Uri $Uri -Headers $headers -Method GET -TimeoutSec $DownloadTimeoutSec
}

function Get-PowerShellRelease {
  param([ValidateSet('stable','preview','lts')] [string]$Channel)

  $base = 'https://api.github.com/repos/PowerShell/PowerShell'

  if ($Channel -eq 'stable') {
    return Invoke-GitHubJson -Uri "$base/releases/latest"
  }

  # For preview/LTS we look at a batch list.
  $releases = Invoke-GitHubJson -Uri "$base/releases?per_page=100"

  if ($Channel -eq 'preview') {
    $r = $releases | Where-Object { $_.prerelease -eq $true } | Select-Object -First 1
    if (-not $r) { throw 'No prerelease found from GitHub API.' }
    return $r
  }

  # LTS: currently PowerShell 7.4 is the LTS line; we select latest 7.4.x non-prerelease.
  $ltsMinor = '7.4'
  $r = $releases |
    Where-Object { $_.prerelease -eq $false -and $_.tag_name -match "^v$([regex]::Escape($ltsMinor))\\." } |
    Select-Object -First 1

  if (-not $r) { throw "No LTS release found for $ltsMinor.x from GitHub API." }
  return $r
}

function Get-Asset {
  param(
    [Parameter(Mandatory)]$Release,
    [Parameter(Mandatory)][string]$Name
  )
  $a = $Release.assets | Where-Object { $_.name -ieq $Name } | Select-Object -First 1
  if (-not $a) {
    # try contains
    $a = $Release.assets | Where-Object { $_.name -ilike $Name } | Select-Object -First 1
  }
  if (-not $a) { throw "Asset not found: $Name" }
  return $a
}

# -------------------------------
# Download + verify
# -------------------------------
function Assert-Https {
  param([Parameter(Mandatory)][string]$Url)
  if ($Url -notmatch '^https://') { throw "Refusing non-HTTPS URL: $Url" }
}

function Download-File {
  param(
    [Parameter(Mandatory)][string]$Url,
    [Parameter(Mandatory)][string]$OutFile
  )

  Assert-Https $Url

  for ($i = 1; $i -le $Retries; $i++) {
    try {
      Write-Log "Downloading ($i/$Retries): $Url" 'STEP'

      # Prefer BITS if available (resumable), fallback to IWR.
      if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
        Start-BitsTransfer -Source $Url -Destination $OutFile -ErrorAction Stop
      } else {
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -TimeoutSec $DownloadTimeoutSec -UseBasicParsing
      }

      if (-not (Test-Path -LiteralPath $OutFile)) {
        throw "Download completed but file missing: $OutFile"
      }

      return
    }
    catch {
      Write-Log "Download attempt $i failed: $($_.Exception.Message)" 'WARN'
      if ($i -eq $Retries) { throw }
      Start-Sleep -Seconds (5 * $i)
    }
  }
}

function Get-ExpectedSha256FromHashesFile {
  param(
    [Parameter(Mandatory)][string]$HashesFile,
    [Parameter(Mandatory)][string]$TargetFileName
  )
  # hashes.sha256 format is: <SHA256><spaces><filename>
  $line = Select-String -LiteralPath $HashesFile -Pattern ("\s" + [regex]::Escape($TargetFileName) + "$") -ErrorAction Stop | Select-Object -First 1
  if (-not $line) { throw "Could not find $TargetFileName in hashes.sha256" }

  $parts = $line.Line -split '\s+'
  $hash  = $parts[0]
  if ($hash -notmatch '^[A-Fa-f0-9]{64}$') { throw "Invalid SHA256 parsed for $TargetFileName: $hash" }
  return $hash.ToUpperInvariant()
}

function Assert-FileHash {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$ExpectedSha256
  )
  $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
  if ($actual -ne $ExpectedSha256.ToUpperInvariant()) {
    throw "SHA256 mismatch. Expected=$ExpectedSha256 Actual=$actual"
  }
}

function Assert-AuthenticodeValid {
  param([Parameter(Mandatory)][string]$Path)

  $sig = Get-AuthenticodeSignature -LiteralPath $Path
  if ($sig.Status -ne 'Valid') {
    throw "Signature invalid: $($sig.Status) ($($sig.StatusMessage))"
  }
}

# -------------------------------
# Installed version detection
# -------------------------------
function Get-InstalledPwshVersion {
  # Try pwsh on PATH first
  try {
    $cmd = Get-Command pwsh -ErrorAction Stop
    $v = & $cmd.Source -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()'
    if ($v -match '^\d+\.\d+\.\d+') {
      return [version]$v
    }
  } catch {}

  # Fall back to common path
  $p = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
  if (Test-Path -LiteralPath $p) {
    $v = & $p -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()'
    if ($v -match '^\d+\.\d+\.\d+') {
      return [version]$v
    }
  }

  return $null
}

# -------------------------------
# Install
# -------------------------------
function Install-PowerShellMsi {
  param([Parameter(Mandatory)][string]$MsiPath)

  $args = @(
    '/i', ('"' + $MsiPath + '"'),
    '/qn',
    '/norestart',
    ('/L*v'), ('"' + $MsiLog + '"')
  )

  Write-Log "Running msiexec (silent). MSI log: $MsiLog" 'STEP'

  $p = Start-Process -FilePath msiexec.exe -ArgumentList $args -Wait -PassThru

  if ($p.ExitCode -eq 0) {
    Write-Log 'MSI install completed successfully.' 'OK'
    return 0
  }

  if ($p.ExitCode -eq 3010) {
    Write-Log 'MSI install completed; reboot required (3010).' 'WARN'
    return 3010
  }

  throw "MSI install failed. ExitCode=$($p.ExitCode). See: $MsiLog"
}

# -------------------------------
# Post-install
# -------------------------------
function Warmup-Pwsh {
  try {
    $pwsh = (Get-Command pwsh -ErrorAction Stop).Source
    & $pwsh -NoProfile -NonInteractive -Command '$null' | Out-Null
  } catch {}
}

function Update-CommonModules {
  if ($SkipModules) {
    Write-Log 'Skipping module updates (SkipModules).' 'INFO'
    return
  }

  try {
    $pwsh = (Get-Command pwsh -ErrorAction Stop).Source

    $cmd = @'
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
try { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue } catch {}
$mods = @('PowerShellGet','PSReadLine','Pester')
foreach($m in $mods){
  try {
    if(Get-Module -ListAvailable -Name $m){ Update-Module -Name $m -Force -ErrorAction Stop }
    else { Install-Module -Name $m -Force -AllowClobber -ErrorAction Stop }
  } catch { Write-Host "Module $m: $($_.Exception.Message)" }
}
'@

    Write-Log 'Updating common modules in pwsh...' 'STEP'
    & $pwsh -NoProfile -NonInteractive -Command $cmd | Out-Null
    Write-Log 'Module update step finished (best-effort).' 'OK'
  } catch {
    Write-Log "Module updates skipped/failed: $($_.Exception.Message)" 'WARN'
  }
}

function Update-PowerShellHelp {
  if ($SkipHelp) {
    Write-Log 'Skipping Update-Help (SkipHelp).' 'INFO'
    return
  }

  try {
    $pwsh = (Get-Command pwsh -ErrorAction Stop).Source
    Write-Log 'Running Update-Help in pwsh (best-effort)...' 'STEP'
    & $pwsh -NoProfile -NonInteractive -Command 'Update-Help -ErrorAction SilentlyContinue' | Out-Null
    Write-Log 'Update-Help finished (best-effort).' 'OK'
  } catch {
    Write-Log "Update-Help skipped/failed: $($_.Exception.Message)" 'WARN'
  }
}

# -------------------------------
# Main
# -------------------------------
Write-Log "WorkDir: $WorkDir" 'INFO'
Write-Log "LogFile: $LogFile" 'INFO'

Assert-Admin
Assert-NoPendingReboot

$installed = Get-InstalledPwshVersion
if ($installed) {
  Write-Log "Installed pwsh version detected: $installed" 'INFO'
} else {
  Write-Log 'No existing pwsh detected (fresh install path).' 'INFO'
}

Write-Log "Fetching PowerShell release info (channel=$Channel)..." 'STEP'
$rel = Get-PowerShellRelease -Channel $Channel

$tag = $rel.tag_name
if (-not $tag) { throw 'GitHub release has no tag_name.' }
$versionString = $tag.TrimStart('v')
$targetVersion = [version]$versionString

Write-Log "Target release: $tag" 'OK'

if ($installed -and ($installed -ge $targetVersion) -and (-not $Force)) {
  $msg = "Installed version ($installed) is already >= target ($targetVersion). Use -Force to reinstall." 
  if ($Silent) { throw $msg }

  $ans = Read-Host "$msg Continue anyway? (y/N)"
  if ($ans -notin @('y','Y','yes','YES')) { throw 'Aborted by user.' }
}

# Determine architecture for MSI
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
$msiArch = switch ($arch) {
  'x64'   { 'x64' }
  'x86'   { 'x86' }
  'arm64' { 'arm64' }
  default { throw "Unsupported OS architecture: $arch" }
}

$msiName = "PowerShell-$versionString-win-$msiArch.msi"
Write-Log "Selected MSI: $msiName" 'INFO'

$msiAsset = Get-Asset -Release $rel -Name $msiName
$hashAsset = Get-Asset -Release $rel -Name 'hashes.sha256'

$msiUrl  = $msiAsset.browser_download_url
$hashUrl = $hashAsset.browser_download_url

Assert-Https $msiUrl
Assert-Https $hashUrl

$msiPath  = Join-Path $WorkDir $msiName
$hashPath = Join-Path $WorkDir 'hashes.sha256'

Download-File -Url $hashUrl -OutFile $hashPath
Download-File -Url $msiUrl  -OutFile $msiPath

$expected = Get-ExpectedSha256FromHashesFile -HashesFile $hashPath -TargetFileName $msiName
Write-Log "Expected MSI SHA256: $expected" 'INFO'

Write-Log 'Verifying SHA256...' 'STEP'
Assert-FileHash -Path $msiPath -ExpectedSha256 $expected
Write-Log 'SHA256 verified.' 'OK'

Write-Log 'Verifying Authenticode signature...' 'STEP'
Assert-AuthenticodeValid -Path $msiPath
Write-Log 'Signature verified.' 'OK'

if ($PSCmdlet.ShouldProcess("PowerShell $targetVersion", 'Install/Update')) {
  $exit = Install-PowerShellMsi -MsiPath $msiPath
}

Warmup-Pwsh

$after = Get-InstalledPwshVersion
if (-not $after) {
  throw 'pwsh was not found after install. Check MSI log.'
}
Write-Log "pwsh after install: $after" 'OK'

Update-CommonModules
Update-PowerShellHelp

Show-Toast -Title 'PowerShell update complete' -Body "Installed/verified: $after"

Write-Log 'All done.' 'OK'
Write-Log "Artifacts in: $WorkDir" 'INFO'
Write-Log "MSI log: $MsiLog" 'INFO'

if ($exit -eq 3010) {
  Write-Log 'Reboot is recommended to finalize installation.' 'WARN'
  exit 3010
}

exit 0
