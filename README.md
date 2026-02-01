# PowerShell Updater (Windows)

A self-contained script that installs/updates PowerShell 7 on Windows using **official GitHub releases**.

## Download

- Script: `update-powershell.ps1`

### One-liner download (PowerShell)

```powershell
iwr -UseBasicParsing "https://raw.githubusercontent.com/TheParadoxGOD/powershell-updater/main/update-powershell.ps1" -OutFile "$env:USERPROFILE\Downloads\update-powershell.ps1"
```

## Run

```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Downloads\update-powershell.ps1"
```

## Options

```powershell
# Stable (default)
.\update-powershell.ps1

# Preview channel
.\update-powershell.ps1 -Channel preview

# LTS line (7.4.x)
.\update-powershell.ps1 -Channel lts

# Non-interactive
.\update-powershell.ps1 -Silent

# Force reinstall
.\update-powershell.ps1 -Force

# Skip module/help updates
.\update-powershell.ps1 -SkipModules -SkipHelp
```

## Notes

- Verifies SHA256 via `hashes.sha256` and verifies MSI Authenticode signature before installing.
- Logs and downloaded artifacts are stored under `%TEMP%\PowerShellUpdater_<timestamp>`.
