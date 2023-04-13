## PowerWash: Interactive Usage Guide
This short guide walks you through how to use PowerWash in the "interactive usage" mode, which prompts you whether to enable each feature.

### Setup
- You only need to download [`PowerWash.ps1`](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/PowerWash.ps1) to use PowerWash interactively.
  - If you want to remove bloatware programs or install custom programs with PowerWash, you also need to download [`PowerWashSettings.json`](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/PowerWashSettings.json)
- Make sure your [`ExecutionPolicy`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.3) allows scripts to run

### Usage: Standard
- Open a PowerShell prompt as an Administrator
- `cd` to the directory containing `PowerWash.ps1`, e.g.: `cd C:\Users\User\Downloads`
- Run PowerWash: `.\PowerWash.ps1`
- You will be prompted step by step which PowerWash features you want to use.

### Usage: Benchmarking (recommended, but slower)
- Open a PowerShell prompt as an Administrator
- `cd` to the directory containing `PowerWash.ps1`, e.g.: `cd C:\Users\User\Downloads`
- Ensure your system is in a state you can roughly replicate, eg same programs open, same devices connected
- Run `.\PowerWash.ps1 /stats` to get a baseline reading of performance stats. (These are still in the works, but can already provide useful information!)
- Run `.\PowerWash.ps1` and interactively select the changes you want to make. (To be completely thorough you would change only one, and repeat this workflow for each change)
- Restart your computer and put it back into as close a state as it was before
- Run `.\PowerWash.ps1 /stats` to get a new reading of performance stats. A comparison table between baseline and current will be shown, with absolute and percent change.
- Retain settings that improve performance, whether by the displayed metrics or others such as LatencyMon (see [`FEATURES.md`](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/FEATURES.md)) or your impression of system responsiveness.
