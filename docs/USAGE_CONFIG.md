<sup>[← Back to home](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/README.md)</sup>

## Using PowerWash with a configuration file
This short guide shows you how to configure PowerWash ahead of time with what features you want to run.

### Setup
- You will need to download two files: [`PowerWash.ps1`](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/PowerWash.ps1) and [`PowerWashSettings.json`](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/PowerWash.ps1).
- Modify your downloaded `PowerWashSettings.json` to enable/disable the features you want to use. For example, if you want to automatically restart when it finishes, change `"AutoRestart": true` to `"AutoRestart": false`.
  - You can also customize the list of preinstalled apps to remove and the list of apps to install with Winget. These will only be executed if `"RemovePreinstalled"` and `"InstallConfigured"`, respectively, are set to `true`.
- Make sure your [`ExecutionPolicy`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.3) allows scripts to run

### Usage
- Open a PowerShell prompt as an Administrator
- `cd` to the directory containing `PowerWash.ps1`, e.g. `cd C:\Users\User\Downloads`
- Run PowerWash with `.\PowerWash.ps1 /config`. The `/config` option tells PowerWash to use the settings from `PowerWashSettings.json` rather than prompting the user. You will not be prompted at any point during execution.
