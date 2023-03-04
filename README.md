# PowerWash (PowerShell script)
Remove bloatware from Windows and optimize for low latency and high performance

## Setup
- Download `PowerWash.ps1`
- Make sure your [`ExecutionPolicy`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.3) allows scripts to run

## Usage
- Open a PowerShell prompt as an Administrator
- `cd` to the directory containing `PowerWash.ps1`
- **Suggested workflow:**
  - Ensure your system is in a state you can roughly replicate, eg same programs open, same devices connected
  - Run `.\PowerWash.ps1 /stats` to get a baseline reading of performance stats. (These are still in the works, but can already provide useful information!)
  - Run `.\PowerWash.ps1` and interactively select the changes you want to make. (To be completely thorough you would change only one, and repeat this workflow for each change)
  - Restart your computer and put it back into as close a state as it was before
  - Run `.\PowerWash.ps1 /stats` to get a new reading of performance stats. A comparison table between baseline and current will be shown, with absolute and percent change.
  - Retain settings that improve performance, whether by the displayed metrics or others such as LatencyMon (see below) or your impression of system responsiveness.
- Other usages:
  - **To see usage information:** `.\PowerWash.ps1 /?`
  - **To run PowerWash interactively (choose Y/N for each step):** `.\PowerWash.ps1`
  - **To run the full PowerWash suite and restart when done:** `.\PowerWash.ps1 /all /autorestart`
  - **To run the main PowerWash suite (without checking OS file integrity or installing gpedit):** `.\PowerWash.ps1 /all /noinstalls /noscans`


## How It Works
The default Windows installation has to cater to a very wide variety of users, and generally makes tradeoffs that sacrifice some degree of performance and responsiveness in exchange for power management, data collection, etc.

PowerWash modifies various aspects of your Windows installation. Instead of compromising performance for power efficiency, it configures your system to compromise power efficiency for low latency and high performance. (Note: Many of the changes intentionally do not apply when on battery)

Current features include:
- Running Microsoft's built-in [system file integrity checks](https://support.microsoft.com/en-us/topic/use-the-system-file-checker-tool-to-repair-missing-or-corrupted-system-files-79aa86cb-ca52-166a-92a3-966e85d4094e) to repair any corrupted system files
- Installing [Group Policy editor](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn265982(v=ws.11)), which presents a straightforward and well-documented interface to make system changes without manually editing the registry. Group Policy editor is a Microsoft product but does not come installed by default on Home editions of Windows.
- Disabling the high precision event timer (may improve DPC latency on some systems)
- Disabling automatic Windows updates (background updates can consume resources and automatic install/restart is often not wanted)
- Disabling Windows telemetry (telemetry can waste resources)
- Applying more aggressive [multimedia settings](https://learn.microsoft.com/en-us/windows/win32/procthread/multimedia-class-scheduler-service) (can improve performance of pro audio tasks)
- Enabling Microsoft's "Ultimate" performance power plan along with additional highly aggressive performance settings
- Disabling network adapter packet coalescing (can improve DPC latency for `ndis.sys`/`tcpip.sys`)
- Disabling Cortana
- Disabling Windows consumer features (e.g. third-party suggestions)
- Disabling preinstalled applications
- Only running Windows Defender scans when the computer is idle
- Disabling Fast Startup (can fix problems with some devices since Fast Startup skips some initialization)
- Enabling [message-signaled interrupts](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-message-signaled-interrupts) on all devices that support them (can improve interrupt latency)
- Prioritizing interrupts from devices like GPU and PCIe controller (may improve DPC/ISR latency)
- Checking for IRQ conflicts (these cannot be resolved automatically, though)
- Checking if a third-party antivirus is installed (Windows Defender is faster and better - third party antivirus must be uninstalled manually, though)

## Suggestions and Tips
- I recommend you use programs like [LatencyMon](https://www.resplendence.com/latencymon) and [WhySoSlow](https://www.resplendence.com/whysoslow) to benchmark your system before and after running PowerWash and any other optimizations.
- This script should be accompanied by a manual review of preinstalled programs, devices, services, etc. to disable or uninstall unwanted software.
- Adequate thermal management is imperative to stable device functioning. Make sure your device is being cooled adequately.
- You can also overclock CPU/GPU/RAM if needed, but this is a "brute force" approach and you should try to get performance as high as possible before resorting to this. May also compromise thermals, so make sure to use long-running stability tests like [Prime95](https://www.mersenne.org/download/) (CPU, RAM), [Kombustor](https://geeks3d.com/furmark/kombustor/) (CPU, GPU), and [Memtest86](https://www.memtest86.com/) (RAM).
- Using SSD instead of HDD, and NVMe instead of SATA, can drastically improve system responsiveness and application load times, though likely won't help with interrupt latency.
- Make sure all drivers are up to date. Perform clean installs where possible.
- Always back up your system before running PowerWash or making any other system configuration changes.
- Obviously, all of this is "use at your own risk"
