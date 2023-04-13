# PowerWash (PowerShell script)
Remove bloatware from Windows and optimize for low latency and high performance

**NOTE:** This script is NOT designed to repair a broken/corrupted Windows installation! It is designed to run on a fully functioning system and further optimize it for high-performance use cases. A clean install prior to using this is ideal!

## Setup
- Download [`PowerWash.ps1`](https://raw.githubusercontent.com/UniverseCraft/WindowsPowerWash/main/PowerWash.ps1) and [`PowerWashSettings.json`](https://raw.githubusercontent.com/UniverseCraft/WindowsPowerWash/main/PowerWashSettings.json)
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
  - **To run the actions configured in `PowerWashSettings.json`:** `.\PowerWash.ps1 /config`
  - **To run the full PowerWash suite and restart when done:** `.\PowerWash.ps1 /all /autorestart`
  - **To run the main PowerWash suite (without checking OS file integrity or installing gpedit):** `.\PowerWash.ps1 /all /noinstalls /noscans`


## How It Works
The default Windows installation has to cater to a very wide variety of users, and generally makes tradeoffs that sacrifice some degree of performance and responsiveness in exchange for power management, data collection, etc.

PowerWash modifies various aspects of your Windows installation. Instead of compromising performance for power efficiency, it configures your system to compromise power efficiency for low latency and high performance. (Note: Many of the changes intentionally do not apply when on battery)

Current features include:
- Running Microsoft's built-in [system file integrity checks](https://support.microsoft.com/en-us/topic/use-the-system-file-checker-tool-to-repair-missing-or-corrupted-system-files-79aa86cb-ca52-166a-92a3-966e85d4094e) to repair any corrupted system files
- Installing [Group Policy editor](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn265982(v=ws.11)), which presents a straightforward and well-documented interface to make system changes without manually editing the registry. Group Policy editor is a Microsoft product but does not come installed by default on Home editions of Windows.
- Disabling the [high precision event timer](https://en.wikipedia.org/wiki/High_Precision_Event_Timer) (may improve DPC latency on some systems)
- Disabling automatic Windows updates (background updates can consume resources and automatic install/restart is often not wanted) (Note: These can't fully be disabled on Home editions without disabling updates completely)
- Disabling Windows telemetry (telemetry can waste resources)
- Applying more aggressive [multimedia settings](https://learn.microsoft.com/en-us/windows/win32/procthread/multimedia-class-scheduler-service) (can improve performance of pro audio tasks)
- Enabling Microsoft's ["Ultimate" performance power plan](https://social.technet.microsoft.com/wiki/contents/articles/52059.windows-10-the-ultimate-performance-power-policy.aspx) along with additional [highly aggressive performance settings](https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/hardware/power/power-performance-tuning)
- Enabling [hardware-accelerated GPU scheduling](https://devblogs.microsoft.com/directx/hardware-accelerated-gpu-scheduling/) (can reduce graphics latency)
- Disabling network adapter packet coalescing (can improve DPC latency for `ndis.sys`/`tcpip.sys`)
- Disabling Cortana
- Disabling [Windows consumer features](https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.CloudContent::DisableWindowsConsumerFeatures) (e.g. third-party suggestions) (Works on Enterprise/Education only)
- Disabling and/or removing preinstalled applications
- Only running Windows Defender scans when the computer is idle; reducing priority of Defender tasks; optionally disabling Defender real-time protection
- Disabling Windows Defender Real-Time Protection, or disabling Windows Defender entirely (antivirus can reduce performance) (CAUTION: This WILL make your device less secure. This is also a highly experimental feature! All features here are use-at-your-own-risk, but this one especially!)
- Disabling [Fast Startup](https://www.makeuseof.com/what-is-windows-fast-startup-why-disable-it) (can fix problems with some devices since Fast Startup skips some initialization)
- Enabling [message-signaled interrupts](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-message-signaled-interrupts) on all devices that support them (can improve interrupt latency)
- Prioritizing interrupts from devices like GPU and PCIe controller (may improve DPC/ISR latency)
- Checking for IRQ conflicts (these cannot be resolved automatically, though)
- Checking if a third-party antivirus is installed (Windows Defender is faster and better - third party antivirus must be uninstalled manually, though)

There are some additional "nice-to-have"s that aren't regularly available through the Windows Settings UI, like showing seconds in the taskbar clock, showing "Run as different user" in the Start menu, and showing file extensions and hidden items in Explorer. This script can optionally also install [Winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/) and a configurable list of applications available through it.

All of the above features are configurable using the provided `PowerWashSettings.json`. To apply the settings in that file, run PowerWash with the `/config` flag. Otherwise, those settings will not be used!

## Suggestions and Tips
- I recommend you use programs like [LatencyMon](https://www.resplendence.com/latencymon) and [WhySoSlow](https://www.resplendence.com/whysoslow) to benchmark your system before and after running PowerWash and any other optimizations.
- This script should be accompanied by a manual review of preinstalled programs, devices, services, etc. to disable or uninstall unwanted software.
- Adequate thermal management is imperative to stable device functioning. Make sure your device is being cooled adequately.
- You can also overclock CPU/GPU/RAM if needed, but this is a "brute force" approach and you should try to get performance as high as possible before resorting to this. May also compromise thermals, so make sure to use long-running stability tests like [Prime95](https://www.mersenne.org/download/) (CPU, RAM), [Kombustor](https://geeks3d.com/furmark/kombustor/) (CPU, GPU), and [Memtest86](https://www.memtest86.com/) (RAM).
- Using SSD instead of HDD, and NVMe instead of SATA, can drastically improve system responsiveness and application load times, though likely won't help with most causes of high interrupt latency.
- Make sure all drivers are up to date. When installing or reinstalling, __perform clean installs where possible__.
- Always back up your system before running PowerWash or making any other system configuration changes.
- Obviously, all of this is "use at your own risk"

## Special Thank-Yous
- While many freely available sites have contributed valuable knowledge in the development of this script, I especially want to thank the maintainers of [admx.help](https://admx.help) for providing an easy-to-use and comprehensive inventory of Group Policy and associated registry settings. Also, as bad a reputation as Microsoft has for user-friendliness, their technical documentation at [learn.microsoft.com](https://learn.microsoft.com) is generally very high quality.
- All beta testers
