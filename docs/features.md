<sup>[← Back to home](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/README.md)</sup>

## How It Works
The default Windows installation has to cater to a very wide variety of users, and generally makes tradeoffs that sacrifice some degree of performance and responsiveness in exchange for power management, data collection, etc.

PowerWash modifies various aspects of your Windows installation. It configures your system to aggressively choose maximum performance and minimum latency over power saving. (Note: Many of the changes intentionally do not apply when on battery). It also removes bloatware and unwanted default programs, and generally cleans up the out-of-box experience. It does this through a combination of registry changes, application package removals, PowerShell cmdlets, and more.

### Highlights

These are some of the most commonly wanted modifications to a standard Windows install, and PowerWash has all of them!
- Disable Microsoft **telemetry** / "phoning home"
- Disable **automatic updates**
- Remove useless **preinstalled applications** -- including **Microsoft Edge**, if desired
- Throttle "**MsMpEng**.exe" / "Antimalware Service Executable"
- Configure and activate **maximum performance** power plan

## Full Listing

*Note that some editions of Windows do not have the necessary components to support certain PowerWash features. PowerWash does not impose any artificial limitations and the author continues to look for ways around Microsoft's. All features listed below are optional and configurable using the provided [`PowerWashSettings.yml`](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/PowerWashSettings.yml). (See [the documentation](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/docs/USAGE_CONFIG.md)).*

*While PowerWash works as expected on Enterprise, it does not work as expected on Enterprise LTSB/LTSC. These editions are missing certain components that are vital to application package management. Most performance settings work as expected, but not bloatware removal or custom software installation.*


### System Configuration - Performance

| Feature | Works on Windows Home | Works on Windows Pro | Works on Windows Enterprise/Education | Description |
| ------- | :----: | :---: | :--------------------: | ----------- |
| Disable HPET | ✅ | ✅ | ✅ | Disabling the [high precision event timer](https://en.wikipedia.org/wiki/High_Precision_Event_Timer) may improve DPC latency on some systems |
| Aggressive multimedia settings | ✅ | ✅ | ✅ | Applying more aggressive [multimedia settings](https://learn.microsoft.com/en-us/windows/win32/procthread/multimedia-class-scheduler-service) can improve performance of pro audio tasks |
| "Ultimate" performance power plan | ✅ | ✅ | ✅ | Enables Microsoft's ["Ultimate" performance power plan](https://social.technet.microsoft.com/wiki/contents/articles/52059.windows-10-the-ultimate-performance-power-policy.aspx) along with additional [highly aggressive performance settings](https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/hardware/power/power-performance-tuning) |
| Accelerated GPU scheduling | ✅ | ✅ | ✅ | Enabling [hardware-accelerated GPU scheduling](https://devblogs.microsoft.com/directx/hardware-accelerated-gpu-scheduling/) can reduce graphics latency |
| Aggressive network adapter settings | ✅ | ✅ | ✅ | Disabling network adapter packet coalescing and similar options can improve DPC latency for `ndis.sys`/`tcpip.sys` |
| Disable Fast Startup | ✅ | ✅ | ✅ | Disabling [Fast Startup](https://www.makeuseof.com/what-is-windows-fast-startup-why-disable-it) can fix problems with some devices since Fast Startup skips some initialization |
| Enable message-signaled interrupts | ✅ | ✅ | ✅ | Enabling [message-signaled interrupts](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-message-signaled-interrupts) on all devices that support them can improve interrupt latency |
| Prioritize GPU and PCIe controller | ✅ | ✅ | ✅ | May improve DPC/ISR latency for tasks where high regularity is preferred |
| Disable automatic Windows updates | ❌ | ✅ | ✅ | Background updates can unexpectedly consume resources and automatic install/restart is typically not wanted. | 
| Disable all Windows updates | ✅ | ✅ | ✅ | Completely disables the Windows Update feature, disabling both automatic and manual updates. |
| Toggle Windows updates | ✅ | ✅ | ✅ | Adds a script to your desktop to toggle the Windows Update feature on/off. **This is the best compromise for Home editions** |
| Disable Windows consumer features | ❌ | ❌ | ✅ | Disables [Windows consumer features](https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.CloudContent::DisableWindowsConsumerFeatures) (e.g. third-party suggestions) |
| Throttle "Antimalware Service Executable" | ✅ | ✅ | ✅ | Configures Windows Defender to only run scans when the computer is idle; reduces priority of Defender tasks and limits their CPU usage |
| Disable Defender Real-Time Protection | ⚠️ | ⚠️ | ⚠️ | CAUTION: This will make your device less secure. Requires Tamper Protection to be disabled. Not recommended and still experimental. |
| Disable Defender entirely | ⚠️ | ⚠️ | ⚠️ | CAUTION: This will make your device less secure. Requires Tamper Protection to be disabled. Not recommended and still experimental. |
| Disable Windows telemetry | ◑ | ◕ | ✅ | Home edition can disable some telemetry; Pro edition can disable most telemetry; Enterprise/Education can disable all telemetry |

### System Configuration - Usability

| Feature | Works on Windows Home | Works on Windows Pro | Works on Windows Enterprise/Education | Description |
| ------- | :----: | :---: | :--------------------: | ----------- |
| Show seconds in taskbar clock | ✅ | ✅ | ✅ | |
| Show "Run as different user" in Start menu | ✅ | ✅ | ✅ | |
| Show file extensions and hidden items in Explorer | ✅ | ✅ | ✅ | |
| Clean up default taskbar | ✅ | ✅ | ✅ | Mainly geared toward fresh installs of Windows |

### Bloatware Removal

| Feature | Works on Windows Home | Works on Windows Pro | Works on Windows Enterprise/Education | Description |
| ------- | :----: | :---: | :--------------------: | ----------- |
| Disable/uninstall Cortana | ✅ | ✅| ✅ | Most people find Cortana a nuisance |
| Remove preinstalled applications | ✅ | ✅ | ✅ | Removes Skype, Teams, Xbox, News/Weather, Solitaire Collection, etc. [This list is configurable!](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/docs/USAGE_CONFIG.md) |
| Remove phantom applications | ✅ | ✅ | ✅ | (BETA) Removes remnants of uninstalled applications from the registry. This can sometimes have a modest impact on performance, e.g. when the system is frequently looking up a large number of paths that don't exist. We can't remove every single reference to the application, but we can clean house quite a bit. |
| Remove Microsoft Edge | ✅ | ✅ | ✅ | Thoroughly removes Microsoft Edge. While some small traces in the filesystem/registry may remain, this removes the vast majority of it and all visible signs. Requires a restart to take full effect. Requires SQLite- this will be installed automatically if needed. |

### Software Installation

| Feature | Works on Windows Home | Works on Windows Pro | Works on Windows Enterprise/Education | Description |
| ------- | :----: | :---: | :--------------------: | ----------- |
| Install Group Policy Editor | ✅ | N/A | N/A | Installs [Group Policy editor](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn265982(v=ws.11)), which presents a straightforward and well-documented interface to make system changes without manually editing the registry. Group Policy editor is a Microsoft product but does not come installed by default on Home editions of Windows. |
| Install Winget | ✅ | ✅ | ✅ | See [https://learn.microsoft.com/en-us/windows/package-manager/winget/](https://learn.microsoft.com/en-us/windows/package-manager/winget/) |
| Install free utilities and replacements for Microsoft bloatware | ✅ | ✅ | ✅ | [This list is configurable!](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/docs/USAGE_CONFIG.md) |

### Scans and checks

| Feature | Works on Windows Home | Works on Windows Pro | Works on Windows Enterprise/Education | Description |
| ------- | :----: | :---: | :--------------------: | ----------- |
| System integrity checks | ✅ | ✅ | ✅ | Runs Microsoft's built-in [system file integrity checks](https://support.microsoft.com/en-us/topic/use-the-system-file-checker-tool-to-repair-missing-or-corrupted-system-files-79aa86cb-ca52-166a-92a3-966e85d4094e) to repair any corrupted system files |
| Check for IRQ conflicts | ✅ | ✅ | ✅ | Sharing interrupt request lines among multiple devices can degrade performance. This cannot be fixed from within the software. | 
| Warn if third-party antivirus found | ✅ | ✅ | ✅ | Windows Defender is generally faster and better; third-party antivirus software can slow the system down substantially - must be uninstalled manually, though |

## Suggestions and Tips
- I recommend you use programs like [LatencyMon](https://www.resplendence.com/latencymon) and [WhySoSlow](https://www.resplendence.com/whysoslow) to benchmark your system before and after running PowerWash and any other optimizations.
- This script should be accompanied by a manual review of preinstalled programs, devices, services, etc. to disable or uninstall unwanted software.
- Adequate thermal management is imperative to stable device functioning. Make sure your device is being cooled adequately.
- You can also overclock CPU/GPU/RAM if needed, but this is a "brute force" approach and you should try to get performance as high as possible before resorting to this. May also compromise thermals, so make sure to use long-running stability tests like [Prime95](https://www.mersenne.org/download/) (CPU, RAM), [Kombustor](https://geeks3d.com/furmark/kombustor/) (CPU, GPU), and [Memtest86](https://www.memtest86.com/) (RAM).
- Using SSD instead of HDD, and NVMe instead of SATA, can drastically improve system responsiveness and application load times, though likely won't help with most causes of high interrupt latency.
- Make sure all drivers are up to date. When installing or reinstalling, __perform clean installs where possible__.
- Always back up your system before running PowerWash or making any other system configuration changes.
- After installing a Windows update, you may need to re-run PowerWash as updates have been known to spontaneously re-enable certain features.
- Obviously, all of this is "use at your own risk"

## Special Thank-Yous
- While many freely available sites have contributed valuable knowledge in the development of this script, I especially want to thank the maintainers of [admx.help](https://admx.help) for providing an easy-to-use and comprehensive inventory of Group Policy and associated registry settings. Also, as bad a reputation as Microsoft has for user-friendliness, their technical documentation at [learn.microsoft.com](https://learn.microsoft.com) is generally very high quality.
- All beta testers
