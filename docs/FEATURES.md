## How It Works
The default Windows installation has to cater to a very wide variety of users, and generally makes tradeoffs that sacrifice some degree of performance and responsiveness in exchange for power management, data collection, etc.

PowerWash modifies various aspects of your Windows installation. It configures your system to aggressively choose maximum performance and minimum latency over power saving. (Note: Many of the changes intentionally do not apply when on battery)

_Disclaimer: See [LICENSE](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/LICENSE) for license details; [LIMITATIONS.md](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/LIMITATIONS.md) for limitations and additional caveats. While the author's testing on virtual and physical machines has consistently shown stability and performance gains, this software makes many changes to your system which are discouraged or completely unsupported by Microsoft. This software may break your system. Always make backups. In any situation where any text in this repository contradicts the LICENSE linked earlier, the LICENSE takes priority._

**Current features include:**

All editions of Windows:
- Running Microsoft's built-in [system file integrity checks](https://support.microsoft.com/en-us/topic/use-the-system-file-checker-tool-to-repair-missing-or-corrupted-system-files-79aa86cb-ca52-166a-92a3-966e85d4094e) to repair any corrupted system files
- Disabling the [high precision event timer](https://en.wikipedia.org/wiki/High_Precision_Event_Timer) (may improve DPC latency on some systems)
- Applying more aggressive [multimedia settings](https://learn.microsoft.com/en-us/windows/win32/procthread/multimedia-class-scheduler-service) (can improve performance of pro audio tasks)
- Enabling Microsoft's ["Ultimate" performance power plan](https://social.technet.microsoft.com/wiki/contents/articles/52059.windows-10-the-ultimate-performance-power-policy.aspx) along with additional [highly aggressive performance settings](https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/hardware/power/power-performance-tuning)
- Enabling [hardware-accelerated GPU scheduling](https://devblogs.microsoft.com/directx/hardware-accelerated-gpu-scheduling/) (can reduce graphics latency)
- Disabling network adapter packet coalescing (can improve DPC latency for `ndis.sys`/`tcpip.sys`)
- Disabling or uninstalling Cortana
- Disabling and/or removing preinstalled applications and unwanted Windows features
- Uninstalling Edge (though at the time of writing, some traces do remain)
- Only running Windows Defender scans when the computer is idle; reducing priority of Defender tasks; optionally disabling Defender real-time protection
- Disabling Windows Defender Real-Time Protection, or disabling Windows Defender entirely (antivirus can reduce performance) (CAUTION: This WILL make your device less secure. This is also a highly experimental feature! All features here are use-at-your-own-risk, but this one especially!)
- Disabling [Fast Startup](https://www.makeuseof.com/what-is-windows-fast-startup-why-disable-it) (can fix problems with some devices since Fast Startup skips some initialization)
- Enabling [message-signaled interrupts](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-message-signaled-interrupts) on all devices that support them (can improve interrupt latency)
- Prioritizing interrupts from devices like GPU and PCIe controller (may improve DPC/ISR latency)
- Checking for IRQ conflicts (these cannot be resolved automatically, though)
- Checking if a third-party antivirus is installed (Windows Defender is faster and better - third party antivirus must be uninstalled manually, though)
- Partially disabling Windows telemetry (telemetry can waste resources) (Note: Windows Pro and Enterprise/Education offer more built-in control of this)

Windows Home edition only:
- Installing [Group Policy editor](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn265982(v=ws.11)), which presents a straightforward and well-documented interface to make system changes without manually editing the registry. Group Policy editor is a Microsoft product but does not come installed by default on Home editions of Windows.

Windows Pro edition only:
- Disabling automatic Windows updates (background updates can consume resources and automatic install/restart is often not wanted)
- Mostly disabling Windows telemetry (telemetry can waste resources) (Note: some minimal telemetry may still make it through; only Enterprise explicitly supports completely disabling this)

Windows Enterprise or Education edition only:
- Completely disabling Windows telemetry
- Disabling [Windows consumer features](https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.CloudContent::DisableWindowsConsumerFeatures) (e.g. third-party suggestions) (Works on Enterprise/Education only)

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
- After installing a Windows update, you may need to re-run PowerWash as updates have been known to spontaneously re-enable certain features.
- Obviously, all of this is "use at your own risk"

## Special Thank-Yous
- While many freely available sites have contributed valuable knowledge in the development of this script, I especially want to thank the maintainers of [admx.help](https://admx.help) for providing an easy-to-use and comprehensive inventory of Group Policy and associated registry settings. Also, as bad a reputation as Microsoft has for user-friendliness, their technical documentation at [learn.microsoft.com](https://learn.microsoft.com) is generally very high quality.
- All beta testers
