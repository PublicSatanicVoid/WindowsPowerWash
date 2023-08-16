# PowerWash: Reclaim Windows
### Improve performance ・ Harden security ・ Remove bloatware ・ Cleanup UI ・ Configurable
The fresh, snappy out-of-box experience you've always wanted in Windows - ready in minutes. Optimized for high-performance, low-latency applications. Removes MS/OEM bloatware, telemetry, and applies aggressive performance settings, including many that are normally hidden from the user. Works on a new or existing Windows installation.

### [Click here for features list](https://publicsatanicvoid.github.io/WindowsPowerWash/docs/features)
* Includes the MOST COMPLETE known Microsoft Edge removal process as of 5/20/23

**Quick start:** Open an admin PowerShell prompt and enter:

```curl -o bootstrap-manual.ps1 github.com/PublicSatanicVoid/WindowsPowerWash/raw/main/autodeploy/bootstrap-manual.ps1; Set-ExecutionPolicy Unrestricted -Force; .\bootstrap-manual.ps1```

Just here for the **MS Edge Removal Tool**? Open an admin PowerShell prompt and enter:

```curl -o MSERT.ps1 github.com/PublicSatanicVoid/WindowsPowerWash/raw/main/MSERT.ps1; Set-ExecutionPolicy Unrestricted -Force; .\MSERT.ps1```

## About PowerWash

The default Windows installation has to cater to a very wide variety of users and bring in advertising revenue. This requires tradeoffs that sacrifice some degree of performance and responsiveness in exchange for power efficiency, data collection, etc. Many "technical" users find the default user experience annoying and inconvenient. **PowerWash removes annoying, bloated, and unperformant parts of Windows** and can also install helpful utilities automatically, improve baseline security, and configure settings for higher performance.

I created PowerWash because I believe that underneath the cruft (ads, bloatware, telemetry, forced automatic updates, and [blatant lies](https://publicsatanicvoid.github.io/WindowsPowerWash/docs/windows-lies)) Windows is fundamentally a great operating system, and it shouldn't be so difficult to make it great. Many debloater tools are themselves bloatware, or don't let you configure things easily, or just don't work. PowerWash takes the good stuff from what's already been done and adds even more good stuff. Also, it's actively maintained and 100% open-source. [Read more about the philosophy behind PowerWash »](https://publicsatanicvoid.github.io/WindowsPowerWash/docs/philosophy)



## Using PowerWash
There are three ways PowerWash is designed to be used:

### Interactive mode *(default)*
In this mode, you are prompted step-by-step to decide which PowerWash features to run.
This is helpful for first-time PowerWash users.
[Guide to interactive mode »](https://publicsatanicvoid.github.io/WindowsPowerWash/docs/usage/interactive)

### Configuration mode *(most flexible)*
In this mode, you edit `PowerWashSettings.yml` to toggle the features that you want PowerWash to run.
This is helpful for automating the process and lets you configure what programs to install/uninstall.
[Guide to configuration mode »](https://publicsatanicvoid.github.io/WindowsPowerWash/docs/usage/config)

### Deployment mode *(most automated)*
In this mode, PowerWash automatically runs when installing Windows from a USB drive.
This is helpful for automating the process when you frequently install/reinstall Windows or want to start multiple devices from the same pre-configured point.
[Guide to deployment mode »](https://universecraft.github.io/WindowsPowerWash/docs/usage/deployment)

## Additional recommendations
PowerWash should be used as part of a comprehensive approach to optimizing and securing your system.

**NOTE:** This script is NOT designed to repair a broken/corrupted Windows installation! It is designed to run on a fully functioning system and further optimize it for high-performance use cases. A clean install prior to using this is ideal! (In fact, you can even [load PowerWash onto Windows installation media!](https://publicsatanicvoid.github.io/WindowsPowerWash/docs/usage/deployment))

**Security.** To maximize security without sacrificing performance, I recommend the following in addition to PowerWash:
- Using an enterprise version of Microsoft Defender, such as [Defender for Business](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-business)
  - Monthly subscription costs ~$4/month if you have an email under a custom domain name
  - This will allow you to fully benefit from the Attack Surface Reduction and other security rules enabled by PowerWash
  - Third-party antivirus solutions tend to slow down your device substantially and are often intrusive / hard to uninstall. All editions of Defender are from Microsoft and integrate much better with Windows.
- Using a long-term support version of Windows, such as [IoT Enterprise LTSC](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-business)
  - Permanent license keys are available from reputable websites for ~$12
- Setting up [BitLocker drive encryption](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)
  - Hardware encryption will provide better performance than software encryption
- Using a browser like [Brave](https://brave.com/) for better tracking prevention (and speed!) and a VPN like [NordVPN](https://nordvpn.com/) for better anonymity.
- Disabling the [Intel Management Engine](https://en.wikipedia.org/wiki/Intel_Management_Engine): Your UEFI settings may allow you to disable it, otherwise you will have to flash an updated [flash descriptor region](https://opensecuritytraining.info/IntroBIOS_files/Day2_02_Advanced%20x86%20-%20BIOS%20and%20SMM%20Internals%20-%20Flash%20Descriptor.pdf) to [set the HAP/AltMeDisable bit](https://github.com/corna/me_cleaner/wiki/HAP-AltMeDisable-bit) (this is risky, so be sure to check that you are changing the correct strap settings for your ME version!). The Intel Management Engine is a highly privileged core embedded into modern Intel CPUs (AMD CPUs have the similar Platform Security Processor) with direct and independent access to RAM and networking. It has had several [critical vulnerabilities](https://en.wikipedia.org/wiki/Intel_Management_Engine#Security_vulnerabilities) discovered that can completely compromise a system and embed themselves invisibly to the user. In response, the NSA requested the addition of a kill switch that disables all nonessential functions of the management engine. This is the "High Assurance Platform" (HAP) bit, or on earlier (<11) versions of the management engine, the "Alt ME Disable" bit. _Removing the Intel Management Engine Interface driver is NOT enough to disable the management engine itself!_

**Device Health.** Keep up with regular hardware and software maintenance tasks, including but not limited to: running the Disk Cleanup and Defragment utilities, installing Windows/driver/firmware updates, running DISM and SFC to check for corrupted system files, removing unused programs and files, uninstalling or disabling unused devices, cleaning computer fans, and periodically stress-testing your system to ensure it remains stable under load.

**Performance.** Some user reports have indicated that disabling virtualization and/or hyperthreading can modestly improve latency. This does make sense logically, so if your latencies are too high, feel free to try this - it should be perfectly safe, and you can always go back.

## Disclaimer
See [LICENSE](https://github.com/PublicSatanicVoid/WindowsPowerWash/tree/main/LICENSE) for license details; [LIMITATIONS.md](https://publicsatanicvoid.github.io/WindowsPowerWash/docs/limitations) for limitations and additional caveats. This software makes many changes to your system, some of which are discouraged or completely unsupported by Microsoft. This software may (depending on user configuration) modify registry settings, uninstall certain Windows applications, or otherwise perform actions commonly considered destructive. While the author's testing on virtual and physical machines has consistently shown stability and performance gains, no amount of testing is perfect, documentation is sometimes wrong, and I can't guarantee your system will be stable if you use any component of this software. You **use this at your own risk** and are strongly encouraged to make sure you understand the features you plan to use prior to using them. This software may break your system. Always make backups. In any situation where any text in this repository contradicts the LICENSE linked earlier, the LICENSE takes priority.

**Known Issues:**
- Desktop background may go black intermittently after applying recommended security settings in strict or extra strict mode.
  - *Workaround:* Set the desktop background again. Somehow this seems to fix it... solution as strange as problem.
- Microsoft Edge reappears in the start menu / search after removing it
  - Don't worry, it wasn't actually reinstalled. This is a defunct shortcut-y thing that Microsoft put there.
  - *Workaround 1:* Run the removal tool again to remove the shortcut again.
  - *Workaround 2:* Run the removal tool again and disable *ALL* updates. It won't come back again until you re-enable updates.

## Special Thank-Yous and Credits
- While many freely available sites have contributed valuable knowledge in the development of this script, I especially want to thank the maintainers of [admx.help](https://admx.help) for providing an easy-to-use and comprehensive inventory of Group Policy and associated registry settings, as well as [DoD Cyber Exchange's list of STIGs](https://public.cyber.mil/stigs/), [Windows Security Encyclopedia](https://www.windows-security.org/), and [Unified Compliance's STIG Viewer](https://stigviewer.com/) for their inventories of Windows security settings and recommendations; these have all been used in the development of PowerWash's "Apply recommended security settings" feature. Also, as bad a reputation as Microsoft has for user-friendliness, their technical documentation at [learn.microsoft.com](https://learn.microsoft.com) is generally very high quality.
- Previous de-bloating work, in particular this list of bloatware packages by [Sycnex](https://github.com/Sycnex/Windows10Debloater/blob/master/Windows10Debloater.ps1#L53), incorporated into `PowerWashSettings.yml`
- All beta testers
