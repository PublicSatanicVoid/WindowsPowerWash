# PowerWash: Reclaim Windows
### Improve performance ・ Disable updates ・ Remove bloatware ・ Cleanup UI ・ Configurable
The fresh, snappy out-of-box experience you've always wanted in Windows - ready in minutes. Optimized for high-performance, low-latency applications. Removes MS/OEM bloatware, telemetry, and applies aggressive performance settings, including many that are normally hidden from the user. Works on a new or existing Windows installation.

### [Click here for features list](https://universecraft.github.io/WindowsPowerWash/docs/features)
* Includes the MOST COMPLETE known Microsoft Edge removal process as of 5/20/23

**Quick start:** Open an admin PowerShell prompt and enter:

```curl -o bootstrap-manual.ps1 github.com/UniverseCraft/WindowsPowerWash/raw/main/autodeploy/bootstrap-manual.ps1; Set-ExecutionPolicy Unrestricted -Force; .\bootstrap-manual.ps1```

Just here for the **MS Edge Removal Tool**? Open an admin PowerShell prompt and enter:

```curl -o MSERT.ps1 github.com/UniverseCraft/WindowsPowerWash/raw/main/MSERT.ps1; Set-ExecutionPolicy Unrestricted -Force; .\MSERT.ps1```

## About PowerWash

The default Windows installation has to cater to a very wide variety of users and bring in advertising revenue. This requires tradeoffs that sacrifice some degree of performance and responsiveness in exchange for power efficiency, data collection, etc. Many "technical" users find the default user experience annoying and inconvenient. **PowerWash removes annoying, bloated, and unperformant parts of Windows** and can also install helpful utilities automatically and configure settings for higher performance.

I created PowerWash because I believe that underneath the cruft (ads, bloatware, telemetry, forced automatic updates, and [blatant lies](https://universecraft.github.io/WindowsPowerWash/docs/windows-lies)) Windows is fundamentally a great operating system, and it shouldn't be so difficult to make it great. Many debloater tools are themselves bloatware, or don't let you configure things easily, or just don't work. PowerWash takes the good stuff from what's already been done and adds even more good stuff. Also, it's actively maintained and 100% open-source. [Read more about the philosophy behind PowerWash »](https://universecraft.github.io/WindowsPowerWash/docs/philosophy)



## Using PowerWash
There are three ways PowerWash is designed to be used:

### Interactive mode (default)
In this mode, you are prompted step-by-step to decide which PowerWash features to run.
This is helpful for first-time PowerWash users.
[Guide to interactive mode »](https://universecraft.github.io/WindowsPowerWash/docs/usage/interactive)

### Configuration mode
In this mode, you edit `PowerWashSettings.yml` to toggle the features that you want PowerWash to run.
This is helpful for automating the process and lets you configure what programs to install/uninstall.
[Guide to configuration mode »](https://universecraft.github.io/WindowsPowerWash/docs/usage/config)

### Deployment mode
In this mode, PowerWash automatically runs when installing Windows from a USB drive.
This is helpful for automating the process when you frequently install/reinstall Windows or want to start multiple devices from the same pre-configured point.
[Guide to deployment mode »](https://universecraft.github.io/WindowsPowerWash/docs/usage/deployment)

## Additional recommendations
PowerWash should be used as part of a comprehensive approach to optimizing and securing your system.

**NOTE:** This script is NOT designed to repair a broken/corrupted Windows installation! It is designed to run on a fully functioning system and further optimize it for high-performance use cases. A clean install prior to using this is ideal! (In fact, you can even [load PowerWash onto Windows installation media!](https://universecraft.github.io/WindowsPowerWash/docs/usage/deployment))

**Security.** To maximize security without sacrificing performance, I recommend the following in addition to PowerWash:
- Using an enterprise version of Microsoft Defender, such as [Defender for Business](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-business)
  - Monthly subscription costs ~$4/month if you have an email under a custom domain name
  - This will allow you to fully benefit from the Attack Surface Reduction and other security rules enabled by PowerWash
  - Third-party antivirus solutions tend to slow down your device substantially and are often intrusive / hard to uninstall. All editions of Defender are from Microsoft and integrate much better with Windows.
- Using a long-term support version of Windows, such as [IoT Enterprise LTSC](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-business)
  - Permanent license keys are available from reputable websites for ~$12
- Setting up [BitLocker drive encryption](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)
  - Hardware encryption will provide better performance than software encryption
- Use a browser like [Brave](https://brave.com/) for better tracking prevention (and speed!) and a VPN like [NordVPN](https://nordvpn.com/) for better anonymity.

**Device Health.** Keep up with regular hardware and software maintenance tasks, including but not limited to: running the Disk Cleanup and Defragment utilities, installing Windows/driver/firmware updates, running DISM and SFC to check for corrupted system files, removing unused programs and files, uninstalling or disabling unused devices, cleaning computer fans, and periodically stress-testing your system to ensure it remains stable under load.

**Performance.** Some user reports have indicated that disabling virtualization and/or hyperthreading can modestly improve latency. This does make sense logically, so if your latencies are too high, feel free to try this - it should be perfectly safe, and you can always go back.

## Disclaimer
See [LICENSE](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/LICENSE) for license details; [LIMITATIONS.md](https://universecraft.github.io/WindowsPowerWash/docs/limitations) for limitations and additional caveats. This software makes many changes to your system, some of which are discouraged or completely unsupported by Microsoft. This software may (depending on user configuration) modify registry settings, uninstall certain Windows applications, or otherwise perform actions commonly considered destructive. While the author's testing on virtual and physical machines has consistently shown stability and performance gains, no amount of testing is perfect, documentation is sometimes wrong, and I can't guarantee your system will be stable if you use any component of this software. You **use this at your own risk** and are strongly encouraged to make sure you understand the features you plan to use prior to using them. This software may break your system. Always make backups. In any situation where any text in this repository contradicts the LICENSE linked earlier, the LICENSE takes priority.

## Special Thank-Yous
- While many freely available sites have contributed valuable knowledge in the development of this script, I especially want to thank the maintainers of [admx.help](https://admx.help) for providing an easy-to-use and comprehensive inventory of Group Policy and associated registry settings. Also, as bad a reputation as Microsoft has for user-friendliness, their technical documentation at [learn.microsoft.com](https://learn.microsoft.com) is generally very high quality.
- All beta testers
