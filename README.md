# PowerWash: Reclaim Windows
The fresh, snappy out-of-box experience you've always wanted in Windows - ready in minutes. Optimized for high-performance, low-latency applications. Removes MS/OEM bloatware, telemetry, and applies aggressive performance settings, including many that are normally hidden from the user.

### [Click here for features list](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/docs/FEATURES.md)
* Includes the ONLY known working Microsoft Edge removal process as of 5/12/23

**Quick start:** Open an admin PowerShell prompt and enter: ```curl -o bootstrap-manual.ps1 https://raw.githubusercontent.com/UniverseCraft/WindowsPowerWash/main/autodeploy/bootstrap-manual.ps1; Set-ExecutionPolicy Unrestricted -Force -Confirm:$false; .\bootstrap-manual.ps1 -Confirm:$false```

## About PowerWash

The default Windows installation has to cater to a very wide variety of users and bring in advertising revenue. This requires tradeoffs that sacrifice some degree of performance and responsiveness in exchange for power efficiency, data collection, etc. Many "technical" users find the default user experience annoying and inconvenient. **PowerWash removes annoying, bloated, and unperformant parts of Windows** and can also install helpful utilities automatically and configure settings for higher performance.

I created PowerWash because I believe that underneath the cruft (ads, bloatware, telemetry, forced automatic updates) Windows is fundamentally a great operating system, and it shouldn't be so difficult to make it great. Many debloater tools are themselves bloatware, or don't let you configure things easily, or just don't work. PowerWash takes the good stuff from what's already been done and adds even more good stuff. Also, it's actively maintained and 100% open-source. [Read more about the philosophy behind PowerWash »](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/docs/PHILOSOPHY.md)



## Using PowerWash
There are three ways PowerWash is designed to be used:

### Interactive mode (default)
In this mode, you are prompted step-by-step to decide which PowerWash features to run.
This is helpful for first-time PowerWash users.
[Guide to interactive mode »](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/docs/USAGE_INTERACTIVE.md)

### Configuration mode
In this mode, you edit `PowerWashSettings.yml` to toggle the features that you want PowerWash to run.
This is helpful for automating the process and lets you configure what programs to install/uninstall.
[Guide to configuration mode »](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/docs/USAGE_CONFIG.md)

### Deployment mode
In this mode, PowerWash automatically runs when installing Windows from a USB drive.
This is helpful for automating the process when you frequently install/reinstall Windows or want to start multiple devices from the same pre-configured point.
[Guide to deployment mode »](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/docs/USAGE_DEPLOYMENT.md)

## Some additional recommendations
PowerWash should be used as part of a comprehensive approach to optimizing and securing your system.

**Security.** To maximize security without sacrificing performance, I recommend using the enterprise version of Microsoft Defender, such as Defender for Business, along with Windows 10 Enterprise. The free version of Windows Defender does not adequately provide techniques such as Attack Surface Reduction, vulnerability tracking, etc., while third-party antivirus solutions tend to slow down your computer substantially. You can obtain permanent license keys to Enterprise from any number of reputable websites for ~$12 and easily purchase a Defender for Business subscription for ~$4/month if you have an email under a custom domain name. In my opinion, the setup is well worth it. I also recommend using BitLocker for drive encryption, using hardware rather than software encryption if possible.

**Device Health.** Keep up with regular hardware and software maintenance tasks, including but not limited to: running the Disk Cleanup and Defragment utilities, installing servicing updates, running DISM and SFC to check for corrupted system files, removing unused programs and files, uninstalling or disabling unused devices, cleaning computer fans, and periodically stress-testing your system to ensure it remains stable under load.

## Disclaimer
See [LICENSE](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/LICENSE) for license details; [LIMITATIONS.md](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/LIMITATIONS.md) for limitations and additional caveats. This software makes many changes to your system which are discouraged or completely unsupported by Microsoft. This software may (depending on user configuration) modify registry settings, uninstall certain Windows applications, or otherwise perform actions commonly considered destructive. While the author's testing on virtual and physical machines has consistently shown stability and performance gains, no amount of testing is perfect, documentation is sometimes wrong, and I can't guarantee your system will be stable if you use any component of this software. You **use this at your own risk** and are strongly encouraged to make sure you understand the features you plan to use prior to using them. This software may break your system. Always make backups. In any situation where any text in this repository contradicts the LICENSE linked earlier, the LICENSE takes priority.

## Special Thank-Yous
- While many freely available sites have contributed valuable knowledge in the development of this script, I especially want to thank the maintainers of [admx.help](https://admx.help) for providing an easy-to-use and comprehensive inventory of Group Policy and associated registry settings. Also, as bad a reputation as Microsoft has for user-friendliness, their technical documentation at [learn.microsoft.com](https://learn.microsoft.com) is generally very high quality.
- All beta testers

**NOTE:** This script is NOT designed to repair a broken/corrupted Windows installation! It is designed to run on a fully functioning system and further optimize it for high-performance use cases. A clean install prior to using this is ideal! (In fact, you can even [load PowerWash onto Windows installation media!](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/docs/USAGE_DEPLOYMENT.md))
