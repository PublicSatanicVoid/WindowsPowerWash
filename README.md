# PowerWash: Reclaim Windows
Remove bloatware from Windows, take control of important settings, and optimize for low latency and high performance

**NOTE:** This script is NOT designed to repair a broken/corrupted Windows installation! It is designed to run on a fully functioning system and further optimize it for high-performance use cases. A clean install prior to using this is ideal!

## About PowerWash
The default Windows installation has to cater to a very wide variety of users, and generally makes tradeoffs that sacrifice some degree of performance and responsiveness in exchange for power management, data collection, etc. Also, many "technical" users find some of the defaults annoying. **PowerWash removes annoying, bloated, and unperformant parts of Windows** and can also install helpful utilities automatically.

I created PowerWash because I believe that underneath the cruft (ads, telemetry, Windows-as-a-service automatic updates) Windows is fundamentally a great operating system, and it shouldn't be so difficult to make it great. Many debloater tools are themselves bloatware, or don't let you configure things easily, or just don't work. PowerWash takes the good stuff from what's already been done and adds even more good stuff.

*This software may (depending on user configuration) modify registry settings, uninstall certain Windows applications, or otherwise perform actions commonly considered "dangerous" or "destructive". My testing on both physical and virtual machines as well as extensive reading of documentation has indicated these are safe operations. However, no amount of testing is perfect, documentation is sometimes wrong, and I can't guarantee your system will be stable if you use any component of this software. You **use this at your own risk** and should make sure you understand what the features you plan to use actually do!*

## Using PowerWash
There are three ways PowerWash is designed to be used:

### Interactive mode (default)
In this mode, you are prompted step-by-step to decide which PowerWash features to run.
This is helpful for first-time PowerWash users.
[Guide to interactive mode »](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/docs/USAGE_INTERACTIVE.md)

### Configuration mode
In this mode, you edit `PowerWashSettings.json` to toggle the features that you want PowerWash to run.
This is helpful for automating the process and lets you configure what programs to install/uninstall.
[Guide to configuration mode »](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/docs/USAGE_CONFIG.md)

### Deployment mode
In this mode, PowerWash automatically runs when installing Windows from a USB drive.
This is helpful for automating the process when you frequently install/reinstall Windows or want to start multiple devices from the same pre-configured point.
[Guide to deployment mode »](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/docs/USAGE_DEPLOYMENT.md)

## Special Thank-Yous
- While many freely available sites have contributed valuable knowledge in the development of this script, I especially want to thank the maintainers of [admx.help](https://admx.help) for providing an easy-to-use and comprehensive inventory of Group Policy and associated registry settings. Also, as bad a reputation as Microsoft has for user-friendliness, their technical documentation at [learn.microsoft.com](https://learn.microsoft.com) is generally very high quality.
- All beta testers
