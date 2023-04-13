There are certain things PowerWash cannot do, because Windows expressly prohibits them being done without the user *manually* changing settings, or because the edition of Windows does not have a certain feature installed.

- Disable automatic updates on Windows Home: The only way to do this is to disable *all* updates, meaning the entire Windows Update system would stop working. Registry/group policy settings to disable automatic updates are ignored in Windows Home.
- Disable Defender: We can only disable Defender from a script if Tamper Protection has been manually turned off in security settings. (However, we can still adjust certain parameters, like only performing scans when the computer is idle)
