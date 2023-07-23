<sup>[← Back to home](https://publicsatanicvoid.github.io/WindowsPowerWash/)</sup>

## PowerWash Limitations

There are certain things PowerWash cannot do, because Windows expressly prohibits them being done without the user *manually* changing settings, or because the edition of Windows does not have a certain feature installed.

- Disable automatic updates on Windows Home: The only way to do this is to disable *all* updates, meaning the entire Windows Update system would stop working. Registry/group policy settings to disable automatic updates are ignored in Windows Home.
- Disable Defender: We can only disable Defender from a script if Tamper Protection has been manually turned off in security settings. (However, we can still adjust certain parameters, like only performing scans when the computer is idle)
- Remove Edge: Microsoft Edge can be successfully removed from any Windows 10 SKU, but it may be reinstalled by Windows Update, particularly during 'quality updates'. Looking into mitigations for this, but for the time being this is something to watch out for. *(Update 6/5/2023: This seems to be resolved for the time being, at least until Microsoft adds more shenanigans)*
