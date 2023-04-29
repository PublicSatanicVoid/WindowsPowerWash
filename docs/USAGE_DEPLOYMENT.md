<sup>[← Back to home](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/README.md)</sup>

## PowerWash: Deployment via Windows Installation Media

PowerWash can be easily deployed to a fresh PC as part of the Windows installation process - no user intervention necessary! This requires a USB flash drive.

**Why?** It's a one-stop shop setup script to go from a standard Windows install to a customized, configured, de-bloated, pre-loaded setup. This functionality is primarily geared toward those who frequently reinstall Windows or frequently acquire new devices as a way to get a better out-of-box experience and auto-install their desired applications. It could also conceivably be used in a small/medium IT capacity. The open-source, scripted nature means that further modifications or domain-specific changes are quite straightforward. Automated deployent can drastically reduce bringup time for new devices and also can be easily extended to run additional commands during initial Windows setup.

**How?** Windows has an "Unattended installation" feature that can be added to installation media, to automate most of the setup process. We can tack on extra commands to this, such as running PowerWash with a predefined configuration.

### Setup
- Familiarize yourself with using PowerWash in "configuration mode" [here](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/docs/USAGE_CONFIG.md).
- [Fork](https://docs.github.com/en/get-started/quickstart/fork-a-repo) this repository (`UniverseCraft/WindowsPowerWash`) into your own public GitHub repository.
- Modify your copy of `PowerWashSettings.json` with the settings you want executed when PowerWash automatically runs during setup.
- *(Optional but highly recommended)* Test this out on a local machine or VM.
- Burn a Windows ISO to a USB drive. You can use [Rufus](https://github.com/pbatard/rufus/releases/) or Microsoft's [Media Creation Tool](https://www.microsoft.com/en-us/software-download/windows10) for this.
- Download and run [`autodeploy/add_to_installer.bat`](https://github.com/UniverseCraft/WindowsPowerWash/tree/main/autodeploy/add_to_installer.bat). You will be prompted to enter the drive letter of the USB drive and also the ID of your forked repository. **This is in the format `Username/Repo`, eg `UniverseCraft/PersonalDeploymentSettings`**, where `PersonalDeploymentSettings` has been forked from `UniverseCraft/WindowsPowerWash`.
- Your USB drive for installing Windows will now download and run your configured copy of PowerWash at the end of Windows setup.

### Usage
- Plug in the USB to a device you want to (re)install Windows on, select it as the device to boot from (generally pressing F8 during boot brings you to the boot options) and follow the prompts to install Windows.
- You'll go through a streamlined version of the setup process as normal (selecting the drive partition/edition of windows, agreeing to the EULA, and choosing a network - everything else should be set automatically), and at the end you will be automatically signed in and PowerWash will run with your configured settings.
  - It's recommended to configure PowerWash to automatically restart when complete. Some registry changes won't take effect until after a restart.
  - You can optionally configure PowerWash to show a confirmation dialog before it starts. If it is not configured to automatically restart, it will show a dialog reminding the user that a restart is recommended for all changes to take effect.
- After restarting, you will be prompted to change your password. The default password is blank. The default account is named User. This can be changed if desired from the Windows settings.

### Testing
- You don't need a spare computer to try this out - you can use eg [VMware Workstation Player](https://www.vmware.com/products/workstation-player.html) with [Plop Boot Manager](https://www.plop.at/en/bootmanager/download.html) to create a Windows VM installed from your USB drive.
- When creating a new VM, you would select the ISO as `plpbt.iso` from Plop Boot Manager. Then upon starting the VM, go to `Player -> Removable Devices`, select your USB drive (e.g. `SanDisk Cruzer Glide`), and click `Connect (disconnect from host)`. You will be prompted to select the USB drive at the boot screen. From there, just follow the (greatly streamlined) standard Windows installation process, following the on-screen prompts.

### More resources
- `unattend.xml` is known as an "Answer file" - see [here](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/update-windows-settings-and-scripts-create-your-own-answer-file-sxs?view=windows-10). There is a lot more you can do with these, and you may wish to customize PowerWash's `unattend.xml` with additional setup tasks or customizations you'd like.
