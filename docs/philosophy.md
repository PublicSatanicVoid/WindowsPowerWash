<sup>[← Back to home](https://universecraft.github.io/WindowsPowerWash/)</sup>

## Why you need PowerWash

Microsoft wants Windows to be a service - not something you own, but something you own the temporary right to use under Microsoft's terms. This lets them force updates, reinstall adware whenever they feel like it, and block users from making simple changes like disabling telemetry or uninstalling Microsoft's default browser. 

And with the out-of-the-box user experience, Windows really does feel like a service. You're bombarded with notifications from apps you never asked for, told to link everything to a Microsoft account and prompted to let Microsoft collect data from you. Before you did anything but choose a username, Microsoft already installed software you never asked for. And without checking for confirmation, it continues to install software you never asked for, through automatic and sometimes disruptive updates. This is Microsoft's dream for Windows: not a clean, efficient, and obedient operating system but a nosy, disruptive, and disobedient piece of borderline malware that you wish you could get rid of but can't. Why is that their dream? Because advertisement deals are more profitable than the resulting user dissatisfaction is costly.

If you're like me, you are absolutely disgusted by the gradual shift toward making Windows a service, and you feel strongly that nobody but you should have control over your operating system. 

The great news is that you can completely nuke all the "service"-like aspects of Windows without making your system unstable or compromising security. With a few minutes of work on a new installation, PowerWash can purge the crapware from your machine and streamline your experience by tuning performance settings, checking for common software and hardware issues, and installing software that _you_ want. (And yes, all of this is configurable.)

And because it's open-source, you don't have to take my word for any of it. You can verify anything you're curious about and disable or remove it if you don't like it or aren't comfortable. You are also encouraged to contribute to this project with any modifications you think would be useful to the broader community.


## The philosophy of PowerWash

PowerWash is the result of several key observations:

* Many users (technical and non-technical) want to modify core aspects of their Windows installation.
* These modifications are difficult or time-consuming to perform manually.
* Microsoft is hostile toward users making these modifications and most users aren't interested in continually reverse-engineering Microsoft's mess.
* Third-party executables and modded ISOs should be avoided unless absolutely necessary, because they are difficult to distinguish from malware and hard for even many technical users to validate.
* Thus, an open-source solution for configuring these modifications is highly preferable.
* Existing open-source tools for this are fragmented, low-quality, and not up-to-date.
* Ideally, an open-source solution would not require compilation and could run in its source code form without the user needing to install additional software.

To meet all these needs and more, PowerWash is an easy-to-use, fully automatable, open-source and actively maintained PowerShell tool that cleans up the mess left behind by Microsoft and OEM bloatware and unwanted products.

PowerWash consolidates decades of existing research and experimentation along with ongoing streamlining and remediation of Microsoft's antics.


## Scope and limitations of PowerWash

PowerWash is currently developed and tested against Windows 10. It may work at least partially against Windows 11, but until Windows 11 becomes the rational choice for the majority of users to switch to, my efforts will remain focused on Windows 10. It's hard to defend spending much time on Windows 11 when it remains buggy and less user-friendly. It's not much of an "upgrade" unless you _really_ want that tabbed Explorer layout, so until it actually is an upgrade, we won't be buying into the hype- and neither should you.

PowerWash is most effective on a new install of Windows 10 - whether it's a brand-new computer or an existing computer that you just reinstalled Windows on. PowerWash is not an antivirus and its purpose is not to remove bloatware that _you_ have downloaded- its purpose is to remove bloatware that Microsoft and OEMs have downloaded, as well as tweaking settings for performance and such. Many aspects of PowerWash are useful on existing Windows installations, but don't expect it to be quite as much of a "magic wand" for those types of use cases. And of course, using any automated tools like PowerWash should be accompanied by a manual review of software installed to see what can be removed or cleaned up. Be sure to remove unused programs, delete files you don't need, delete Windows temporary files, remove anything from startup that you don't actually need, and defrag/retrim your drive(s) regularly.
