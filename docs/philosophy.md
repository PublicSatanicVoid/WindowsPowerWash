<sup>[← Back to home](https://publicsatanicvoid.github.io/WindowsPowerWash/)</sup>

## Why you need PowerWash

Microsoft wants Windows to be a service - not something you own, but something you license the temporary right to use under Microsoft's terms. This lets them force updates, reinstall adware whenever they feel like it, and block users from making simple changes like disabling telemetry or uninstalling Microsoft's default browser.

And with the out-of-the-box user experience, your Windows computer really does feel like something you own. You're bombarded with notifications from apps you never chose, told to link everything to a Microsoft account and prompted to let Microsoft collect data from you. Before you did anything but choose a username, Microsoft already installed software you never asked for. And without checking for confirmation, it continues to install software you don't want, through automatic and sometimes disruptive updates. This is Microsoft's vision for Windows: not a clean, obedient operating system but a nosy, disobedient piece of adware that you wish you could get rid of but can't. Why is that their goal? Because advertisement and data brokerage deals are more profitable than the resulting user dissatisfaction is costly.

If you're like me, you are appalled by the gradual shift toward making Windows a service, and you feel strongly that nobody should have control over your operating system but _you_.

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

PowerWash is currently developed and tested against Windows 10. It may work at least partially against Windows 11, but until Windows 11 becomes the rational choice for the majority of users to switch to, my efforts will remain focused on Windows 10. It's hard to defend spending much time on Windows 11 when it remains buggy and less user-friendly. It's not much of an "upgrade" unless you _really_ want that tabbed Explorer layout, so until it actually is an upgrade, I won't be buying into the hype- and neither should you.

PowerWash is most effective on a new install of Windows 10 - whether it's a brand-new computer or an existing computer that you just reinstalled Windows on. PowerWash is not an antivirus and its purpose is not to remove bloatware that _you_ have downloaded- its purpose is to remove bloatware that Microsoft (and some known OEMs) have downloaded, as well as tweaking settings for performance and such. Many aspects of PowerWash are useful on existing Windows installations, but don't expect it to be quite as much of a "magic wand" for those types of use cases. And of course, using any automated tools like PowerWash should be accompanied by a manual review of software installed to see what can be removed or cleaned up. Be sure to remove unused programs, delete files you don't need, delete Windows temporary files, remove anything from startup that you don't actually need, and defrag/retrim your drive(s) regularly.


## Users are frustrated with Windows' status quo

This comment on a Microsoft blog post sums up many, many users' feelings on the matter (note, "LTSC" refers to Microsoft's non-commercially-available edition of Windows that lacks the third-party bloatware and forced "feature" updates):

> Maybe there wouldn't be so much interest in LTSC if your core offerings weren't so full of bloat. No IT professional asked for your data spigot aka telemetry. You can try and cram Edge down our throats all you want but we don't want it. We didn't ask for nor do we want all the consumer apps suggestions, chibi graphics and gamification. The problem is that you (Microsoft) have an agenda that does not align with the stated needs of IT professionals and advanced users. Rather than deliver the products that we want, you'd rather try to gaslight us into thinking that we're crazy for wanting an unbloated OS. An Xbox app in Windows 10 Enterprise? Really dude? Really?
- ThatGuyWhoWrites, 2/27/2019. [https://techcommunity.microsoft.com/t5/windows-it-pro-blog/ltsc-what-is-it-and-when-should-it-be-used/ba-p/293181](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/ltsc-what-is-it-and-when-should-it-be-used/ba-p/293181)

And this one, same blog post:

> You want consumers and IT Admins to stop resorting to an OS you say is intended for medical devices and kiosks? Then stop consistently putting out versions of Windows 10 that break NICs, lose data, reboot sans warning, and come pre-loaded with adware like candy Crush, xbox apps, start menu ads, lock screen ads, and 2 browsers. [...] Stop blaming your users for adopting something that actually works as a viable solution with STABLE updates. Stop using paying customers as beta testers.
- lord_frith, 12/27/2018
