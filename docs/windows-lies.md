<sup>[← Back to home](https://publicsatanicvoid.github.io/WindowsPowerWash/)</sup>

## Windows Lies

It is pretty much an open secret at this point that Microsoft blatantly lies about their products in an attempt to get users to purchase software they don't really need or to dissuade users from trying too hard to get rid of software they don't really want.

Still, it bears cataloguing just how brazen they've become. Here is a list of lies that *you can disprove by yourself with PowerWash*.


### "You can't stop updates entirely"

> You can’t stop updates entirely—because they help keep your device safe and secure, updates will eventually need to be installed and downloaded, regardless of your update settings.
-[Windows Update FAQ -- accessed 5/18/2023](https://support.microsoft.com/en-us/windows/windows-update-faq-8a903416-6f45-0718-f5c7-375e92dddeb2#WindowsVersion=Windows_10:~:text=You%20can%E2%80%99t%20stop%20updates%20entirely%E2%80%94because%20they%20help%20keep%20your%20device%20safe%20and%20secure%2C%20updates%20will%20eventually%20need%20to%20be%20installed%20and%20downloaded%2C%20regardless%20of%20your%20update%20settings.)

This is one of the easier lies to disprove, as any user with Pro, Education, or Enterprise editions of Windows can use the Group Policy editor to disable automatic updates *through Microsoft-approved means.* Still, they sure do want you to think you're at their mercy.

On Home editions of Windows, you can disable all updates for as long as you like with PowerWash:
- Enter `Y` to `Do you want to disable all Windows updates?` (or with `/config`, set `WindowsUpdate.DisableAllUpdate` to `true`)
or
- Enter `Y` to `Do you want to add a script to your desktop that lets you toggle Windows updates on or off?` (or with `/config`, set `WindowsUpdate.AddUpdateToggleScriptToDesktop` to `true`)

And on other editions of Windows, you have the (easier) option to disable automatic updates with PowerWash:
- Enter `Y` to `Do you want to disable automatic Windows updates?` (or with `/config`, set `WindowsUpdate.DisableAutoUpdate` to `true`)


### "You can't use Group Policy  /  Hyper-V on Home editions"

> The Hyper-V role **cannot** be installed on Windows 10 Home.
-[Microsoft Learn -- accessed 5/18/2023](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v#:~:text=The%20Hyper%2DV%20role%20cannot%20be%20installed%20on%20Windows%2010%20Home)

While they take a bit of DISM-fu to install, both Group Policy Editor and Hyper-V, which are advertised as exclusive to professional Windows editions, can easily be installed on Windows Home through their corresponding PowerWash features. Their installation files are even included in the folder of servicing packages, just waiting to be installed! How ridiculous is it that they tell you the feature can't be installed, when they put the installation files _on your computer?_

(Yes, certain group policies don't work on Windows Home, but many of them do and most of the others have workarounds)


### "Edge is an essential component of Windows and can't be uninstalled"

> Because Windows supports applications that rely on the web platform, our default web browser is an essential component of our operating system and can’t be uninstalled.
-[Microsoft Support -- accessed 5/18/2023](https://support.microsoft.com/en-us/microsoft-edge/why-can-t-i-uninstall-microsoft-edge-ee150b3b-7d7a-9984-6d83-eb36683d526d)

I really hate this one. Edge is **NOT** an essential component of Windows. Microsoft has, however, tried incredibly hard to artificially make this the case by marking it as non-removable, non-repairable, and as an "in-box" application which means that ordinary administrative methods will fail to remove it. However, as you can see if you use PowerWash to remove Edge, literally nothing breaks with this supposedly "essential" program gone.

Removing Edge from Windows and preventing it from coming back require a number of carefully orchestrated steps - not because (as Microsoft would probably have you believe) it needs to be carefully disentangled from all the other "essential" components that depend on it, but *only because Microsoft makes it incredibly hard to remove* ... probably because of all the advertising revenue and behavioral data collection they get from people using Edge.


### "'Required' telemetry is required"

> Required (Basic): Minimum data required to keep the device secure, up to date, and performing as expected.
-[Microsoft Learn -- accessed 6/5/2023](https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization)

This is a *really* braindead one, because just a little farther down on the same page they say:

> If you choose [Diagnostic Data Off], devices in your organization will still be secure.

It would seem that Microsoft's "party line" changes so often that they can't even keep track of their own lies *on the same page*.


### "LTSC editions shouldn't be used by consumers"

The overwhelming messaging from Microsoft is that LTSC should be used only for "business-critical" systems, not consumer devices. They haven't explicitly said not to use it on consumer devices, but they've heavily implied as much [here](https://learn.microsoft.com/en-us/windows/whats-new/ltsc/overview) and [here](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/ltsc-what-is-it-and-when-should-it-be-used/ba-p/293181), for example.

A particularly humorous "oopsies" on Microsoft's part is the repeated claim that 

> Windows 10 LTSC [...] does not contain any of the components of Windows 10 that may change over the life of the release. These components include Microsoft Edge
-[Microsoft Tech Community -- accessed 6/5/2023](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/ltsc-what-is-it-and-when-should-it-be-used/ba-p/293181)

Just install a current LTSC edition and find out for yourself how this statement is completely false. Ironically, this lie (or significant oversight, at least) is likely trying to dissuade users from using LTSC (oh no, it won't have Edge, my favorite browser!!!!) when in reality it probably has done exactly the opposite.

(And by the way, if you are fine with a slower release cycle for feature updates, and aren't particularly fond of the default mail/store/etc apps, LTSC really is the no-brainer choice of Windows edition.)

Oh, Microsoft.
