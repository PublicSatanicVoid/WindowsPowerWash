<sup>[← Back to home](https://universecraft.github.io/WindowsPowerWash/)</sup>

## Removing Edge (technical overview)

There are many reasons someone might want to remove Microsoft Edge. Maybe you're sick of the ads for it in Windows Search; or you want it to stop popping up when you click on a link in Settings, for example; or you are of the opinion that it is perfectly reasonable to remove software you don't use, and Edge is software you don't use; or maybe you object to it on the principle of the thing - you don't want Microsoft to be controlling what you can and can't uninstall. We won't litigate those reasons here; that's what Reddit's for. If you are reading this page, it is likely because you want to remove Edge, or because you are curious as to how it can be removed even if you yourself want to keep it.

There is a _remarkable_ amount of low-quality, blatantly incorrect advice out there about how to remove Edge - as well as plenty of sites asserting that it can't be removed at all.

Anyone who tells you to simply delete the `NoRemove` registry value from Edge's uninstall location, or to run Edge's `setup.exe` with some certain combination of flags, is wrong. Maybe this used to work, but it is still being passed around as valid advice despite Microsoft making both of those methods insufficient.

### The NoRemove issue

Normally, a program can be uninstalled from the Apps & Features settings menu by clicking on the app name, then clicking "Uninstall", and possibly being guided through an uninstall wizard. Sometimes however, that "Uninstall" button is greyed out. In those cases, the usual fix is to delete the `NoRemove` value for that app's key under one of the `\Software\(WOW6432Node)\Microsoft\Windows\CurrentVersion\Uninstall` paths.

That does not work with Microsoft Edge. Why? Because the command that is registered to uninstall Edge _doesn't actually do it._

### The setup.exe issue

If you deleted the `NoRemove` value and tried to uninstall Edge, Windows (under the hood) called `setup.exe --uninstall --verbose-logging --system-level` on the Edge setup tool. This command has also been suggested in many online forums as a way to "manually" remove Edge.

But without further modifications, this command will do **nothing**. There are additional registry keys that must be set in order to make this method (sort of) work.

Mainly, you have to set `[HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev] AllowUninstall = (DWORD) 0x1`, and also remove any `experiment_control_labels` values from subkeys of `HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState`. Once you've done this, you can run that command above and it will allow you to uninstall Edge - or rather, the Chromium-based version of Edge.

### Wait, Edge still opens! And it still shows up in my programs list!

This is the old (UWP) version of Edge, which exists side-by-side with the new (Chromium) version, ready to take over if the Chromium version is uninstalled. Removing this version is a lot trickier.

You can get close by just deleting all the registry entries for it and removing it from the program files and program data system folders (after an appropriate amount of permissions-wrangling, of course). This will render Edge non-functional, but Edge will still show up in your programs list and in the start menu.

To remove Edge fully, you have to uninstall its application package. But Microsoft has made this, too, stupidly inconvenient.

### The Appx issue

Edge (and the Edge DevTools client) is installed as an "Appx" package, which just means that it is packaged in a certain format and is registered in a certain database, separately from non-Appx programs like most that you would install.

There is a handy set of PowerShell cmdlets: `Get-AppxPackage -Name "*Microsoft*Edge*"` will select all the Appx packages for Microsoft Edge, and piping this to `Remove-AppxPackage` _should_ then remove those packages.

But if you try to do that, you get a rather nasty error message saying that the application is "part of Windows" and "can't be removed". They don't use this term in the error message, because that would be useful information and Microsoft as a matter of policy does not provide useful information, but the reason those packages can't be removed is because they are "Inbox" applications (meaning they are "part of the box" and are -- **artificially** -- "built in" to Windows and can't be removed).

Thankfully, there's nothing fundamentally different about an inbox application - there's just a boolean field in a database somewhere specifying whether a given package is inbox or not. Clear that boolean, and the package can be removed.

The details of editing that field are a bit hairy, because it resides in an actively open database with specialized logic that normally prevents external modifications, but by killing the services that have the database open and temporarily removing that specialized logic, we can edit the "Is Inbox?" field, package things back up (this is also hairy; if you do something in the wrong order it bricks your whole Appx repository), and now the `Remove-AppxPackage` cmdlet completes successfully, after showing an *extremely satisfying* "Deployment operation" progress bar for removing Edge.

There are some other relatively unimportant steps to delete some lingering traces of Edge, but these are the major hurdles to overcome.

### Windows Update

Windows Update may attempt to reinstall Edge, but at the time of writing this system is totally broken and the version it installs will be completely non-functional. You will see Edge in the start menu / programs list (with no icon and a listed size of like 8KB) but the application won't start and it won't show up in the Control Panel app wizard. Basically, the updater has just re-added the entries for Edge to the package database but not re-installed the application itself, so while it *looks* like Edge is back, it's really not.

Most updates will not attempt to bring Edge back at all. Its phantom will reappear every so often though - and if you want those annoying traces removed again, you can just run this script again. I'm actively working on ways to prevent updates from putting those weird traces back in.

### Wrap up

Now that we know definitively that Edge can be completely removed from any computer, can we all take a moment to appreciate the profound stupidity of this official statement from Microsoft?

> Because Windows supports applications that rely on the web platform, our default web browser is an essential component of our operating system and can’t be uninstalled.
-[Microsoft Support -- accessed 5/18/2023](https://support.microsoft.com/en-us/microsoft-edge/why-can-t-i-uninstall-microsoft-edge-ee150b3b-7d7a-9984-6d83-eb36683d526d)

You will notice that your system still runs totally fine - literally nothing should break as a result of removing Edge - and so it clearly is *not* an essential component of Windows. But even if it *were* an essential component of Windows, that still wouldn't explain why it *couldn't* be uninstalled - just why it *shouldn't*. Microsoft's never exactly been strong on transparency, but this is just hilariously sloppy bullshit.

Hopefully you've found this explanation of the Edge removal process enlightening! The full process took me weeks to come up with and weeks more to stabilize against edge cases and glitches. The Windows user community always needs more reverse engineers to unravel Microsoft's advertisement-driven antics, so if you feel drawn to this kind of experimentation and (quite honestly) fun, feel free to submit your findings via a pull request or GitHub issue! Even if it doesn't get incorporated into PowerWash (and it very well could!) it's always nice to discuss the ugly innards of Microsoft Windows over a steaming-hot bowl of spaghetti.
