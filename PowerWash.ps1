#
# PowerWash (Beta)
#
# Aims to improve system responsiveness, performance, and latency
# by tuning settings to uncompromisingly favor performance and
# low latencies. Also removes some usually unwanted default Windows
# behaviors.
#
# USE AT YOUR OWN RISK. BACKUP SYSTEM BEFORE USING.
#

### USAGE INFORMATION ###
if ("/?" -in $args) {
    ".\PowerWash.ps1 [/all | /auto | /config | /stats | /warnconfig] [/noinstalls] [/noscans] [/autorestart]"
    "	/all			Runs all PowerWash features without prompting"
    "	/auto			Runs a default subset of PowerWash features, without prompting"
    "	/config			Runs actions enabled in PowerWashSettings.json, without prompting"
    "	/stats			Shows current performance stats and exits"
    "	/warnconfig		Shows potentially destructive configured operations"
    "	/noinstalls		Skips PowerWash actions that would install software (overrides other flags)"
    "	/noscans		Skips PowerWash actions that perform lengthy scans (overrides other flags)"
    "	/autorestart		Restarts computer when done"
    exit
}


"Loading dependencies..."

"- NuGet package manager"
if ("NuGet" -notin (Get-PackageProvider | Select-Object Name).Name) {
    Install-PackageProvider -Name NuGet -Force | Out-Null
    "  - Installed NuGet package manager"
}

"- powershell-yaml module"
if ("powershell-yaml" -notin (Get-Module | Select-Object Name).Name) {
    Install-Module -Name powershell-yaml -Force
    " - Installed powershell-yaml module"
}
""


### COMMAND LINE PARAMETERS ###
$global:do_all = "/all" -in $args
$global:do_all_auto = "/auto" -in $args
$global:do_config = "/config" -in $args
if ($global:do_all -and $global:do_all_auto) {
    "Error: Can only specify one of /all or /auto"
    "Do '.\PowerWash.ps1 /?' for help"
    exit
}
$global:config_map = If (Test-Path ".\PowerWashSettings.yml") {
	(Get-Content -Raw ".\PowerWashSettings.yml" | ConvertFrom-Yaml)
}
Else {
    @{}
}
$will_restart = $autorestart -or ($global:do_config -and $global:config_map.AutoRestart)
$noinstall = "/noinstalls" -in $args
$noscan = "/noscans" -in $args
$autorestart = "/autorestart" -in $args
$is_unattend = "/is-unattend" -in $args

if ($is_unattend) {
    "Unattended setup detected"
    if ($global:config_map.Unattend.NotifyBeforePowerWash) {
        $restart_info = If ($will_restart) { "`nThe computer will automatically restart when finished." } Else { "" }
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("Applying custom Windows configuration.`nDo not restart until notified that this has completed.$restart_info`nPress OK to continue.", 'PowerWash Setup', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information)
    }
}


### WARN ON DESTRUCTIVE OPERATIONS ###
if ("/warnconfig" -in $args) {
    "Showing potentially destructive configured operations:"
    "==Removals=="
    if ($global:config_map.Defender.DisableRealtimeMonitoringCAUTION) {
        if ($global:config_map.Defender.DisableAllDefenderCAUTIONCAUTION) {
            "* WARNING: Configured settings will disable Windows Defender entirely."
        }
        else {
            "* WARNING: Configured settings will disable Windows Defender realtime monitoring."
        }
    }
    if ($global:config_map.Debloat.RemoveEdge) {
        "* Will remove Microsoft Edge"
    }
    if ($global:config_map.Debloat.RemovePreinstalled) {
        "* Will remove the following preinstalled apps:"
        foreach ($app in $global:config_map.Debloat.RemovePreinstalledList) {
            "  - $app"
        }
    }
    if ($global:config_map.Debloat.RemoveWindowsCapabilities) {
        "* Will remove the following capabilities:"
        foreach ($cap in $global:config_map.Debloat.RemoveWindowsCapabilitiesList) {
            " - $app"
        }
    }
    "==Installs=="
    if ($global:config_map.Install.InstallGpEdit) {
        "* Will install Group Policy Editor if Windows edition is Home"
    }
    if ($global:config_map.Install.InstallWinget) {
        "* Will install Winget if needed"
    }
    try {
        Get-Command winget | Out-Null
        if ($global:config_map.Install.InstallConfigured) {
            "* Will install the following via Winget:"
            foreach ($app in $global:config_map.Install.InstallConfiguredList) {
                "  - $app"
            }
        }
    }
    catch {
        "* Will skip configured Winget installs as Winget is not present"
    }
	
    exit
}


### FEATURE VERB MAP ###
$global:feature_verbs = @{
    "Performance.DisableHpet"                      = "Disabling High-precision event timer";
    "Performance.HwGpuScheduling"                  = "Enabling hardware-accelerated GPU scheduling";
    "Performance.MultimediaResponsiveness"         = "Applying high-performance multimedia settings";
    "Performance.NetworkResponsiveness"            = "Applying high-performance network adapter settings";
    "Performance.PowerSettingsMaxPerformance"      = "Applying high-performance power settings";
    "Performance.DisableFastStartup"               = "Disabling fast startup";
    "Performance.EnableDriverMsi"                  = "Enabling message-signaled interrupts on supported devices";
    "Performance.EnableDriverPrio"                 = "Prioritizing GPU and PCIe controller interrupts";
    "DisableTelemetry"                             = "Disabling Microsoft telemetry";
    "Debloat.DisableCortana"                       = "Disabling Cortana";
    "Debloat.DisableConsumerFeatures"              = "Disabling Microsoft consumer features";
    "Debloat.DisablePreinstalled"                  = "Disabling preinstalled apps from Microsoft and OEMs";
    "Debloat.RemovePreinstalled"                   = "Removing configured list of preinstalled apps";
    "Debloat.RemoveWindowsCapabilities"            = "Removing configured list of Windows capabilities";
    "Debloat.RemoveEdge"                           = "Removing Microsoft Edge";
    "WindowsUpdate.DisableAutoUpdate"              = "Disabling automatic Windows updates";
    "WindowsUpdate.DisableAllUpdate"               = "Disabling Windows Update completely";
    "WindowsUpdate.AddUpdateToggleScriptToDesktop" = "Adding script to desktop to toggle Windows Update on/off";
    "Install.InstallGpEdit"                        = "Installing Group Policy Editor (gpedit.msc)";
    "Install.InstallWinget"                        = "Installing Winget package manager";
    "Install.InstallConfigured"                    = "Installing configured list of Winget packages";
    "Defender.DefenderScanOnlyWhenIdle"            = "Configuring Defender to scan only when idle";
    "Defender.DefenderScanLowPriority"             = "Configuring Defender to run at low priority";
    "Defender.DisableRealtimeMonitoringCAUTION"    = "Disabling Defender realtime monitoring (requires Tamper Protection disabled)";
    "Defender.DisableAllDefenderCAUTIONCAUTION"    = "Disabling Defender entirely (requires Tamper protection disabled)";
    "Convenience.DisableStartupDelay"              = "Disabling application startup delay";
    "Convenience.ShowSecondsInTaskbar"             = "Showing seconds in taskbar";
    "Convenience.ShowRunAsDifferentUser"           = "Showing 'Run as different user' option in start menu";
    "Convenience.ShowHiddenExplorer"               = "Showing hidden files in Explorer";
    "Convenience.CleanupTaskbar"                   = "Cleaning up taskbar";
    "Scans.CheckIntegrity"                         = "Running system file integrity checks";
    "Scans.CheckIRQ"                               = "Checking for IRQ conflicts"
}


### REGISTRY KEY DEFINITIONS ###
$RK_PolicyRoot = "HKLM:\SOFTWARE\Policies\Microsoft"
$RK_Policy_AppCompat = "$RK_PolicyRoot\Windows\AppCompat"
$RK_Policy_CloudContent = "$RK_PolicyRoot\Windows\CloudContent"
$RK_Policy_DataCollection = "$RK_PolicyRoot\Windows\DataCollection"
$RK_Policy_Defender = "$RK_PolicyRoot\Windows Defender"
$RK_Policy_Defender_RealtimeProtection = "$RK_Policy_Defender\Real-Time Protection"
$RK_Policy_Explorer = "$RK_PolicyRoot\Windows\Explorer"
$RK_Policy_Feeds = "$RK_PolicyRoot\Windows\Windows Feeds"
$RK_Policy_Search = "$RK_PolicyRoot\Windows\Windows Search"
$RK_Policy_Store = "$RK_PolicyRoot\WindowsStore"
$RK_Policy_Update = "$RK_PolicyRoot\Windows\WindowsUpdate"
$RK_Policy_Update_AU = "$RK_Policy_Update\AU"

$RK_Defender = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
$RK_Defender_Features = "$RK_Defender\Features"

$RK_Explorer = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
$RK_Explorer_Advanced = "$RK_Explorer\Advanced"
$RK_Explorer_Serialize = "$RK_Explorer\Serialize"
#$RK_Startup = "$RK_Explorer\StartupApproved\Run"

$RK_MMCSS = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
$RK_MMCSS_ProAudio = "$RK_MMCSS\Tasks\Pro Audio"

$RK_Uninst = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
$RK_Uninst_Edge = "$RK_Uninst\Microsoft Edge"






# Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\Microsoft.MicrosoftEdge_44.19041.1266.0_neutral__8wekyb3d8bbwe
# Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\Microsoft.MicrosoftEdgeDevToolsClient_1000.19041.1023.0_neutral_neutral_8wekyb3d8bbwe
# Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe
# Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Config\Microsoft.MicrosoftEdge_8wekyb3d8bbwe
# Computer\HKEY_LOCAL_MACHINE\SYSTEM\Setup\Upgrade\Appx\DownlevelGather\AppxAllUserStore\Config\Microsoft.MicrosoftEdge_8wekyb3d8bbwe
# Computer\HKEY_LOCAL_MACHINE\SYSTEM\Setup\Upgrade\Appx\DownlevelGather\AppxAllUserStore\InboxApplications\Microsoft.MicrosoftEdge_44.18362.1533.0_neutral__8wekyb3d8bbwe
# Computer\HKEY_LOCAL_MACHINE\SYSTEM\Setup\Upgrade\Appx\DownlevelGather\AppxAllUserStore\S-1-5-21-3648988713-1279931744-352962703-1001\Microsoft.MicrosoftEdge_44.18362.1533.0_neutral__8wekyb3d8bbwe
# Computer\HKEY_LOCAL_MACHINE\SYSTEM\Setup\Upgrade\Appx\DownlevelGather\PackageInstallState\Microsoft.MicrosoftEdge_44.18362.1533.0_neutral__8wekyb3d8bbwe









# OSIntegrationLevel: default 5
# Protected by SYSTEM
#$RK_Edge = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MicrosoftEdge"

$RK_Privacy = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"
$RK_Store_Update = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate"
$RK_ContentDelivery = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
$RK_Search = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"

$RK_DevEnum = "HKLM:\SYSTEM\CurrentControlSet\Enum"
$RK_FastStartup = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
$RK_GPUSched = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
$RK_Net_Ndu = "HKLM:\SYSTEM\ControlSet001\Services\Ndu"
$RK_PowerThrottling = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"
$RK_Services = "HKLM:\SYSTEM\CurrentControlSet\Services"

$RK_TIPC = "HKLM:\SOFTWARE\Microsoft\Input\TIPC"


### PERFORMANCE STATISTICS ###
if ("/stats" -in $args) {
    "Collecting current performance stats, please be patient..."
    "It's recommended to run this before and after applying PowerWash (remember to restart)"
    $NumSamples = 5
    $SampleInterval = 1
    $HistoryFile = "PowerWash_LastStats.csv"
    $HasPrev = Test-Path -Path $HistoryFile
    if ($HasPrev) {
        $PrevStats = Import-Csv $HistoryFile
    }
    $CounterSets = @("Processor", "Thermal Zone Information", "Memory")
    foreach ($CounterSet in $CounterSets) {
        "- Collecting performance stats from $CounterSet set..."
        $Paths = (Get-Counter -ListSet $CounterSet).Paths
        $Samples += (Get-Counter -Counter $Paths -SampleInterval $SampleInterval -MaxSamples $NumSamples -ErrorAction SilentlyContinue) `
        | Select-Object -ExpandProperty CounterSamples `
        | Group-Object -Property Path `
        | ForEach-Object {
            $_ | Select-Object -Property Name, @{n = 'Average'; e = { ($_.Group.CookedValue | Measure-Object -Average).Average } };
        }
    }
    "# PowerWash performance stats: $(Get-Date)" | Out-File -FilePath $HistoryFile
    "label,average" | Out-File -Append -FilePath $HistoryFile
    $Results = @()
    foreach ($Entry in $Samples) {
        if ((-not ($Entry.Name -match "Processor")) -or ($Entry.Name -match "Processor" -and $Entry.Name -match "_total")) {
            $Label = $Entry.Name.Split("\")[-1]
			
            if ($Label -in @("high precision temperature")) {
                $Entry.Average = $Entry.Average / 10 - 273.15  # 10*Kelvin to Celsius
            }
            if ($Label -in @("throttle reasons", "% passive limit", "temperature")) {
                continue
            }
            if (($Entry.Name -match "memory") -and $Label -NotIn @("page faults/sec", "cache faults/sec", "% committed bytes in use")) {
                continue
            }
			
            "$Label,$($Entry.Average)" | Out-File -Append -FilePath $HistoryFile
            if ($HasPrev) {
                $Prev = ($PrevStats | Where-Object { $_.label -eq $Label }).average
                $Row = "" | Select-Object Label, Prev, Curr, Delta, PercentDelta
                $Row.Label = $Label
                $Row.Prev = $Prev
                $Row.Curr = $Entry.Average
                $Row.Delta = $Entry.Average - $Prev
                $Row.PercentDelta = 100 * ($Entry.Average - $Prev) / $Prev
                if ($Entry.Average -eq $Prev) {
                    $Row.PercentDelta = 0
                }
                $Results += $Row
            }
            else {
                $Results += @{ Label = $Label; Average = $Entry.Average }
            }
        }
    }
    $Results | Format-Table -AutoSize
    if (-not $HasPrev) {
        "NOTE: Run this script with '/stats' again to display a comparison table!"
        "Typically this would be to see how the stats changed from before to after you made a change."
    }
    exit
}


### COMPATIBILITY CHECKS ###
# Check Windows edition; some editions don't support certain features
$edition = (Get-WindowsEdition -online).Edition
$has_win_pro = ($edition -Like "*Pro*") -or ($edition -Like "*Edu*") -or ($edition -Like "*Enterprise*")
$has_win_enterprise = ($edition -Like "*Enterprise*") -or ($edition -Like "*Edu*")

"Windows Edition: $edition (pro=$has_win_pro) (enterprise=$has_win_enterprise)"
""

# Check if we have Winget already
Get-Command winget 2>$null | Out-Null
$has_winget = $?


### UTILITY FUNCTIONS ###

function RegistryPut ($Path, $Key, $Value, $VType) {
    if ($null -eq $Path) {
        "ERROR: Null registry key passed"
        return
    }
    if (-NOT (Test-Path "$Path")) {
        New-Item -Path "$Path" -Force | Out-Null
    }
    New-ItemProperty -Path "$Path" -Name "$Key" -Value "$Value" -PropertyType "$VType" -Force | Out-Null
}

function RunScriptAsSystem ($Path, $ArgString) {
    "  [Invoking script as SYSTEM]"
    "$home" | Out-File -FilePath "C:\.PowerWashHome.tmp" -Force -NoNewline
    # Adapted from https://github.com/mkellerman/Invoke-CommandAs/blob/master/Invoke-CommandAs/Private/Invoke-ScheduledTask.ps1
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "$Path $ArgString"
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Task = Register-ScheduledTask PowerWashSystemTask -Action $Action -Principal $Principal
    $Job = $Task | Start-ScheduledTask -AsJob -ErrorAction Stop
    $Job | Wait-Job | Remove-Job -Force -Confirm:$False
    While (($Task | Get-ScheduledtaskInfo).LastTaskResult -eq 267009) { Start-Sleep -Milliseconds 200 }
    $Task | Unregister-ScheduledTask -Confirm:$false
    "System level script completed successfully"
}

function TryDisableTask ($TaskName) {
    try {
        $task = Get-ScheduledTask $TaskName -EA SilentlyContinue
        Disable-ScheduledTask $task -EA SilentlyContinue | Out-Null
    }
    catch {}
}

function GetNested($Object, $Path) {
    $obj = $Object
    $keys = $Path.Split(".")
    $keys | ForEach-Object {
        $obj = $obj.$_
    }
    return $obj
}

function Confirm ($Prompt, $Auto = $false, $ConfigKey = $null) {
    if ($global:do_all) {
        return $true
    }
    if ($global:do_all_auto) {
        return $Auto
    }
    if ($global:do_config) {
        $enable = GetNested -Object $global:config_map -Path $ConfigKey
        if ($enable) {
            Write-Host $global:feature_verbs.$ConfigKey
        }
        else {
            Write-Host "Skipped: $($global:feature_verbs.$ConfigKey)"
        }
        return $enable
    }
    return (Read-Host "$Prompt y/n") -eq "y"
}

function UnpinApp($appname) {
    # https://learn.microsoft.com/en-us/answers/questions/214599/unpin-icons-from-taskbar-in-windows-10-20h2
	((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() `
    | Where-Object { $_.Name -eq $appname }).Verbs() `
    | Where-Object { $_.Name.replace('&', '') -match 'Unpin from taskbar' } `
    | ForEach-Object { $_.DoIt() }
}

function CreateShortcut($Dest, $Source, $Admin = $false) {
    # https://stackoverflow.com/questions/28997799/how-to-create-a-run-as-administrator-shortcut-using-powershell
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($Dest)
    $Shortcut.TargetPath = $Source
    $Shortcut.Save()

    if ($Admin) {
        $bytes = [System.IO.File]::ReadAllBytes("$home\Desktop\Toggle Updates.lnk")
        $bytes[0x15] = $bytes[0x15] -bor 0x20 #set byte 21 (0x15) bit 6 (0x20) ON
        [System.IO.File]::WriteAllBytes("$home\Desktop\Toggle Updates.lnk", $bytes)
    }
}

$global:verbose_log = "C:\PowerWashVerbose.log"
function SyslevelDebugLog($Msg) {
    #$Msg | Out-File -FilePath $global:verbose_log -Append -Force
}

# Must be running as SYSTEM to modify certain Defender settings (even then, will need Tamper Protection off manually for some of them to take effect)
# We have to bootstrap to this by scheduling a task to call this script with this flag

if ("/ElevatedAction" -in $args) {
    $UserHome = Get-Content "C:\.PowerWashHome.tmp"
    Set-Location $UserHome
    SyslevelDebugLog "ElevatedAction entering (user home = $UserHome)"

    if ("/DisableRealtimeMonitoring" -in $args) {
        Set-MpPreference -DisableRealtimeMonitoring $true
        RegistryPut $RK_Policy_Defender_RealtimeProtection -Key "DisableBehaviorMonitoring" -Value 1 -VType "DWORD"
        RegistryPut $RK_Policy_Defender_RealtimeProtection -Key "DisableRealtimeMonitoring" -Value 1 -VType "DWORD"
        RegistryPut $RK_Policy_Defender_RealtimeProtection -Key "DisableOnAccessProtection" -Value 1 -VType "DWORD"
        RegistryPut $RK_Policy_Defender_RealtimeProtection -Key "DisableScanOnRealtimeEnable" -Value 1 -VType "DWORD"
        "Defender real-time monitoring disabled."
        if ("/DisableAllDefender" -in $args) {
            RegistryPut $RK_Policy_Defender_RealtimeProtection -Key "SpyNetReporting" -Value 0 -VType "DWORD"
            RegistryPut $RK_Policy_Defender_RealtimeProtection -Key "SubmitSamplesConsent" -Value 0 -VType "DWORD"
            RegistryPut $RK_Defender -Key "DisableAntiSpyware" -Value 1 -VType "DWORD"
            RegistryPut $RK_Defender_Features -Key "TamperProtection" -Value 4 -VType "DWORD"
            RegistryPut $RK_Policy_Defender -Key "DisableAntiSpyware" -Value 1 -VType "DWORD"
            "Defender disabled."
        }
    }
    elseif ("/RemoveEdge" -in $args) {
        if ("/RegistryStage" -in $args) {
            $keys_to_remove = @(
                "HKLM:\SOFTWARE\WOW6432Node\Clients\StartMenuInternet\Microsoft Edge",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate",
                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineCore",
                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineUA"
            )
            $keys_to_remove_by_child = @(
                "HKLM:\SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx",
                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Update\TargetingInfo\Installed",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )
            $entries_to_remove_by_key = @(
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"
            )
            $entries_to_remove_by_val = @(
                "HKLM:\SOFTWARE\RegisteredApplications",
                "HKCU:\SOFTWARE\RegisteredApplications"
            )
            SyslevelDebugLog "keys_to_remove"
            $keys_to_remove | ForEach-Object {
                SyslevelDebugLog "Reg remove: $_"
                Remove-Item -Recurse -Force -Path "$_" | Tee-Object -FilePath $global:verbose_log
            }
            SyslevelDebugLog "keys_to_remove_by_child"
            $keys_to_remove_by_child | ForEach-Object {
                if (-not (Test-Path -Path $_)) {
                    SyslevelDebugLog "Skipping nonexistent path $_"
                }
                else {
                    Get-ChildItem -Path $_ | Where-Object { $_ -Like "*Microsoft*Edge*" } | ForEach-Object {
                        SyslevelDebugLog "Reg remove: $_"
                        Remove-Item -Recurse -Force -Path $_ | Tee-Object -FilePath $global:verbose_log
                    }
                }
            }
            SyslevelDebugLog "entries_to_remove_by_key"
            $entries_to_remove_by_key | ForEach-Object {
                $path = $_
                if (-not (Test-Path -Path $path)) {
                    SyslevelDebugLog "Skipping nonexistent path $path"
                }
                else {
                    (Get-ItemProperty -Path $path).PSObject.Properties | Where-Object { $_.Name -Like "* Microsoft*Edge*" } | ForEach-Object {
                        SyslevelDebugLog "Reg remove: $path -> $($_.Name)"
                        Remove-ItemProperty -Force -Path $path -Name $_.Name | Tee-Object -FilePath $global:verbose_log
                    }
                }
            }
            SyslevelDebugLog "entries_to_remove_by_val"
            $entries_to_remove_by_val | ForEach-Object {
                $path = $_
                if (-not (Test-Path -Path $path)) {
                    SyslevelDebugLog "Skipping nonexistent path $path"
                }
                else {
                    (Get-ItemProperty -Path $path).PSObject.Properties | Where-Object { $_.Value -Like "*Microsoft*Edge*" } | ForEach-Object {
                        SyslevelDebugLog "Reg remove: $path -> $($_.Name)"
                        Remove-ItemProperty -Force -Path $path -Name $_.Name | Tee-Object -FilePath $global:verbose_log
                    }
                }
            }
        }
        elseif ("/FilesystemStage" -in $args) {
            $folders_to_remove = @(
                "$UserHome\AppData\Local\Microsoft\Edge",
                "$UserHome\AppData\Local\Microsoft\EdgeBho",
                "$UserHome\AppData\Local\MicrosoftEdge",
                "$UserHome\MicrosoftEdgeBackups"
            )
            $folders_to_remove_by_subfolder = @(
                "C:\ProgramData\Packages",
                "C:\Windows\SystemApps",
                "C:\Program Files\WindowsApps",
                "C:\ProgramData\Microsoft\Windows\AppRepository",
                "C:\ProgramData\Microsoft\Windows\Start Menu\Programs",
                "$UserHome\Desktop"
            )
            $folders_to_remove_by_subfolder_aggressive = @(
                "C:\Program Files (x86)\Microsoft"
            )
            SyslevelDebugLog "folders_to_remove"
            $folders_to_remove | ForEach-Object {
                if (-not (Test-Path -Path $_)) {
                    SyslevelDebugLog "Skipping nonexistent path $_"
                }
                else {
                    SyslevelDebugLog "File remove: $_"
                    Remove-Item -Recurse -Force -Path $_ | Tee-Object -FilePath $global:verbose_log
                }
            }
            SyslevelDebugLog "folders_to_remove_by_subfolder"
            $folders_to_remove_by_subfolder | ForEach-Object {
                $path = $_
                if (-not (Test-Path -Path $path)) {
                    SyslevelDebugLog "Skipping nonexistent path $path"
                }
                else {
                    Get-ChildItem -Path $_ | Where-Object { $_ -Like "*Microsoft*Edge*" } | ForEach-Object {
                        "File remove: $path\$_" | SyslevelDebugLog
                        Remove-Item -Recurse -Force -Path "$path\$_" | Tee-Object -FilePath $global:verbose_log
                    }
                }
            }
            SyslevelDebugLog "folders_to_remove_by_subfolder_aggressive"
            $folders_to_remove_by_subfolder_aggressive | ForEach-Object {
                $path = $_
                if (-not (Test-Path -Path $path)) {
                    SyslevelDebugLog "Skipping nonexistent path $path"
                }
                else {
                    Get-ChildItem -Path $_ | Where-Object { $_ -Like "*Edge*" } | ForEach-Object {
                        SyslevelDebugLog "File remove: $path\$_"
                        Remove-Item -Recurse -Force -Path "$path\$_" | Tee-Object -FilePath $global:verbose_log
                    }
                }
            }
        }
    }

    Remove-Item -Path "C:\.PowerWashHome.tmp"

    SyslevelDebugLog "ElevatedAction exiting"
    exit
}



### POWERWASH FEATURES ###



""
"### PERFORMANCE FEATURES ###"
""


# Disable HPET (high precision event timer)
# Some systems will benefit from this, some will suffer. Only way is to benchmark and see
if (Confirm "Do you want to disable the high-precision event timer? (May not improve performance on all systems)" -Auto $false -ConfigKey "Performance.DisableHpet") {
    Get-PnpDevice -FriendlyName "High precision event timer" | Disable-Pnpdevice -Confirm:$false
    "- Complete"
}

if (Confirm "Enable hardware-accelerated GPU scheduling?" -Auto $true -ConfigKey "Performance.HwGpuScheduling") {
    RegistryPut $RK_GPUSched -Key "HwSchMode" -Value 2 -VType "DWORD"
    "- Complete"
}

# Multimedia related settings to prioritize audio
if ($do_all -or (Confirm "Do you want to optimize multimedia settings for pro audio?" -Auto $true -ConfigKey "Performance.MultimediaResponsiveness")) {
    # Scheduling algorithm will reserve 10% (default is 20%) of CPU for low-priority tasks
    RegistryPut $RK_MMCSS -Key "SystemResponsiveness" -Value 10 -VType "DWORD"
	
    # May reduce idling, improving responsiveness
    RegistryPut $RK_MMCSS_ProAudio -Key "NoLazyMode" -Value 1 -VType "DWORD"
	
    # Max priority for Pro Audio tasks
    RegistryPut $RK_MMCSS_ProAudio -Key "Priority" -Value 1 -VType "DWORD"
    RegistryPut $RK_MMCSS_ProAudio -Key "Scheduling Category" -Value "High" -VType "String"
	
    "- Complete"
}

# Prioritize low latency on network adapters
if (Confirm "Optimize network adapter settings for low latency?" -Auto $true -ConfigKey "Performance.NetworkResponsiveness") {
    RegistryPut $RK_MMCSS -Key "NetworkThrottlingIndex" -Value 0xFFFFFFFF -VType "DWORD"
    RegistryPut $RK_Net_Ndu -Key "Start" -Value 0x4 -VType "DWORD"
	
    # Below settings may fail depending on network adapter's capabilities. This isn't a problem, so fail silently
    Set-NetAdapterAdvancedProperty -Name "*" -IncludeHidden -DisplayName "Throughput Booster" -DisplayValue "Enabled" -EA SilentlyContinue 2>$null | Out-Null
    Enable-NetAdapterChecksumOffload -Name "*" -IncludeHidden -EA SilentlyContinue
    Disable-NetAdapterRsc -Name '*' -IncludeHidden -EA SilentlyContinue 2>$null | Out-Null  # Disables packet coalescing
    Disable-NetAdapterPowerManagement -Name '*' -IncludeHidden -EA SilentlyContinue 2>$null | Out-Null
    Restart-NetAdapter -Name '*' -IncludeHidden -EA SilentlyContinue 2>$null | Out-Null
	
    "- Complete"
}

# Power management settings for high performance - "Ultimate" power scheme bundled with newer Windows versions
if (Confirm "Redline power settings for maximum performance? (May reduce latency, but will use more power)" -Auto $true -ConfigKey "Performance.PowerSettingsMaxPerformance") {
    "- Enabling 'Ultimate' performance plan..."
    $guid_match = ".*GUID: (\w+-\w+-\w+-\w+-\w+).*"
    $default_ultimate_guid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
    $active_scheme = ((powercfg /getactivescheme) -ireplace $guid_match, '$1')
    $scheme = ((powercfg /duplicatescheme $default_ultimate_guid) -ireplace $guid_match, '$1')
    powercfg /setacvalueindex $scheme 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0  # Disable usb selective suspend
    powercfg /setacvalueindex $scheme 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 0  # Disable wake timers
    powercfg /setacvalueindex $scheme SUB_PROCESSOR LATENCYHINTPERF1 99  # Latency sensitive tasks will raise performance level
    powercfg /setacvalueindex $scheme SUB_VIDEO VIDEOIDLE 0  # Don't automatically turn off display
	
    "- Applying additional performance settings..."
    # Below are documented at https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/hardware/power/power-performance-tuning
    powercfg /setacvalueindex $scheme SUB_PROCESSOR DISTRIBUTEUTIL 0  # Disable utility distribution, which can reduce performance
    powercfg /setacvalueindex $scheme SUB_PROCESSOR CPMINCORES 100  # Disable core parking
    # Below are recommended by Microsoft for ultra-low latency
    # They will rapidly increase performance in response to increased workload,
    # and only slowly decrease performance in response to decreased workload
    powercfg /setacvalueindex $scheme SUB_PROCESSOR PERFINCPOL 2
    powercfg /setacvalueindex $scheme SUB_PROCESSOR PERFDECPOL 1
    powercfg /setacvalueindex $scheme SUB_PROCESSOR PERFINCTHRESHOLD 10
    powercfg /setacvalueindex $scheme SUB_PROCESSOR PERFDECTHRESHOLD 8
	
    powercfg /setacvalueindex $scheme SUB_PROCESSOR PERFBOOSTMODE 2  # Aggressive turbo boosting
	
    powercfg /setactive $scheme
	
    "- Cleaning up stale copies..."
    # Delete old profiles from this script being run multiple times
    foreach ($line in powercfg /list) {
        if (-not ($line -match $guid_match)) {
            continue
        }
        $guid = (($line) -ireplace ".*GUID: (\w+-\w+-\w+-\w+-\w+).*", '$1')
        if (($guid -eq $active_scheme) -or ($guid -eq $default_ultimate_guid)) {
            continue
        }
        if ($line -match "\(Ultimate Performance\)") {
            powercfg /delete $guid 2>$null | Out-Null
        }			
    }
	
    # Disable power throttling
    RegistryPut $RK_PowerThrottling -Key "PowerThrottlingOff" -Value 1 -VType "DWORD"
	
    # Make hibernate option user-selectable
    powercfg /hibernate on
	
    "- Complete"
}


if (Confirm "Disable Fast Startup? (may fix responsiveness issues with some devices)" -Auto $true -ConfigKey "Performance.DisableFastStartup") {
    RegistryPut $RK_FastStartup -Key "HiberbootEnabled" -Value 0 -VType "DWORD"
    "- Complete"
}

# Enable MSI mode for devices that support it
# Message-signaled interrupts are an alternative to line-based interrupts,
# supporting a larger number of interrupts and lower latencies.
if (Confirm "Do you want to enable Message-Signaled Interrupts for all devices that support them?" -Auto $true -ConfigKey "Performance.EnableDriverMsi") {
    $do_priority = Confirm "--> Do you also want to prioritize interrupts from certain devices like the GPU and PCIe controller?" -Auto $true -ConfigKey "Performance.EnableDriverPrio"
	
    "- Applying interrupt policies..."
	
    $N_MSI = 0
    $N_Prio = 0
    $Devices = Get-CimInstance -ClassName Win32_PnPEntity
    foreach ($Device in $Devices) {
        # https://powershell.one/wmi/root/cimv2/win32_pnpentity-GetDeviceProperties
        $Properties = Invoke-CimMethod -MethodName GetDeviceProperties -InputObject $Device | Select-Object -ExpandProperty DeviceProperties
		
        $DeviceDesc = ($Properties | Where-Object { $_.KeyName -eq 'DEVPKEY_Device_DeviceDesc' }).Data
        $InstanceId = ($Properties | Where-Object { $_.KeyName -eq 'DEVPKEY_Device_InstanceId' }).Data
		
        # Prioritize interrupts from PCIe controller and graphics card
        if ($do_priority -and ($DeviceDesc -like "*PCIe Controller*" -or $DeviceDesc -like "*NVIDIA GeForce*")) {
            "  - Prioritizing interrupts from $DeviceDesc..."
            RegistryPut "$RK_DevEnum\$InstanceId\Device Parameters\Interrupt Management\Affinity Policy" -Key "DevicePriority" -Value 3 -VType "DWORD"
            $N_Prio++
        }
		
        # https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/shared/pciprop.h#L345
        # 1 = LineBased, 2 = Msi, 4 = MsiX
        # Only devices that support MSI should have it enabled. Attempting to enable MSI on a device
        # that does not support it *can* make Windows unbootable. The "InterruptSupport" key tells us
        # what interrupt types are supported, so we can ensure they're only enabled where valid
        $InterruptModes = ($Properties | Where-Object { $_.KeyName -eq 'DEVPKEY_PciDevice_InterruptSupport' }).Data
        if ($InterruptModes -gt 1) {
            "  - Enabling MSI mode for $DeviceDesc..."
            RegistryPut "$RK_DevEnum\$InstanceId\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" -Key "MSISupported" -Value 1 -VType "DWORD"
            $N_MSI++
        }
    }
    "- MSI mode enabled for all $N_MSI supported devices. Restart required to take effect"
    "- Interrupts prioritized for $N_Prio devices. Restart required to take effect"
    "- Complete"
}



""
""
"### TELEMETRY CONFIGURATION ###"
""


# Disable Microsoft telemetry as much as we can
if (Confirm "Do you want to disable Microsoft telemetry?" -Auto $true -ConfigKey "DisableTelemetry") {
    # Windows has 4 levels of telemetry: Security, Required, Enhanced, Optional
    # According to Microsoft, only Enterprise supports Security as min telemetry level, other platforms only support Required
    # However, we can just always set it to Security and Windows will apply the lowest allowed setting.
    $min_telemetry = 0
	
    "- Disabling telemetry registry settings..."
    RegistryPut $RK_Policy_DataCollection -Key "AllowTelemetry" -Value $min_telemetry -VType "DWORD"
    RegistryPut $RK_Privacy -Key "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -VType "DWORD"
    RegistryPut $RK_TIPC -Key "Enabled" -Value 0 -VType "DWORD"  # Inking/typing
    RegistryPut $RK_Policy_AppCompat -Key "AITEnable" -Value 0 -VType "DWORD"  # Apps
	
    "- Disabling known telemetry services..."
    sc.exe config DiagTrack start=disabled | Out-Null
    sc.exe config dmwappushservice start=disabled | Out-Null
    sc.exe config PcaSvc start=disabled | Out-Null
    sc.exe config RemoteRegistry start=disabled | Out-Null
	
    "- Disabling known telemetry tasks..."
    TryDisableTask "Consolidator"
    TryDisableTask "FamilySafetyMonitor"
    TryDisableTask "FamilySafetyRefreshTask"
    TryDisableTask "Intel Telemetry"
    TryDisableTask "Intel Telemetry 1"
    TryDisableTask "Intel Telemetry 2"
    TryDisableTask "Intel Telemetry 3"
    TryDisableTask "Microsoft Compatibility Appraiser"
    TryDisableTask "ProgramDataUpdater"
    TryDisableTask "OfficeTelemetryAgentFallBack"
    TryDisableTask "OfficeTelemetryAgentLogOn"
    TryDisableTask "UsbCeip"
    TryDisableTask "KernelCeipTask"
    Disable-ScheduledTask -TaskName "CreateObjectTask" -TaskPath "\Microsoft\Windows\CloudExperienceHost" -EA SilentlyContinue | Out-Null
	
    Set-MpPreference -DisableNetworkProtectionPerfTelemetry $true | Out-Null
	
    "- Complete"
}



""
""
"### BLOATWARE REMOVAL ###"
""


if (Confirm "Disable Cortana?" -Auto $true -ConfigKey "Debloat.DisableCortana") {
    RegistryPut $RK_Policy_Search -Key "AllowCortana" -Value 0 -VType "DWORD"
    RegistryPut $RK_Policy_Search -Key "DisableWebSearch" -Value 1 -VType "DWORD"
    RegistryPut $RK_Policy_Search -Key "ConnectedSearchUseWeb" -Value 0 -VType "DWORD"
    RegistryPut $RK_Policy_Search -Key "ConnectedSearchUseWebOverMeteredConnections" -Value 0 -VType "DWORD"
    "- Complete"
}

if ($has_win_enterprise -and (Confirm "Disable Windows consumer features?" -Auto $true -ConfigKey "Debloat.DisableConsumerFeatures")) {
    RegistryPut $RK_Policy_CloudContent -Key "DisableWindowsConsumerFeatures" -Value 1 -VType "DWORD"
    RegistryPut $RK_Policy_CloudContent -Key "DisableThirdPartySuggestions" -Value 1 -VType "DWORD"
    RegistryPut $RK_Policy_CloudContent -Key "DisableThirdPartySuggestions" -Value 1 -VType "DWORD"
    RegistryPut $RK_Policy_CloudContent -Key "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -VType "DWORD"
    "- Complete"
}

if ($has_win_enterprise -and (Confirm "Disable preinstalled apps?" -Auto $true -ConfigKey "Debloat.DisablePreinstalled")) {
    RegistryPut $RK_ContentDelivery -Key "FeatureManagementEnabled" -Value 0 -VType "DWORD"
    RegistryPut $RK_ContentDelivery -Key "OemPreInstalledAppsEnabled" -Value 0 -VType "DWORD"
    RegistryPut $RK_ContentDelivery -Key "PreInstalledAppsEnabled" -Value 0 -VType "DWORD"
    RegistryPut $RK_ContentDelivery -Key "ContentDeliveryAllowed" -Value 0 -VType "DWORD"
    RegistryPut $RK_ContentDelivery -Key "SilentInstalledAppsEnabled" -Value 0 -VType "DWORD"
    RegistryPut $RK_ContentDelivery -Key "PreInstalledAppsEverEnabled" -Value 0 -VType "DWORD"
    RegistryPut $RK_ContentDelivery -Key "SystemPaneSuggestionsEnabled" -Value 0 -VType "DWORD"
    RegistryPut $RK_ContentDelivery -Key "SoftLandingEnabled" -Value 0 -VType "DWORD"
    "- Complete"
}

if (Confirm "Remove configured list of preinstalled apps?" -Auto $true -ConfigKey "Debloat.RemovePreinstalled") {
    # Adapted from  https://www.kapilarya.com/how-to-uninstall-built-in-apps-in-windows-10
    ForEach ($App in $global:config_map.Debloat.RemovePreinstalledList) {
        $Packages = Get-AppxPackage | Where-Object { $_.Name -eq $App }
        if ($null -eq $Packages) {
            "- No installed packages found for $App, skipping"
        }
        else {
            "- Attempting removal of $App installed package..."
            foreach ($Package in $Packages) {
                Set-NonRemovableAppsPolicy -Online -PackageFamilyName $Package.PackageFamilyName -NonRemovable 0 | Out-Null
                Remove-AppxPackage -package $Package.PackageFullName 2>$null | Out-Null
            }
        }
        $ProvisionedPackage = Get-AppxProvisionedPackage -online | Where-Object { $_.displayName -eq $App }
        if ($null -eq $ProvisionedPackage) {
            "- No provisioned package found for $App, skipping"
        }
        else {
            "- Attempting removal of $App provisioned package..."
            Remove-AppxProvisionedPackage -online -packagename $ProvisionedPackage.PackageName 2>$null | Out-Null
        }
    }
    "- Complete"
}

if (Confirm "Remove configured list of Windows capabilities?" -Auto $true -ConfigKey "Debloat.RemoveWindowsCapabilities") {
    $Caps = Get-WindowsCapability -Online
    ForEach ($CapName in $global:config_map.Debloat.RemoveWindowsCapabilitiesList) {
        $Cap = $Caps | Where-Object { $_.Name -Like "*$CapName*" }
        if ($null -eq $Cap) {
            "- No such capability as $CapName, skipping"
        }
        else {
            "- Removing $CapName capability..."
            $Caps | Where-Object { $_.Name -Like "*$Cap*" } | Remove-WindowsCapability -Online 2>$null | Out-Null
        }
    }
    "- Complete"
}

if (Confirm "Remove Microsoft Edge? (EXPERIMENTAL)" -Auto $false -ConfigKey "Debloat.RemoveEdge") {
    "- NOTE: This feature is experimental and may not work completely or at all"
	
    "- Marking Edge as removable..."
    RegistryPut $RK_Uninst_Edge -Key "NoRemove" -Value 0 -VType "DWORD"
    RegistryPut $RK_Uninst_Edge -Key "NoRepair" -Value 0 -VType "DWORD"
	
    "- Attempting to remove Edge using setup tool..."
    $edge_base = "C:\Program Files (x86)\Microsoft\Edge\Application\"
    if (Test-Path "$edge_base") {
        foreach ($item in Get-ChildItem -Path "$edge_base") {
            $setup = "$edge_base\$item\Installer\setup.exe"
            if (Test-Path "$setup") {
                "Removing Edge installation: $setup"
                & "$setup" --uninstall --msedge --system-level --verbose-logging --force-uninstall
            }
        }
    }
	
    "- Removing Edge from provisioned packages..."
    $provisioned = (Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Edge*" }).PackageName
    if ($null -ne $provisioned) {
        Remove-AppxProvisionedPackage -PackageName $provisioned -Online -AllUsers
    }

    # Many registry keys to remove are protected by SYSTEM
    "- Removing Edge from registry..."
    RunScriptAsSystem -Path "$PSScriptRoot/PowerWash.ps1" -ArgString "/ElevatedAction /RemoveEdge /RegistryStage"

    # Many folders to remove are protected by SYSTEM
    "- Removing Edge from filesystem..."
    RunScriptAsSystem -Path "$PSScriptRoot/PowerWash.ps1" -ArgString "/ElevatedAction /RemoveEdge /FilesystemStage"

    "- Disabling Edge services..."
    $services_to_disable = @(
        "edgeupdate",
        "edgeupdatem",
        "MicrosoftEdgeElevationService"
    )
    $services_to_disable | ForEach-Object {
        sc.exe stop $_ | Out-Null
        sc.exe config $_ start=disabled | Out-Null
    }

    # Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\MicrosoftEdge
    # ^ OSIntegrationLevel: 6 -> 0

    # Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\EdgeIntegration
    # ^ Supported: 1 -> 0
	
    "- Complete"
}



""
""
"### WINDOWS UPDATE CONFIGURATION ###"
""


# Disable automatic updates
if ($has_win_pro) {
    if (Confirm "Do you want to disable automatic Windows updates?" -Auto $true -ConfigKey "WindowsUpdate.DisableAutoUpdate") {
        RegistryPut $RK_Policy_Update_AU -Key "NoAutoUpdate" -Value 1 -VType "DWORD"
        RegistryPut $RK_Policy_Update_AU -Key "AUOptions" -Value 2 -VType "DWORD"
        RegistryPut $RK_Store_Update -Key "AutoDownload" -Value 5 -VType "DWORD"
        RegistryPut $RK_Policy_Store -Key "AutoDownload" -Value 4 -VType "DWORD"
        RegistryPut $RK_Policy_Store -Key "DisableOSUpgrade" -Value 1 -VType "DWORD"
        RegistryPut $RK_Policy_Update -Key "AUPowerManagement" -Value 0 -VType "DWORD"
        "- Complete"
    }
}
else {
    "Windows Home edition does not support disabling only automatic updates, skipping this feature"
    "If you want to disable automatic updates on Home, you can try setting your internet connection to Metered. Otherwise, you can disable updates entirely below."
}

# Disable all updates
if (Confirm "Do you want to disable all Windows updates? (You will need to manually re-enable them when you want to check or install updates)" -Auto $false -ConfigKey "WindowsUpdate.DisableAllUpdate") {
    sc.exe stop UsoSvc | Out-Null
    sc.exe config UsoSvc start=disabled | Out-Null

    sc.exe stop WaaSMedicSvc | Out-Null
    RegistryPut "$RK_Services\WaaSMedicSvc" -Key "Start" -Value 4 -VType "DWORD"

    sc.exe stop wuauserv | Out-Null
    sc.exe config wuauserv start=disabled | Out-Null
	
    "- Complete"
}

# Add update toggle script to desktop
# This is the next best thing for Home users to being able to disable automatic updates. They can toggle updates on when they want to check or install updates, and toggle updates back off when they're done.
if ((-not (Test-Path "$home\Documents\.ToggleUpdates.bat")) -or (-not (Test-Path "$home\Desktop\Toggle Updates.lnk"))) {
    if (Confirm "Do you want to add a script to your desktop that lets you toggle Windows updates on or off?" -Auto $false -ConfigKey "WindowsUpdate.AddUpdateToggleScriptToDesktop") {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/UniverseCraft/WindowsPowerWash/main/extra/ToggleUpdates.bat" -OutFile $home\Documents\.ToggleUpdates.bat
        
        CreateShortcut -Dest "$home\Desktop\Toggle Updates.lnk" -Source "$home\Documents\.ToggleUpdates.bat" -Admin $true
        
        "- Complete (script in Documents, shortcut on Desktop)"
    }
}
else {
    "Windows Update toggle script already exists, skipping this feature"
}



""
""
"### INSTALLATION CONFIGURATION ###"
""


# Install Group Policy editor, which isn't installed by default on Home editions
# Allows easy tweaking of a wide range of settings without needing to edit registry
if ((-not $has_win_pro) -and (-not $noinstall) -and (Confirm "Install Group Policy editor? (Not installed by default on Home editions)" -Auto $true -ConfigKey "Install.InstallGpEdit")) {
    "- Installing Group Policy editor..."
    cmd /c 'FOR %F IN ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum") DO (DISM /Online /NoRestart /Add-Package:"%F")' | Out-Null
    cmd /c 'FOR %F IN ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum") DO (DISM /Online /NoRestart /Add-Package:"%F")' | Out-Null
	
    "- Complete"
}

if ((-not $has_winget) -and (Confirm "Install Winget package manager?" -Auto $false -ConfigKey "Install.InstallWinget")) {
    "- Installing Winget dependencies..."
	
    # https://github.com/microsoft/winget-cli/issues/1861#issuecomment-1435349454
    Add-AppxPackage -Path https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx

    Invoke-WebRequest -Uri https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.7.3 -OutFile .\microsoft.ui.xaml.2.7.3.zip
    Expand-Archive .\microsoft.ui.xaml.2.7.3.zip
    Add-AppxPackage .\microsoft.ui.xaml.2.7.3\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.7.appx

    "- Installing Winget..."
    Invoke-WebRequest -Uri https://github.com/microsoft/winget-cli/releases/download/v1.4.10173/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle -OutFile .\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
    Add-AppxPackage .\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
	
    $has_winget = $true
	
    "- Complete"
}

if ($has_winget) {
    if (Confirm "Install configured applications?" -Auto $false -ConfigKey "Install.InstallConfigured") {
        foreach ($params in $global:config_map.Install.InstallConfiguredList) {
            & "winget" "install" "--accept-package-agreements" "--accept-source-agreements" "$params"
        }
        "- Complete"
    }
}
else {
    "Skipping install of configured applications: Winget not installed"
}



""
""
"### WINDOWS DEFENDER CONFIGURATION ###"
""


if (Confirm "Configure Windows Defender to run scans only when computer is idle?" -Auto $true -ConfigKey "Defender.DefenderScanOnlyWhenIdle") {
    if ($global:do_config) {
        $timeout_mins = $global:config_map.Defender.DefenderScanOnlyWhenIdle_TimeoutMins
    }
    else {
        $timeout_mins = 10
    }
    $wait = New-TimeSpan -Minutes $timeout_mins
    $settings = New-ScheduledTaskSettingsSet -RunOnlyIfIdle -IdleWaitTimeout $wait -RestartOnIdle
    Set-ScheduledTask -TaskPath "Microsoft\Windows\Windows Defender" -TaskName "Windows Defender Cache Maintenance" -Settings $settings | Out-Null
    Set-ScheduledTask -TaskPath "Microsoft\Windows\Windows Defender" -TaskName "Windows Defender Cleanup" -Settings $settings | Out-Null
    Set-ScheduledTask -TaskPath "Microsoft\Windows\Windows Defender" -TaskName "Windows Defender Scheduled Scan" -Settings $settings | Out-Null
    Set-ScheduledTask -TaskPath "Microsoft\Windows\Windows Defender" -TaskName "Windows Defender Verification" -Settings $settings | Out-Null
    Set-MpPreference -ScanOnlyIfIdleEnabled $true
    "- Complete"
}

if (Confirm "Run Defender tasks at a lower priority?" -Auto $true -ConfigKey "Defender.DefenderScanLowPriority") {
    if ($global:do_config) {
        $max_cpu_usage = $global:config_map.Defender.DefenderScanLowPriority_MaxCpuUsage
    }
    else {
        $max_cpu_usage = 5
    }
    Set-MpPreference -EnableLowCpuPriority $true
    Set-MpPreference -ScanAvgCPULoadFactor $max_cpu_usage
    "- Complete"
}

if (Confirm "Disable real-time protection from Windows Defender? (CAUTION) (EXPERIMENTAL)" -Auto $false -ConfigKey "Defender.DisableRealtimeMonitoringCAUTION") {
    $disable_all_defender = Confirm "--> Disable Windows Defender entirely? (CAUTION) (EXPERIMENTAL)" -Auto $false -ConfigKey "Defender.DisableAllDefenderCAUTIONCAUTION"
    RunScriptAsSystem -Path "$PSScriptRoot/PowerWash.ps1" -ArgString "/ElevatedAction /DisableRealtimeMonitoring $(If ($disable_all_defender) {'/DisableAllDefender'} Else {''})"
	
    "- Complete (requires Tamper Protection disabled to take effect)"
}



""
""
"### CONVENIENCE SETTINGS ###"
""


if (Confirm "Disable app startup delay?" -Auto $true -ConfigKey "Convenience.DisableStartupDelay") {
    RegistryPut $RK_Explorer_Serialize -Key "StartupDelayInMSec" -Value 0 -VType "DWORD"
    "- Complete"
}

# Seconds in taskbar
if (Confirm "Do you want to show seconds in the taskbar clock?" -Auto $false -ConfigKey "Convenience.ShowSecondsInTaskbar") {
    RegistryPut $RK_Explorer_Advanced -Key "ShowSecondsInSystemClock" -Value 1 -VType "DWORD"
    "- Complete"
}

# Show "Run as different user"
if (Confirm "Do you want to show 'Run as different user' in Start?" -Auto $true -ConfigKey "Convenience.ShowRunAsDifferentUser") {
    RegistryPut $RK_Policy_Explorer -Key "ShowRunAsDifferentUserInStart" -Value 1 -VType "DWORD"
    "- Complete"
}

# Show useful Explorer stuff
if (Confirm "Do you want to show file extensions and hidden files in Explorer?" -Auto $true -ConfigKey "Convenience.ShowHiddenExplorer") {
    RegistryPut $RK_Explorer_Advanced -Key "Hidden" -Value 1 -VType "DWORD"
    RegistryPut $RK_Explorer_Advanced -Key "HideFileExt" -Value 0 -VType "DWORD"
    "- Complete"
}

# Clean up taskbar
if (Confirm "Clean up taskbar? (Recommended for a cleaner out-of-box Windows experience)" -Auto $false -ConfigKey "Convenience.CleanupTaskbar") {
    UnpinApp("Microsoft Store")
    UnpinApp("Microsoft Edge")
    RegistryPut $RK_Policy_Feeds -Key "EnableFeeds" -Value 0 -VType "DWORD"
    taskkill /f /im explorer.exe | Out-Null
    Start-Process explorer.exe
    "- Complete"
}

# Configure search box in taskbar
if ($global:do_config) {
    $searchbox_mode = $global:config_map.Convenience.TaskbarSearchboxMode
    "Configuring search box in taskbar"
}
elseif (Confirm "Configure search box in taskbar?" -Auto $true) {
    $searchbox_mode = Read-Host "- Enter 'Full' to show the full search box, 'Icon' to just show the search icon, or 'Hidden' to hide the search box and icon entirely"
}
else {
    $searchbox_mode = "NoChange"
}
if ($searchbox_mode -eq "Full") {
    RegistryPut $RK_Search -Key "TraySearchBoxVisible" -Value 1 -VType "DWORD"
    RegistryPut $RK_Search -Key "SearchboxTaskbarMode" -Value 2 -VType "DWORD"
}
elseif ($searchbox_mode -eq "Icon") {
    RegistryPut $RK_Search -Key "TraySearchBoxVisible" -Value 0 -VType "DWORD"
    RegistryPut $RK_Search -Key "SearchboxTaskbarMode" -Value 1 -VType "DWORD"
}
elseif ($searchbox_mode -eq "Hidden") {
    RegistryPut $RK_Search -Key "TraySearchBoxVisible" -Value 0 -VType "DWORD"
    RegistryPut $RK_Search -Key "SearchboxTaskbarMode" -Value 0 -VType "DWORD"
}
if ($searchbox_mode -ne "NoChange") {
    taskkill /f /im explorer.exe | Out-Null
    Start-Process explorer.exe
    "- Complete"
}



""
""
"### SCANS AND AUTOMATIC REPAIRS ###"
""


# Check system file integrity
if ((-not $noscan) -and (Confirm "Run system file integrity checks? (May take a few minutes)" -Auto $false -ConfigKey "Scans.CheckIntegrity")) {
    "- Running Deployment Image Servicing and Management Tool..."
    dism.exe /online /cleanup-image /restorehealth
	
    "- Running System File Checker..."
    sfc.exe /scannow
	
    "- Complete"
}

# Checks for IRQ conflicts
if (Confirm "Do you want to check for IRQ conflicts?" -Auto $true -ConfigKey "Scans.CheckIRQ") {
    Get-CimInstance Win32_PNPAllocatedResource | Out-File -FilePath "IRQDump.txt"
	(Select-String -Path "IRQDump.txt" -Pattern "IRQNumber") -ireplace '.*IRQNumber = (\d+).*', '$1' | Out-File -FilePath IRQNumbers.txt
    $SharedIRQ = (Get-Content IRQNumbers.txt | Group-Object | Where-Object { $_.Count -gt 1 } | Select-Object -ExpandProperty Name)
    if ($SharedIRQ.Length -gt 0) {
        "- Alert: IRQ conflicts found at: $SharedIRQ"
        "- This means that more than one device is sharing an interrupt line to the CPU, which *may* cause resource contention and degrade performance of those devices."
    }
    else {
        "- No IRQ conflicts found"
    }
}

# Checks for third-party antivirus products (generally not needed)
if ((-not $global:do_config) -or ($global:config_map.Scans.WarnAV)) {
    $av_product = (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).displayName
    if ($av_product -ne "Windows Defender") {
        "Notice: You are using a third-party antivirus product ($av_product). These can slow down your system and often don't provide any extra benefit."
        if ($av_product -like "*McAffee*") {
            "Warning: McAffee software is especially notorious for bloating your system and providing low-quality protection!"
        }
    }
}



""
""
"### POWERWASH COMPLETE ###"
"A restart is recommended"
""



if ($is_unattend -and (-not $will_restart)) {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show('Custom Windows configuration has been successfully applied. A restart is recommended.', 'PowerWash Setup', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information)
}

if ($will_restart) {
    Restart-Computer
}
