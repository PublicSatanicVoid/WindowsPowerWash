#
# PowerWash (Beta)
#
# Aims to improve system responsiveness, performance, and latency
# by tuning settings to uncompromisingly favor performance and
# low latencies. Also removes some usually unwanted default Windows
# behaviors and hardens device security.
#
# USE AT YOUR OWN RISK. BACKUP SYSTEM BEFORE USING.
#

$global:ScriptName = $MyInvocation.MyCommand.Name

$global:sys_account_debug_log = "$env:SystemDrive\PowerWashSysActionsDbg.log"
$global:is_debug = $false
if ($global:is_debug) {
    "POWERWASH DEBUG MODE IS ON"
    ""
}


$global:is_msert = "/msert" -in $args  # Microsoft Edge Removal Tool- specifies to only run Edge removal features of PowerWash
if ($global:is_msert) {
    $global:tool_name = "MSERT"
}
else {
    $global:tool_name = "PowerWash"
}


if (-not $global:is_msert) {
    ""
    "IMPORTANT NOTICE: It is recommended to restart before running PowerWash, to minimize the chance that certain system files will be in use by other programs. This is especially important if you are trying to remove Edge."
}
""
"IMPORTANT NOTICE: It is recommended to create a system restore point before running $global:tool_name. The author of $global:tool_name takes no responsibility for its effects on the user's system; see"
"    https://github.com/PublicSatanicVoid/WindowsPowerWash/blob/main/LICENSE"
"for more details."
""



### USAGE INFORMATION ###
if ("/?" -in $args) {
    ".\$global:ScriptName MODE [/noinstalls] [/noscans] [/autorestart]"
    "  Supported modes:"
    "    /all            Runs all PowerWash features without prompting"
    "    /auto           Runs a default subset of PowerWash features, without prompting"
    "    /config         Runs actions enabled in PowerWashSettings.yml, without prompting"
    "    /config <path>  Runs actions enabled in provided config file, without prompting"
    "    /stats          Shows current performance stats and exits"
    "    /warnconfig     Shows potentially destructive configured operations"
    "  Additional options:"
    "    /noinstalls     Skips PowerWash actions that would install software (overrides other flags)"
    "    /noscans        Skips PowerWash actions that perform lengthy scans (overrides other flags)"
    "    /autorestart    Restarts computer when done"
    exit
}


"Loading dependencies..."
if (-not $global:is_msert) {
    "- NuGet package manager"
    if ("NuGet" -notin (Get-PackageProvider | Select-Object Name).Name) {
        Install-PackageProvider -Name NuGet -Force | Out-Null
        "  - Installed NuGet package manager"
    }
    "- powershell-yaml module"
    Import-Module powershell-yaml 2>$null | Out-Null
    if (-not $?) {
        Install-Module -Name powershell-yaml -Force
        " - Installed powershell-yaml module"
    }
}

""


### COMMAND LINE PARAMETERS ###
$global:do_all = "/all" -in $args
$global:do_all_auto = "/auto" -in $args
$global:do_config = "/config" -in $args
$config_path = ".\PowerWashSettings.yml"
$switches = @("/all", "/auto", "/config", "/warnconfig", "/stats", "/noinstalls", "/noscans", "/autorestart", "-Confirm", "-Confirm:")
$next_is_config_path = $false
foreach ($arg in $args) {
    if ($arg -eq "/config") {
        $next_is_config_path = $true
    }
    elseif ($next_is_config_path) {
        if ($arg -notin $switches) {
            $config_path = $arg
        }
        $next_is_config_path = $false
    }
}
if ($global:do_all -and $global:do_all_auto) {
    "==============================================================================="
    "Error: Can only specify one of /all or /auto"
    "Do '.\$global:ScriptName /?' for help"
    "==============================================================================="
    exit
}
$global:config_map = If (Test-Path "$config_path") {
    (Get-Content -Raw "$config_path" | ConvertFrom-Yaml)
}
Else {
    @{}
}
if (-not (Test-Path "$config_path") -and -not $global:is_msert) {
    "==============================================================================="
    "Error: Specified config file '$config_path' does not exist"
    "Do '\$global:ScriptName /?' for help"
    "==============================================================================="
    exit
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
            "* WARNING: Configured settings will disable Windows Defender entirely. (EXPERIMENTAL)"
        }
        else {
            "* WARNING: Configured settings will disable Windows Defender realtime monitoring. (EXPERIMENTAL)"
        }
    }
    if ($global:config_map.Debloat.RemoveEdge) {
        "* Will remove Microsoft Edge"
        if ($global:config_map.Deblaot.RemoveEdge_ExtraTraces) {
            "  - Will attempt to remove additional traces of Edge"
        }
    }
    if ($global:config_map.Debloat.RemoveStore) {
        "* Will remove Windows Store"
    }
    if ($global:config_map.Debloat.RemovePreinstalled) {
        "* Will remove the following preinstalled apps:"
        foreach ($app in $global:config_map.Debloat.RemovePreinstalledList) {
            "  - $app"
        }
        "* Will remove preinstalled apps matching the following name patterns:"
        foreach ($pat in $global:config_map.Debloat.RemovePreinstalledPatterns) {
            "  - $pat"
        }
    }
    if ($global:config_map.Debloat.RemoveWindowsCapabilities) {
        "* Will remove the following capabilities:"
        foreach ($cap in $global:config_map.Debloat.RemoveWindowsCapabilitiesList) {
            "  - $app"
        }
    }
    if ($global:config_map.Debloat.RemovePhantom) {
        "* Will remove phantom applications"
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
    "Performance.PowerSettingsMaxPerformance"      = "Applying high-performance power settings";
    "Performance.NetworkResponsiveness"            = "Applying high-performance network adapter settings";
    "Performance.EnableDriverMsi"                  = "Enabling message-signaled interrupts on supported devices";
    "Performance.EnableDriverPrio"                 = "Prioritizing GPU and PCIe controller interrupts";
    "Performance.DisableHpet"                      = "Disabling High-precision event timer";
    "Performance.HwGpuScheduling"                  = "Enabling hardware-accelerated GPU scheduling";
    "Performance.MultimediaResponsiveness"         = "Applying high-performance multimedia settings";
    "Performance.AdjustVisualEffects"              = "Applying high-performance visual effects settings";
    "Performance.DisableFastStartup"               = "Disabling fast startup";
    "DisableTelemetry"                             = "Disabling Microsoft telemetry";
    "Debloat.DisableCortana"                       = "Disabling Cortana";
    "Debloat.DisableConsumerFeatures"              = "Disabling Microsoft consumer features";
    "Debloat.DisablePreinstalled"                  = "Disabling preinstalled apps from Microsoft and OEMs";
    "Debloat.RemovePreinstalled"                   = "Removing configured list of preinstalled apps";
    "Debloat.RemovePreinstalledPatterns"           = "Removing configured list of preinstalled apps based on pattern-matched names";
    "Debloat.RemoveWindowsCapabilities"            = "Removing configured list of Windows capabilities";
    "Debloat.RemovePhantom"                        = "Removing phantom applications";
    "Debloat.RemoveEdge"                           = "Removing Microsoft Edge";
    "Debloat.RemoveEdge_ExtraTraces"               = "Removing extra traces of Microsoft Edge";
    "Debloat.RemoveStore"                          = "Removing Windows Store";
    "WindowsUpdate.DisableAutoUpdate"              = "Disabling automatic Windows updates";
    "WindowsUpdate.DisableAllUpdate"               = "Disabling Windows Update completely";
    "WindowsUpdate.AddUpdateToggleScriptToDesktop" = "Adding script to desktop to toggle Windows Update on/off";
    "Install.InstallGpEdit"                        = "Installing Group Policy Editor (gpedit.msc)";
    "Install.InstallHyperV"                        = "Installing Hyper-V";
    "Install.InstallWinget"                        = "Installing Winget package manager";
    "Install.InstallConfigured"                    = "Installing configured list of Winget packages";
    "Defender.ApplyRecommendedSecurityPolicies"    = "Applying recommended security policies";
    "Defender.ApplyStrictSecurityPolicies"         = "Applying strict security policies";
    "Defender.ApplyExtraStrictSecurityPolicies"    = "Applying extra strict security policies";
    "Defender.DefenderScanOnlyWhenIdle"            = "Configuring Defender to scan only when idle";
    "Defender.DefenderScanLowPriority"             = "Configuring Defender to run at low priority";
    "Defender.DisableRealtimeMonitoringCAUTION"    = "Disabling Defender realtime monitoring (requires Tamper Protection disabled)";
    "Defender.DisableAllDefenderCAUTIONCAUTION"    = "Disabling Defender entirely (requires Tamper protection disabled)";
    "Convenience.DisableStartupDelay"              = "Disabling application startup delay";
    "Convenience.ShowSecondsInTaskbar"             = "Showing seconds in taskbar";
    "Convenience.ShowRunAsDifferentUser"           = "Showing 'Run as different user' option in start menu";
    "Convenience.ShowHiddenExplorer"               = "Showing hidden files in Explorer";
	"Convenience.RemoveFileExplorerCruft"          = "Removing unwanted shortcuts from File Explorer";
    "Convenience.CleanupTaskbar"                   = "Cleaning up taskbar";
    "Convenience.ShowUacPromptOnSameDesktop"       = "Showing UAC on same desktop for elevation requests";
	"Convenience.DisableMonoAudio"                 = "Turning off mono audio";
    "Scans.CheckIntegrity"                         = "Running system file integrity checks";
    "Scans.CheckIRQ"                               = "Checking for IRQ conflicts"
}

function Get-SID() {
    return (New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([Security.Principal.SecurityIdentifier]).Value
}

$SID = Get-SID
"User SID: $SID"


### REGISTRY KEY DEFINITIONS ###
$RK_Uninst_Locs = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)
$RK_AppPath_Locs = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths"
)
$RK_AppxStores = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore"
)
$RK_AppxStores_Subkeys = @(
    "Applications", "Config", "DownlevelGather", "DownlevelInstalled", "InboxApplications", "$SID"
)


$global:DL_VCLibs = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
$global:DL_UIXaml = "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.7.3"
$global:DL_UIXaml_PathToAppx = "tools\AppX\x64\Release\Microsoft.UI.Xaml.2.7.appx"
$global:DL_Winget = "https://github.com/microsoft/winget-cli/releases/download/v1.4.11071/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
$global:DL_Winget_License = "https://github.com/microsoft/winget-cli/releases/download/v1.4.11071/5d9d44b170c146e1a3085c2c75fcc2c1_License1.xml"


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
$has_win_pro = ($edition -Like "*Pro*") -or ($edition -Like "*Enterprise*") -or ($edition -Like "*Education*")
$has_win_enterprise = ($edition -Like "*Enterprise*") -or ($edition -Like "*Education*")

"Windows Edition: $edition (pro=$has_win_pro) (enterprise=$has_win_enterprise)"
""

# Check if we have Winget already
$_winget = Get-Command winget -EA SilentlyContinue
$global:has_winget = $?
if ($global:has_winget) {
    $global:winget_cmd = $_winget.Source
}


### UTILITY FUNCTIONS ###

function PowerWashText ($Text) {
    if (-not $global:is_msert) {
        "$Text"
    }
}

function RegPut ($Path, $Key, $Value, $VType = "DWORD") {
    if ($null -eq $Path) {
        "ERROR: Null registry key passed"
        return
    }
    if (-NOT (Test-Path "$Path")) {
        New-Item -Path "$Path" -Force | Out-Null
    }
    New-ItemProperty -Path "$Path" -Name "$Key" -Value "$Value" -PropertyType "$VType" -Force | Out-Null
}

function RegGet($Path, $Key) {
    return (Get-ItemProperty -Path $Path -Name $Key).$Key
}

function TryRemoveItem($Path) {
	if (Test-Path $Path) {
		Remove-Item -Force $Path
	}
}

function RunScriptAsSystem($Path, $ArgString) {
    Write-Host "  [Invoking task as SYSTEM..." -NoNewline

    "$home" | Out-File -FilePath "$env:SystemDrive\.PowerWashHome.tmp" -Force -NoNewline
    Get-SID | Out-File -FilePath "$env:SystemDrive\.PowerWashSID.tmp" -Force -NoNewline

    # Adapted from https://github.com/mkellerm1n/Invoke-CommandAs/blob/master/Invoke-CommandAs/Private/Invoke-ScheduledTask.ps1
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "$Path $ArgString"
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Task = Register-ScheduledTask PowerWashSystemTask -Action $Action -Principal $Principal
    $Job = $Task | Start-ScheduledTask -AsJob -ErrorAction Stop
    $Job | Wait-Job | Remove-Job -Force -Confirm:$False
    While (($Task | Get-ScheduledtaskInfo).LastTaskResult -eq 267009) { Start-Sleep -Milliseconds 200 }
    $Task | Unregister-ScheduledTask -Confirm:$false
    Write-Host " Complete]"

    Remove-Item -Path "$env:SystemDrive\.PowerWashHome.tmp"
    Remove-Item -Path "$env:SystemDrive\.PowerWashSID.tmp"
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
    if ($global:is_msert) {
        return ($ConfigKey -eq "Debloat.RemoveEdge" -or $ConfigKey -eq "Debloat.RemoveEdge_ExtraTraces")
    }
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
    $AppItems = ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() `
        | Where-Object { $_.Name -eq $appname })
    if (-not $AppItems) {
        # That app does not exist or is not pinned to the taskbar
        return
    }
    $AppItems.Verbs() `
    | Where-Object { $_.Name.replace('&', '') -match 'Unpin from taskbar' } `
    | ForEach-Object { $_.DoIt() } 2>$null | Out-Null
}

function CreateShortcut($Dest, $Source, $Admin = $false) {
    # https://stackoverflow.com/questions/28997799/how-to-create-a-run-as-administrator-shortcut-using-powershell
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($Dest)
    $Shortcut.TargetPath = $Source
    $Shortcut.Save()

    if ($Admin) {
        $bytes = [System.IO.File]::ReadAllBytes("$Dest")
        $bytes[0x15] = $bytes[0x15] -bor 0x20  # set byte 21 (0x15) bit 6 (0x20) ON
        [System.IO.File]::WriteAllBytes("$Dest", $bytes)
    }
}

function SysDebugLog {
    param([Parameter(Mandatory, ValueFromPipeline)] $Msg)
    process {
        if ($global:is_debug) {
            $Msg | Out-File -FilePath $global:sys_account_debug_log -Append -Force
        }
        "$Msg"
    }
}

function PSFormatRegPath ($Path, $SID) {
    $result = "$Path".replace("HKEY_LOCAL_MACHINE", "HKLM:").replace("HKLM\", "HKLM:\").replace("HKCU\", "HKCU:\").replace("HKCU:", "HKEY_CURRENT_USER").replace("HKEY_CURRENT_USER", "HKEY_USERS\$SID")
    if ($result.contains("HKEY_") -and -not ($result.contains("Registry::"))) {
        $result = "Registry::$result"
    }
    return $result
}


function DownloadFile($Url, $DestFile) {
    $ProgressPreference = "SilentlyContinue"
    Invoke-WebRequest -Uri $Url -UseBasicParsing -OutFile $DestFile
}

function Install-Winget {
    # https://github.com/microsoft/winget-cli/issues/1861#issuecomment-1435349454
    Add-AppxPackage -Path $global:DL_VCLibs

    DownloadFile -Url $global:DL_UIXaml -DestFile ".\microsoft.ui.xaml.zip"
    Expand-Archive ".\microsoft.ui.xaml.zip"
    Add-AppxPackage ".\microsoft.ui.xaml\$global:DL_UIXaml_PathToAppx"

    "- Installing Winget..."
    $winget_msix = Split-Path -Leaf $global:DL_Winget
    $winget_lic = Split-Path -Leaf $global:DL_Winget_License
    DownloadFile -Url $global:DL_Winget -DestFile $winget_msix
    DownloadFile -Url $global:DL_Winget_License -DestFile $winget_lic

    Add-AppxProvisionedPackage -Online -PackagePath $winget_msix -LicensePath $winget_lic

    $global:has_winget = $true
    $global:winget_cmd = "$home\AppData\Local\Microsoft\WindowsApps\winget.exe"
}

function Add-Path($Path) {
    # https://poshcode.gitbook.io/powershell-faq/src/getting-started/environment-variables
    $Path = [Environment]::GetEnvironmentVariable("PATH", "Machine") + [IO.Path]::PathSeparator + $Path
    [Environment]::SetEnvironmentVariable("Path", $Path, "Machine")
}

# Must be running as SYSTEM to modify certain Defender settings (even then, will need Tamper Protection off manually for some of them to take effect)
# We have to bootstrap to this by scheduling a task to call this script with this flag

if ("/ElevatedAction" -in $args) {
    if ("/ForceAllowForDebug" -notin $args -and "$(whoami)" -ne "nt authority\system") {
        ""
        SysDebugLog "ERROR: Can only run /ElevatedAction features as SYSTEM. (Currently running as $(whoami))"
        ""
        exit
    }

    $UserHome = Get-Content "$env:SystemDrive\.PowerWashHome.tmp"
    $UserSID = Get-Content "$env:SystemDrive\.PowerWashSID.tmp"
    $HKCU = "Registry::HKEY_USERS\$UserSID"  # SYSTEM user's HKCU is not the script user's HKCU
    $HKCU_Classes = "$($HKCU)_Classes"
    Set-Location $UserHome
    SysDebugLog "ElevatedAction entering (we are $(whoami); user home = $UserHome, user sid = $UserSID, args = $args)"

    if ("/DisableRealtimeMonitoring" -in $args) {
        Set-MpPreference -DisableRealtimeMonitoring $true
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Key DisableBehaviorMonitoring -Value 1
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Key DisableRealtimeMonitoring -Value 1
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Key DisableOnAccessProtection -Value 1
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Key DisableScanOnRealtimeEnable -Value 1
        "Defender real-time monitoring disabled."
        if ("/DisableAllDefender" -in $args) {
            RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Key SpyNetReporting -Value 0
            RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Key SubmitSamplesConsent -Value 0
            RegPut "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Key DisableAntiSpyware -Value 1
            RegPut "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Key TamperProtection -Value 4
            RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Key DisableAntiSpyware -Value 1
            "Defender disabled."
        }
    }
    elseif ("/RemoveEdge" -in $args) {
        $aggressive = ("/Aggressive" -in $args)
        if ("/RegistryStage" -in $args) {
            $keys_to_remove = @(
                "HKLM:\SOFTWARE\WOW6432Node\Clients\StartMenuInternet\Microsoft Edge",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate",
                "HKLM:\SOFTWARE\Microsoft\Edge",
                "$HKCU\SOFTWARE\Microsoft\Edge",
                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineCore",
                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineUA"
            )
            $keys_to_remove_by_child = @(
                # Documented locations used to list installed applications
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "$HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                "$HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",

                "HKLM:\SOFTWARE\RegisteredApplications",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",

                "HKLM:\SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\SecurityManager\CapAuthz\ApplicationsEx",

                "HKLM:\SOFTWARE\Classes",
                "HKLM:\SOFTWARE\Classes\WOW6432Node",
                "HKLM:\SOFTWARE\WOW6432Node\Classes",
                "$HKCU_Classes\ActivatableClasses\Package",
                "$HKCU_Classes\Local Settings\MrtCache",
                "$HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData",

                "$HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
                "$HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView",

                "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Update\TargetingInfo\Installed",
                "$HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB",

                "HKLM:\SOFTWARE\Clients\StartMenuInternet",
                "HKLM:\SOFTWARE\Policies\Microsoft"
            )
            $entries_to_remove_by_key = @(
                "$HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "$HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
                "$HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
                "$HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
                "$HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
            )
            $entries_to_remove_by_val = @(
                "HKLM:\SOFTWARE\RegisteredApplications",
                "$HKCU\SOFTWARE\RegisteredApplications"
            )
            $app_model = @(
                "HKLM:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel",
                "$HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel"
            )
            $app_model_sub = @(
                "PackageRepository\Extensions\ProgIDs",
                "PackageRepository\Packages",
                "PolicyCache",
                "StateRepository"
                "Repository\Families",
                "Repository\Packages",
                "SystemAppData"
            )
            $amcache_paths = @(
                "Root\InventoryMiscellaneousUUPInfo",
                "Root\InventoryApplicationShortcut",
                "Root\InventoryApplicationFile"
            )

            SysDebugLog "keys_to_update"
            RegPut "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\MicrosoftEdge" -Key OSIntegrationLevel -Value 0
            RegPut "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\EdgeIntegration" -Key Supported -Value 0

            SysDebugLog "keys_to_remove"
            $keys_to_remove | ForEach-Object {
                $path = PSFormatRegPath -Path $_ -SID $SID
                if (-not (Test-Path $path)) {
                    SysDebugLog "- Skipping nonexistent path $_"
                }
                else {
                    SysDebugLog "- Reg remove: $path"
                    Remove-Item -Recurse -Force -Path "$path" | SysDebugLog
                }
            }

            SysDebugLog "keys_to_remove_by_child"
            $keys_to_remove_by_child | ForEach-Object {
                if (-not (Test-Path -Path $_)) {
                    SysDebugLog "- Skipping nonexistent path $_"
                }
                else {
                    Get-ChildItem -Path $_ | Where-Object { $_ -Like "*Microsoft*Edge*" } | ForEach-Object {
                        $path = PSFormatRegPath -Path $_ -SID $SID
                        SysDebugLog "- Reg remove: $path"
                        Remove-Item -Recurse -Force -Path $path | SysDebugLog
                    }
                }
            }

            SysDebugLog "entries_to_remove_by_key"
            $entries_to_remove_by_key | ForEach-Object {
                $path = $_
                if (-not (Test-Path -Path $path)) {
                    SysDebugLog "- Skipping nonexistent path $path"
                }
                else {
                    (Get-ItemProperty -Path $path).PSObject.Properties | Where-Object { $_.Name -Like "* Microsoft*Edge*" } | ForEach-Object {
                        SysDebugLog "- Reg remove: $path -> $($_.Name)"
                        Remove-ItemProperty -Force -Path $path -Name $_.Name | SysDebugLog
                    }
                }
            }

            SysDebugLog "entries_to_remove_by_val"
            $entries_to_remove_by_val | ForEach-Object {
                $path = $_
                if (-not (Test-Path -Path $path)) {
                    SysDebugLog "- Skipping nonexistent path $path"
                }
                else {
                    (Get-ItemProperty -Path $path).PSObject.Properties | Where-Object { $_.Value -Like "*Microsoft*Edge*" } | ForEach-Object {
                        SysDebugLog "- Reg remove: $path -> $($_.Name)"
                        Remove-ItemProperty -Force -Path $path -Name $_.Name | SysDebugLog
                    }
                }
            }

            SysDebugLog "rk_uninst_locs"
            $RK_Uninst_Locs | ForEach-Object {
                $root = $_
                Get-ChildItem -Path $root | ForEach-Object {
                    $path = PSFormatRegPath -Path $_ -SID $SID
                    $name = (Get-ItemProperty -Path $path -Name "DisplayName" -EA SilentlyContinue).DisplayName
                    if ($name -like "*Microsoft*Edge*") {
                        SysDebugLog "- Reg remove: $path ($name)"
                        Remove-Item -Recurse -Force -Path $path | SysDebugLog
                    }
                }
            }
            
            if ($Aggressive) {
                SysDebugLog "app_model"
                $app_model | ForEach-Object {
                    $root = $_
                    $app_model_sub | ForEach-Object {
                        $sub = "$root\$_"
                        if (-not (Test-Path -Path $sub)) {
                            SysDebugLog "- Skipping nonexistent path $sub"
                        }
                        else {
                            Get-ChildItem -Path $sub | Where-Object { $_ -Like "*Microsoft*Edge*" } | ForEach-Object { 
                                $path = PSFormatRegPath -Path $_ -SID $SID
                                SysDebugLog "- Reg remove: $path"
                                Remove-Item -Recurse -Force -Path $path | SysDebugLog
                            }
                        }
                    }
                }
                
                SysDebugLog "appx_stores"
                $RK_AppxStores | ForEach-Object {
                    $root = $_
                    $RK_AppxStores_Subkeys | ForEach-Object {
                        $sub = "$root\$_"
                        Get-ChildItem -Path $sub -EA SilentlyContinue | ForEach-Object {
                            $path = PSFormatRegPath -Path $_ -SID $SID
                            if ($path -like "*Microsoft*Edge*") {
                                SysDebugLog "- Reg remove: $path"
                                Remove-Item -Recurse -Force -Path $path | SysDebugLog
                            }
                        }
                    }
                }

                SysDebugLog "amcache"
                $amcache_online = "$env:SystemDrive\WINDOWS\AppCompat\Programs\Amcache.hve"
                $amcache_offline = "$env:SystemDrive\WINDOWS\AppCompat\Programs\AmcacheOffline.hve"
                $amcache_offline_mod = "$env:SystemDrive\WINDOWS\AppCompat\Programs\AmcacheOfflineMod.hve"
                $amcache_offline_bak = "$env:SystemDrive\WINDOWS\AppCompat\Programs\AmcacheOffline.hve.bak"
                $amcache_offline_mount = "HKLM\amcacheoffline"
                $amcache_success = $true
                try {
                    try {
                        $amcache_online_handle = [System.io.File]::Open($amcache_online, "Open", "ReadWrite", "None")
                        ">amcache online lock success"
                    }
                    catch {
                        "- Could not open amcache online file, it is probably already in use"
                        $_ | Format-List * -Force | Out-String | SysDebugLog
                        $_.InvocationInfo | Format-List * -Force | Out-String | SysDebugLog
                    }
                    $amcache_offline_handle = [System.io.File]::Open($amcache_offline, "OpenOrCreate", "ReadWrite", "None")
                    $amcache_online_handle.CopyTo($amcache_offline_handle)
                    $amcache_offline_handle.Close()
                    SysDebugLog ">amcache offline copy success"
                    
                    Copy-Item -Path $amcache_offline -Dest $amcache_offline_bak -Force
                    SysDebugLog ">If anything goes wrong, Amcache backup is at $amcache_offline_bak"

                    reg.exe load $amcache_offline_mount $amcache_offline
                    SysDebugLog ">amcache mount offline copy success"

                    $amcache_paths | ForEach-Object {
                        $root = "$amcache_offline_mount\$_"
                        $path = PSFormatRegPath -Path $root -SID $UserSID
                        Get-ChildItem -Path $path | Where-Object { "$_" -like "*Microsoft*Edge*" -or "$_" -like "*MSEdge*" } | ForEach-Object {
                            SysDebugLog "- Reg remove: $_"
                            Remove-Item -Recurse -Force -Path (PSFormatRegPath -Path $_ -SID $UserSID)
                        }
                    }
                    SysDebugLog ">amcache mount purge edge success"
                    
                    reg.exe save $amcache_offline_mount $amcache_offline_mod /y
                    SysDebugLog ">amcache save offline copy success"

                    reg.exe unload $amcache_offline_mount
                    SysDebugLog ">amcache unmount offline copy success"

                    try {
                        $amcache_online_handle.SetLength(0)
                        $amcache_offline_mod_handle = [System.IO.File]::Open($amcache_offline_mod, "OpenOrCreate", "ReadWrite", "None")
                        $amcache_offline_mod_handle.CopyTo($amcache_online_handle)

                        SysDebugLog ">amcache bring changes online and unlock success"
                    }
                    catch {
                        SysDebugLog "- Failed to bring modifications back online"
                        $_ | Format-List * -Force | Out-String | SysDebugLog
                        $_.InvocationInfo | Format-List * -Force | Out-String | SysDebugLog
                        $amcache_success = $false
                    }
                    finally {
                        $amcache_offline_mod_handle.Close()
                        $amcache_online_handle.Close()
                    }

                    if ($amcache_success) {
                        Remove-Item -Path $amcache_offline -Force
                        Remove-Item -Path $amcache_offline_mod -Force
                        Remove-Item -Path $amcache_offline_bak -Force
                        SysDebugLog ">amcache cleanup offline copy success"
                    }
                    else {
                        SysDebugLog ">amcache cleanup skipped because errors occurred"
                    }
                }
                catch {
                    SysDebugLog "- Could not remove from Amcache, probably in use by another process"
                    $_ | Format-List * -Force | Out-String | SysDebugLog
                    $_.InvocationInfo | Format-List * -Force | Out-String | SysDebugLog
                    $amcache_success = $false
                }

                if ($amcache_success) {
                    "Success" | Out-File "$env:SystemDrive\.PowerWashAmcacheStatus.tmp" -NoNewline
                }
                else {
                    "Failure" | Out-File "$env:SystemDrive\.PowerWashAmcacheStatus.tmp" -NoNewline
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
                "$env:SystemDrive\ProgramData\Packages",
                "$env:SystemDrive\Windows\SystemApps",
                "$env:SystemDrive\Program Files\WindowsApps",
                "$env:SystemDrive\ProgramData\Microsoft\Windows\AppRepository",
                "$env:SystemDrive\ProgramData\Microsoft\Windows\Start Menu\Programs",
                "$UserHome\Desktop",
                "$UserHome\AppData\Local",
                "$userHome\AppData\Local\Microsoft",
                "$UserHome\AppData\Local\Packages",
                "$UserHome\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch",
                "$env:SystemDrive\Windows\Prefetch",
                "$env:SystemDrive\ProgramData\Microsoft"
            )
            $folders_to_remove_by_subfolder_aggressive = @(
                "$env:SystemDrive\Program Files (x86)\Microsoft"
            )

            SysDebugLog "folders_to_remove"
            $folders_to_remove | ForEach-Object {
                if (-not (Test-Path -Path $_)) {
                    SysDebugLog "- Skipping nonexistent path $_"
                }
                else {
                    SysDebugLog "- File remove: $_"
                    Remove-Item -Recurse -Force -Path $_ | SysDebugLog
                }
            }

            SysDebugLog "folders_to_remove_by_subfolder"
            $folders_to_remove_by_subfolder | ForEach-Object {
                $path = $_
                if (-not (Test-Path -Path $path)) {
                    SysDebugLog "- Skipping nonexistent path $path"
                }
                else {
                    Get-ChildItem -Path $_ | Where-Object { $_ -Like "*Microsoft*Edge*" } | ForEach-Object {
                        "- File remove: $path\$_" | SysDebugLog
                        Remove-Item -Recurse -Force -Path "$path\$_" | SysDebugLog
                    }
                }
            }

            SysDebugLog "folders_to_remove_by_subfolder_aggressive"
            $folders_to_remove_by_subfolder_aggressive | ForEach-Object {
                $path = $_
                if (-not (Test-Path -Path $path)) {
                    SysDebugLog "- Skipping nonexistent path $path"
                }
                else {
                    Get-ChildItem -Path $_ | Where-Object { $_ -Like "*Edge*" } | ForEach-Object {
                        SysDebugLog "- File remove: $path\$_"
                        Remove-Item -Recurse -Force -Path "$path\$_" | SysDebugLog
                    }
                }
            }

            SysDebugLog "remove implicit app shortcuts"
            $implicit_app_shortcuts = "$UserHome\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\ImplicitAppShortcuts"
            if (Test-Path -Path $implicit_app_shortcuts) {
                Get-ChildItem -Path $implicit_app_shortcuts | ForEach-Object {
                    $path = "$implicit_app_shortcuts\$_"
                    Get-ChildItem -Path $path | Where-Object { $_ -Like "*Edge*" } | ForEach-Object {
                        SysDebugLog "- File remove: $path"
                        Remove-Item -Recurse -Force -Path "$path" | SysDebugLog
                    }
                }
            }
        }
    }
    elseif ("/ApplySecurityPolicy" -in $args) {
        # Sources:
        # https://admx.help
        # https://public.cyber.mil/stigs
        # https://www.windows-security.org
        # https://stigviewer.com
        # https://learn.microsoft.com
        # https://security.microsoft.com
        # https://github.com/nsacyber/Windows-Secure-Host-Baseline/blob/master/Windows/Compliance/Windows10.audit
        
        # Source abbreviations:
        # MDE -- Microsoft Defender for Endpoint -- attributions still in progress
        # MSS -- Microsoft MSS registry settings
        # MSSB -- MS Security Baseline Windows 10 v21H1
        # SHB -- Secure Host Baseline (from NSA)
        # STIG -- Security Technical Implementation Guideline (from DISA)
        
        $strict = ("/StrictMode" -in $args)
        $draconian = ("/DraconianMode" -in $args)
        SysDebugLog "Strict mode: $strict"

        
        ###### HARDWARE LEVEL SECURITY SETTINGS ######
        SysDebugLog "Applying hardware-level security settings..."

        # Firmware protection
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard -Key Enabled -Value 1
        
        # Secure biometrics (Enhanced sign-on security)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SecureBiometrics -Key Enabled -Value 1
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SecureFingerprint -Key Enabled -Value 1
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures -Key EnhancedAntiSpoofing -Value 1  # (~SHB)

        # Hypervisor enforced code integrity (HVCI)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity -Key Enabled -Value 1
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity -Key Locked -Value 0
        
        # Device Guard -- enable virtualization-based security (~MSSB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Key EnableVirtualizationBasedSecurity -Value 1
        
        # Device Guard -- use both Secure Boot and DMA protection (~MSSB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Key RequirePlatformSecurityFeatures -Value 3
        
        # Device Guard -- Virtualization-based Protection of Code Integrity (~MSSB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Key HypervisorEnforcedCodeIntegrity -Value 1
        
        # Device Guard -- Require UEFI Memory Attributes Table (~MSSB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Key HVCIMatRequired -Value 1
        
        # Device Guard -- Credential Guard (~MSSB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Key LsaCfgFlags -Value 1
        
        # Device Guard -- Secure Launch (~MSSB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Key ConfigureSystemGuardLaunch -Value 1


        ###### SYSTEM SECURITY SETTINGS ######
        SysDebugLog "Applying system-level process mitigations..."
        
        # No-Execute should be set to OptOut or (stricter, may break things) AlwaysOn
        if ($draconian) {
            cmd /c "bcdedit /set {current} nx AlwaysOn"
        }
        else {
            cmd /c "bcdedit /set {current} nx OptOut"
        }
        
        # Process mitigations that are less likely to break normal functionality
        Set-ProcessMitigation -System -Force on -Enable DEP, EmulateAtlThunks, BottomUp, HighEntropy, DisableExtensionPoints, CFG, SuppressExports, BlockRemoteImageLoads, SEHOP
        
        # Structured Exception Handling Overwrite PRotection (SEHOP) (~MSSB, SHB)
        RegPut "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" -Key DisableExceptionChainValidation -Value 0
        
        if ($strict) {
            # Process mitigations that could break normal functionality (esp. with third party AV)
            Set-ProcessMitigation -System -Force on -Enable EnforceModuleDependencySigning, StrictHandle, StrictCFG, UserShadowStack, UserShadowStackStrictMode
           
            # Enable untrusted font blocking (~SHB)
            RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions" -Key MitigationOptions_FontBocking -Value "1000000000000" -VType String  # sic
            RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions" -Key MitigationOptions_FontBlocking -Value "1000000000000" -VType String
        }
        if ($draconian) {
            # Very likely to break some normal functionality; this will have to be evaluated on a case-by-case basis
            # to determine if the marginal increase in security is worth it.
            Set-ProcessMitigation -System -Force on -Enable TerminateOnError, DisableNonSystemFonts, DisableWin32kSystemCalls
        }
        
        if ($strict) {
            # Disable "Turn off data execution prevention for Explorer" (~SHB, STIG)
            RegPut HKLM:\Software\Policies\Microsoft\Windows\Explorer -Key NoDataExecutionPrevention -Value 0
        
            # Disable "Turn off Heap termination on corruption" (~SHB, STIG)
            RegPut HKLM:\Software\Policies\Microsoft\Windows\Explorer -Key NoHeapTerminationOnCorruption -Value 0
        }
        
        if ($draconian) {
            # Disable "MSS: (AutoReboot) Allow Windows to automatically restart after a system crash (recommended except for highly secure environments)"
            RegPut HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Key AutoReboot -Value 0
        }
		
		# Enable Local Security Authority (LSA) protection (~MDE)
		RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Key RunAsPPL -Value 1
        
        # Disable new DMA devices when this computer is locked (~MSSB)
        RegPut HKLM:\Software\Policies\Microsoft\FVE -Key DisableExternalDMAUnderLock -Value 1
        
        # MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)
        RegPut "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Key SafeDllSearchMode -Value 1
        
        # Turn off downloading of print drivers over HTTP (~MSSB, SHB, STIG)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Key DisableWebPnPDownload -Value 1
        
        # Turn off printing over HTTP (~SHB, STIG)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Key DisableHTTPPrinting -Value 1
        
        # Limit print driver installation to administrators (~MSSB)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Key RestrictDriverInstallationToAdministrators -Value 1
        
        # Disable Delivery Optimization (~SHB)
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization -Key DODownloadMode -Value 0

        # Set machine inactivity limit to 15 mins (~SHB)
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Key InactivityTimeoutSecs -Value 900
        
        # Require case insensitivity for non-Windows subsystems when dealing with arguments or commands (~SHB)
        RegPut "HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel" -Key ObCaseInsensitive -Value 1
        
        # System objects: Strengthen default permissions of internal system objects (~SHB, STIG)
        RegPut "HKLM:\System\CurrentControlSet\Control\Session Manager" -Key ProtectionMode -Value 1
        
        # MSS: (NoNameReleaseOnDemand) Allow computer to ignore NetBIOS name release requests except from WINS servers (~MSS, SHB, STIG)
        RegPut HKLM:\System\CurrentControlSet\Services\Netbt\Parameters -Key NoNameReleaseOnDemand -Value 1

        # Set "MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning" to 90%
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security -Key WarningLevel -Value 90
        
        # Specify the maximum log file size (KB) (~MSSB, STIG)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application -Key MaxSize -Value 32768
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security -Key MaxSize -Value 196608
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System -Key MaxSize -Value 32768
        
        # Blacklist certain drivers (~MSSB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions -Key DenyDeviceClasses -Value 1
        RegPut HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions -Key DenyDeviceClassesRetroactive -Value 1
        RegPut HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses -Key 1 -Value "{d48179be-ec20-11d1-b6b8-00c04fa372a7}" -VType String

        # Boot-Start Driver Initialization Policy (~MSSB, SHB)
        if ($draconian) {
            # Good and unknown
            RegPut HKLM:\System\CurrentControlSet\Policies\EarlyLaunch -Key DriverLoadPolicy -Value 1
        }
        else {
            # Good, unknown and bad but critical
            RegPut HKLM:\System\CurrentControlSet\Policies\EarlyLaunch -Key DriverLoadPolicy -Value 3
        }
        
        # Set "Enumeration policy for external devices incompatible with Kernel DMA Protection" to "Block all" (~MSSB)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection" -Key DeviceEnumerationPolicy -Value 0
        
        # Set cloud protection level (~MSSB)
        if ($draconian) {
            # Enabled: High+ blocking level
            RegPut "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine" -Key MpCloudBlockLevel -Value 4
        }
        else {
            # Enabled: High blocking level
            RegPut "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine" -Key MpCloudBlockLevel -Value 2
        }
        
        # Scan all downloaded files and attachments (~MSSB)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Key DisableIOAVProtection -Value 0
        
        # Disable "Turn off real-time protection" (~MSSB)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Key DisableRealtimeMonitoring -Value 0
        
        # Turn on behavior monitoring (~MSSB)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Key DisableBehaviorMonitoring -Value 0

        # Turn off Program Inventory (~SHB, STIG)
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat -Key DisableInventory -Value 1
        
        # Attempt device authentication using certificates (~SHB)
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters -Key DevicePKInitEnabled -Value 1
    
        # Disable Windows Telemetry to the extent possible (~SHB)
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Key AllowTelemetry -Value 0
    
    
        ###### DRIVE AND FILESYSTEM SECURITY SETTINGS ######
        SysDebugLog "Applying drive and filesystem security settings..."

        # Scan removable drives
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Key DisableRemovableDriveScanning -Value 0
        
        # Turn off autoplay for non-volume devices (~MSSB, SHB, STIG, MDE)
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Key NoAutoplayfornonVolume -Value 1
        
        # Prevent autorun commands (~MSSB, SHB, STIG, MDE)
        RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Key NoAutorun -Value 1
        
        # Disable autorun for all drive types (~MSSB, SHB, STIG, MDE)
        RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Key NoDriveTypeAutoRun -Value 255
        
        # (Legacy) Run Windows Server 2019 File Explorer shell protocol in protected mode (~SHB)
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Key PreXPSP2ShellProtocolBehavior -Value 0
        
        # Disable indexing of encrypted files (~MSSB, SHB, STIG)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Key AllowIndexingEncryptedStoresOrItems -Value 0

        if ($strict) {
            # MSS: (NtfsDisable8dot3NameCreation) Enable the computer to stop generating 8.3 style filenames
            RegPut HKLM:\System\CurrentControlSet\Control\FileSystem -Key NtfsDisable8dot3NameCreation -Value 1
        }

        # Typically too annoying relative to likely benefits (try in Audit mode instead?)
        if ($draconian) {
            RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Key EnableControlledFolderAccess -Value 1
        }
        elseif ($strict) {
            # Notify when apps make changes to files in protected folders
            RegPut "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Key EnableControlledFolderAccess -Value 2
        }
        
        # Turn off Internet download for Web publishing and online ordering wizards (~MSSB, SHB, STIG)
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Key NoWebServices -Value 1
        
        # Allow users to configure advanced startup options in BitLocker setup
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\FVE -Key UseAdvancedStartup -Value 1
        
        if ($false -and $draconian) {
            # Deny write access to removable drives not protected by BitLocker (~MSSB)
            RegPut HKLM:\Software\Policies\Microsoft\FVE -Key RDVDenyCrossOrg -Value 1
            RegPut HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE -Key RDVDenyWriteAccess -Value 1
        }
        
        # Include command line data in process creation events (~SHB)
        RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Key ProcessCreationIncludeCmdLine_Enabled -Value 1
        

        ###### AUTHENTICATION SECURITY SETTINGS ######
        SysDebugLog "Applying authentication security settings..."

        # Disable "MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)" (~MSS, SHB)
        RegPut "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Key AutoAdminLogon -Value 0

        # Prevent automatic logon to the system through the Recovery Console (~SHB)
        RegPut "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" -Key SecurityLevel -Value 0

        # Minimum PIN length
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\FVE -Key MinimumPIN -Value 6
        
        # TMP-based lockout settings (~SHB, STIG)
        RegPut HKLM:\Software\Policies\Microsoft\Tpm -Key StandardUserAuthorizationFailureIndividualThreshold -Value 4
        RegPut HKLM:\Software\Policies\Microsoft\Tpm -Key StandardUserAuthorizationFailureTotalThreshold -Value 10
        RegPut HKLM:\Software\Policies\Microsoft\Tpm -Key StandardUserAuthorizationFailureDuration -Value 900
        
        # Prevent enabling lock screen camera, slide show (~MSSB, SHB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\Personalization -Key NoLockScreenCamera -Value 1
        RegPut HKLM:\Software\Policies\Microsoft\Windows\Personalization -Key NoLockScreenSlideShow -Value 1
        
        # Enable local admin password management (~MSSB, MDE)
        RegPut "HKLM:\Software\Policies\Microsoft Services\AdmPwd" -Key AdmPwdEnabled -Value 1
        
        # Disable WDigest Authentication (stores plaintext passwords in memory) (~MSSB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -Key UseLogonCredential -Value 0
        
        # Windows Hello for Business (~SHB)
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork -Key RequireSecurityDevice -Value 1
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity -Key MinimumPINLength -Value 6
        
        if ($strict) {
            # Automatically deny elevation requests from standard users (~SHB)
            RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Key ConsentPromptBehaviorUser -Value 0
        }
        else {
            # Require standard users to enter a valid admin username/password to allow elevation
            RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Key ConsentPromptBehaviorUser -Value 1
        }

        # Behavior of the elevation prompt for administrators in Admin Approval Mode (~STIG)
        # Admins don't need to enter credentials to allow elevation, but are still prompted to allow or deny.
        if ($strict) {
            # Also use secure desktop (~SHB)
            RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Key ConsentPromptBehaviorAdmin -Value 2
        }
        else {
            RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Key ConsentPromptBehaviorAdmin -Value 4
        }
        
        # Require a password when a computer wakes (~MSSB, SHB, STIG)
        RegPut HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 -Key ACSettingIndex -Value 1
        RegPut HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 -Key DCSettingIndex -Value 1

        # Disable "Allow standby states (S1-S3) when sleeping" (~MSSB)
        RegPut HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab -Key ACSettingIndex -Value 0
        RegPut HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab -Key DCSettingIndex -Value 0
        
        # Disable "Enumerate administrator accounts on elevation" (~SHB, STIG)
        RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI -Key EnumerateAdministrators -Value 0
        
        # Disable "Enumerate local users on domain-joined computers" (~MSSB, SHB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\System -Key EnumerateLocalUsers -Value 0
        
        # Disable "Turn on convenience PIN sign-in" (applies only to domain users) (~MSSB, SHB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\System -Key AllowDomainPINLogon -Value 0

        # Prevent elevated privileges from being used over the network on domain systems. (~SHB)
        RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Key LocalAccountTokenFilterPolicy -Value 0
        
        # Don't automatically sign in last interactive user after a restart (~MSSB, SHB)
        RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Key DisableAutomaticRestartSignOn -Value 1
        
        # User Account Control: Admin Approval Mode for the Built-in Administrator account (~SHB, STIG)
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Key FilterAdministratorToken -Value 1
        
        # User Account Control: Detect application installations and prompt for elevation (~SHB, STIG)
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Key EnableInstallerDetection -Value 1
        
        # User Account Control: Only elevate UIAccess applications that are installed in secure locations (~SHB, STIG)
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Key EnableSecureUIAPaths -Value 1
        
        # Run all administrators in Admin Approval Mode (~SHB, STIG)
        # UAC will notify the user when programs try to make changes to the computer
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Key EnableLUA -Value 1
        
        # Virtualize file and registry write failures to per-user locations (~SHB, STIG)
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Key EnableVirtualization -Value 1

        if ($strict) {
            # Show the prompt to run an application as administrator on a separate desktop, rather than overlaid on the current desktop
            RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Key PromptOnSecureDesktop -Value 1
        }
        
        # Hide usernames from login screen
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Key DontDisplayLastUserName -Value 1
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Key DontDisplayLockedUserId -Value 3
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Key DontDisplayUserName -Value 1
        
        if ($strict) {
            # Require Ctrl+Alt+Del to unlock (prevents username/password interception)
            RegPut "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Key DisableCAD -Value 0
        }
        
        # Prevent Kerberos from using DES and RC4 encryption suites (~SHB, STIG)
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters -Key SupportedEncryptionTypes -Value 2147483640
        
        # Require user authentication for remote connections by using Network Level Authentication
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key UserAuthentication -Value 1
        
        # Restrict local accounts with blank passwords from accessing the network (~SHB)
        RegPut HKLM:\System\CurrentControlSet\Lsa -Key LimitBlankPasswordUse -Value 1
        
        # Enable Windows Defender Credential Guard with UEFI lock
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Key LsaCfgFlags -Value 1
        
        # Prevent local storage of domain credentials (~SHB, MDE)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Key DisableDomainCreds -Value 1
        
        # Network access: Do not allow anonymous enumeration of SAM accounts (~SHB, STIG)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Key RestrictAnonymousSAM -Value 1
        
        # Network access: Do not allow anonymous enumeration of SAM accounts and shares (~SHB, STIG, MDE)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Key RestrictAnonymous -Value 1
        
        # Computer Identity Authentication for NTLM (~SHB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Key UseMachineId -Value 1
        
        # Network access: Restrict clients allowed to make remote calls to SAM (~SHB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Key RestrictRemoteSAM -Value "O:BAG:BAD:(A;;RC;;;BA)" -VType String
        
        # Set "Network access: Sharing and security model for local accounts" to "Classic - local users authenticate as themselves" (~SHB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Key ForceGuest -Value 0
        
        # Disable "Network access: Let everyone permissions apply to anonymous users" (~SHB, STIG)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Key EveryoneIncludesAnonymous -Value 0
        
        # Enable LSA protection using a UEFI variable
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Key RunAsPPL -Value 1
        
        # Network security: Do not store LAN Manager hash value on next password change (~SHB, STIG)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Key NoLMHash -Value 1
        
        # Set "Network Security: LAN Manager Authentication Level" to send NTLMv2 response only, and refuse LM and NTLM (~SHB, STIG, MDE)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Key LmCompatibilityLevel -Value 5
        
        # NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access. (~SHB, STIG)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 -Key allownullsessionfallback -Value 0
        
        # Network security: Minimum session security for NTLM SSP based (including secure RPC) (~SHB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 -Key NTLMMinClientSec -Value 537395200
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 -Key NTLMMinServerSec -Value 537395200
        
        # Network Security: Allow PKU2U authentication requests to this computer to use online identities (~SHB, STIG)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u -Key AllowOnlineID -Value 0
        
        # System Cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing (~SHB, STIG)
        RegPut HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy -Key Enabled -Value 1

        # Set "Network Security: LDAP client signing requirements" to "Negotiate signing" (~SHB, STIG)
        RegPut HKLM:\System\CurrentControlSet\Services\LDAP -Key LDAPClientIntegrity -Value 1

        # MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)
        RegPut "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Key ScreenSaverGracePeriod -Value 0

        ### Remote Desktop Services ###
        
        # Do not allow passwords to be saved (~MSSB, SHB, STIG)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Key DisablePasswordSaving -Value 1
        
        # Always prompt for password upon connection (~MSSB, SHB, STIG)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Key fPromptForPassword -Value 1
        
        # Require secure RPC communication (~MSSB, SHB)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Key fEncryptRPCTraffic -Value 1
        
        # Do not allow drive redirection (~MSSB, SHB, STIG)
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key fDisableCdm -Value 1
        
        # Set "Restrictions for Unauthenticated RPC clients" to "Authenticated" (~MSSB, SHB, STIG)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Key RestrictRemoteClients -Value 1
        
        # Set client connection encryption level to High Level (~MSSB, SHB, STIG)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Key MinEncryptionLevel -Value 3
        
        # Disable Solicited Remote Assistance (~MSSB, STIG)
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key fAllowToGetHelp -Value 0  # (~SHB, MDE too)
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key fAllowFullControl -Value 0
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key fUseMailto -Value 0
        
        # Domain member: Digitally encrypt or sign secure channel data (always) (~SHB, STIG)
        RegPut HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters -Key RequireSignOrSeal -Value 1
        
        # Domain member: Digitally encrypt secure channel data (when possible) (~SHB, STIG)
        RegPut HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters -Key SealSecureChannel -Value 1
        RegPut HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters -Key SignSecureChannel -Value 1
        
        # Allow account passwords to be reset (~SHB)
        RegPut HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters -Key DisablePasswordChange -Value 0
        
        # Require Strong Session Key (when connecting to a domain controller) (~SHB, STIG)
        RegPut HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters -Key RequireStrongKey -Value 1
        
        if ($strict) {
            # Maximum password age (~SHB)
            RegPut HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters -Key MaximumPasswordAge -Value 30
            
            # Number of domain credentials that can be cached (~SHB)
            RegPut "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Key cachedlogonscount -Value 1
        }
        else {
            # Number of domain credentials that can be cached
            RegPut "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Key cachedlogonscount -Value 10
        }
        
        # Do not require Domain Controller authentication to unlock the workstation (~SHB)
        RegPut "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Key ForceUnlockLogon -Value 0
        
        if ($strict) {
            # Disable built-in Guest and Administrator accounts (easy targets for entry into system) (~STIG)
            Disable-LocalUser -Name Guest -EA SilentlyContinue
            Disable-LocalUser -Name Administrator -EA SilentlyContinue
        }
        
        # Set "Let Windows apps activate with voice while the system is locked" to "Force Deny" (~MSSB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy -Key LetAppsActivateWithVoiceAboveLock -Value 2
        
        # Allow Microsoft accounts to be optional (~MSSB, SHB)
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Key MSAOptional -Value 1
        
        # Allow enhanced PINs for startup (~MSSB)
        RegPut HKLM:\Software\Policies\Microsoft\FVE -Key UseEnhancedPin -Value 1
        

        ###### ATTACK SURFACE REDUCTION ######
        SysDebugLog "Applying Attack Surface Reduction settings..."
        RegPut "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Key ExploitGuard_ASR_Rules -Value 1
        # https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#asr-rule-to-guid-matrix
        $asr_guids_block = @(
            "26190899-1602-49e8-8b27-eb1d0a1ce869", # Block Office communication application from creating child processes
            "3b576869-a4ec-4529-8536-b80a7769e899", # Block Office applications from creating executable content
            "56a863a9-875e-4185-98a7-b882c64b5ce5", # Block abuse of exploited vulnerable signed drivers
            "5beb7efe-fd9a-4556-801d-275e5ffc04cc", # Block execution of potentially obfuscated scripts
            "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", # Block Office applications from injecting code into other processes
            "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", # Block Adobe Reader from creating child processes
            "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", # Block Win32 API calls from Office macros
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", # Block untrusted and unsigned processes that run from USB
            "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", # Block executable content from email client and webmail
            "c1db55ab-c21a-4637-bb3f-a12568109d35", # Use advanced protection against ransomware
            "d3e037e1-3eb8-44c8-a917-57927947596d", # Block JavaScript or VBScript from launching downloaded executable content
            "e6db77e5-3df2-4cf1-b95a-636979351e5b"  # Block persistence through WMI event subscription
        )
        $asr_guids_warn = @(
        )
        if ($draconian) {
            $asr_guids_block += @(
                "01443614-cd74-433a-b99e-2ecdc07bfc25", # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
                "d1e49aac-8f56-4280-b9ba-993a6d77406c", # Block process creations originating from PSExec and WMI commands
                "d4f940ab-401b-4efc-aadc-ad5f3c50688a"  # Block all Office applications from creating child processes
            )
        }
        elseif ($strict) {
            $asr_guids_block += @(
                "d4f940ab-401b-4efc-aadc-ad5f3c50688a"  # Block all Office applications from creating child processes
            )
            $asr_guids_warn += @(
                "01443614-cd74-433a-b99e-2ecdc07bfc25", # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
                "d1e49aac-8f56-4280-b9ba-993a6d77406c"  # Block process creations originating from PSExec and WMI commands
            
            )
        }
        else {
            $asr_guids_warn += @(
                "01443614-cd74-433a-b99e-2ecdc07bfc25", # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
                "d1e49aac-8f56-4280-b9ba-993a6d77406c", # Block process creations originating from PSExec and WMI commands
                "d4f940ab-401b-4efc-aadc-ad5f3c50688a"  # Block all Office applications from creating child processes
            )
        }
        $asr_guids_block | ForEach-Object {
            RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Key "$_" -Value 1 -VType String
        }
        $asr_guids_warn | ForEach-Object {
            RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Key "$_" -Value 6 -VType String
        }
        
        
        ###### NETWORK SECURITY SETTINGS ######
        SysDebugLog "Applying network security settings..."

        # Do not display network selection UI on logon screen (~SHB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\System -Key DontDisplayNetworkSelectionUI -Value 1

        # Microsoft network client: Digitally sign communications (always) (~SHB, STIG)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Key RequireSecuritySignature -Value 1 # (~MDE too)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Key EnableSecuritySignature -Value 1
        
        # Disable "Microsoft network client: Send unencrypted password to third-party SMB servers" (~SHB, STIG)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Key EnablePlainTextPassword -Value 0
        
        # Set "MSS: (SynAttackProtect) Syn attack protection level (protects against DoS)" to "Connections time out sooner if a SYN attack is detected" (~MSS)
        RegPut HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Key SynAttackProtect -Value 1
        
        # Set "MSS: (TcpMaxConnectResponseRetransmissions) SYN-ACK retransmissions when a connection request is not acknowledged" to "3 & 6 seconds, half-open connections dropped after 21 seconds" (~MSS)
        RegPut HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Key TcpMaxConnectResponseRetransmissions -Value 2
        
        # Set "MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" to 3 (~MSS)
        RegPut HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Key TcpMaxDataRetransmissions -Value 3
        RegPut HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters -Key TcpMaxDataRetransmissions -Value 3
        
        if ($draconian) {
            # Disable "MSS: Enable Administrative Shares (recommended except for highly secure environments)" (~MSS)
            RegPut HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters -Key AutoShareServer -Value 0
            RegPut HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters -Key AutoShareWks -Value 0
        }
        
        # Idle timeout before suspending an SMB session (~SHB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Key AutoDisconnect -Value 15
        
        # Disable SMB v1 client driver (~MSSB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10 -Key Start -Value 4
        
        # Disable server-side processing pf SMBv1 protocol (~MSSB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Key SMB1 -Value 0
        
        # Disable insecure guest logons to an SMB server (~MSSB, SHB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation -Key AllowInsecureGuestAuth -Value 0
        
        # Hardened UNC paths (~MSSB, SHB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths -Key "\\*\NETLOGON" -Value "RequireMutualAuthentication=1,RequireIntegrity=1" -VType String
        RegPut HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths -Key "\\*\SYSVOL" -Value "RequireMutualAuthentication=1,RequireIntegrity=1" -VType String
        
        # Microsoft network server: Digitally sign communications (always) (~SHB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Key RequireSecuritySignature -Value 1
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Key EnableSecuritySignature -Value 1
        
        # Microsoft network server: Disconnect clients when logon hours expire (~SHB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Key EnableForcedLogoff -Value 1
        
        # Disable "Microsoft network server: Server SPN target name validation level" (it can be disruptive) (~SHB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Key SmbServerNameHardeningLevel -Value 0
        
        # Network access: Restrict anonymous access to Named Pipes and Shares (~SHB, STIG)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Key RestrictNullSessAccess -Value 1
        
        # MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing) (~MSS, SHB, STIG, MDE)
        # Set to "Highest protection, source routing is completely disabled"
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Key DisableIPSourceRouting -Value 2
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters -Key DisableIPSourceRouting -Value 2
        
        # MSS: (DisableSavePassword) Prevent the dial-up passsword from being saved (recommended)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters -Key DisableSavePassword -Value 1
        
        # Disable "MSS: (EnableDeadGWDetect) Allow automatic detection of dead network gateways (could lead to DoS)"
        RegPut HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Key EnableDeadGWDetect -Value 0
        
        # Disable "MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes" (~MSS, SHB, STIG)
        RegPut HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Key EnableICMPRedirect -Value 0
        
        # Disable "MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)"
        RegPut HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters -Key PerformRouterDiscovery -Value 0
        
        if ($draconian) {
            # MSS: (Hidden) Hide Computer From the Browse List (not recommended except for highly secure environments)
            RegPut HKLM:\System\CurrentControlSet\Services\Lanmanserver\Parameters -Key Hidden -Value 1
        }
        
        # Set "MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic." to "Only ISAKMP is exempt (recommended for Windows Server 2003)"
        RegPut HKLM:\System\CurrentControlSet\Services\IPSEC -Key NoDefaultExempt -Value 3
        
        # Prevent users and apps from accessing dangerous websites (~MSSB, MDE)
        if ($strict) {
            # Block dangerous websites
            RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Key EnableNetworkProtection -Value 2
			Set-MpPreference -EnableNetworkProtection Enabled
        }
        else {
            # Audit Mode
            RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Key EnableNetworkProtection -Value 1
			Set-MpPreference -EnableNetworkProtection AuditMode
        }
        
        # Windows Remote Management (WinRM) authentication hardening (~MSSB, SHB, MDE)
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -Key AllowBasic -Value 0
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -Key AllowUnencryptedTraffic -Value 0
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -Key DisableRunAs -Value 1
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -Key AllowBasic -Value 0
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -Key AllowUnencryptedTraffic -Value 0
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -Key AllowDigest -Value 0  # SHB says no, MSSB says yes

        # Disable Internet Connection Sharing
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Key NC_ShowSharedAccessUI -Value 0
        
        # Require domain users to elevate when setting a network's location
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Key NC_StdDomainUserSetLocation -Value 1
        
        # Prohibit installation and configuration of Network Bridge on your DNS domain network
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Key NC_AllowNetBridge_NLA -Value 0
        
        # Set NetBT NodeType to P-node (use only point-to-point name queries to a name server) (~MSSB)
        RegPut HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters -Key NodeType -Value 2
        
        # Turn off multicast name resolution (~MSSB)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Key EnableMulticast -Value 0
        
        # Set "Encryption Oracle Remediation" to "Force Updated Clients" (~MSSB)
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters -Key AllowEncryptionOracle -Value 0
        
        # Remote host allows delegation of non-exportable credentials (~MSSB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation -Key AllowProtectedCreds -Value 1
        
        if ($strict) {
            # Limit simultaneous connections to the Internet or a Windows domain (~SHB)
            RegPut HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy -Key fMinimizeConnections -Value 1
            
            # Block connections to non-domain networks when connected to a domain authenticated network (~SHB)
            RegPut HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy -Key fBlockNonDomain -Value 1
        }

        # Disable Wi-Fi Sense (~SHB)
        RegPut HKLM:\SOFTWARE\Microsoft\WvmSvc\wifinetworkmanager\config -Key AutoConnectAllowedOEM -Value 0
        
        
        ###### APPLICATION SECURITY SETTINGS ######
        SysDebugLog "Applying application security settings..."
        
        # Block Potentially Unwanted Applications
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Key PUAProtection -Value 1
        
        # Configure the 'Block at First Sight' feature (Enable) (~MSSB)
        RegPut "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Key DisableBlockAtFirstSeen -Value 0
        
        # ***TODO:*** Make this configurable ***separately*** before enabling it
        if ($false) {
            # Join Microsoft MAPS with Advanced membership (~MSSB)
            RegPut "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Key SpynetReporting -Value 2
            
            # Set "Send file samples when further analysis is required" to "Send safe samples"
            RegPut "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Key SubmitSamplesConsent -Value 1
        }
        
        # Disable "Allow user control over installers" (~MSSB, SHB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\Installer -Key EnableUserControl -Value 0
        
        # Disable "Always install with elevated privileges" (~MSSB, SHB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\Installer -Key AlwaysInstallElevated -Value 0
        
        # Prompts users when Web scripts try to install software (~SHB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\Installer -Key SafeForScripting -Value 0

        if ($strict) {
            # Enable Windows Defender Application Guard in Managed Mode (~MDE)
            Enable-WindowsOptionalFeature -Online -NoRestart -FeatureName Windows-Defender-ApplicationGuard
            RegPut HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI -Key AllowAppHVSI_ProviderSet -Value 3
        }
        
        # Configure Windows Defender SmartScreen -- Enable and set to Warn but allow bypass (~MSSB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\System -Key EnableSmartScreen -Value 1  # (~SHB too)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\System -Key ShellSmartScreenLevel -Value Warn -VType String
        
        
        ###### BROWSER SECURITY SETTINGS ######
        SysDebugLog "Applying browser security settings..."

        # Chrome/Brave -- Block third-party cookies
        RegPut HKLM:\SOFTWARE\Policies\Google\Chrome -Key BlockThirdPartyCookies -Value 1
        RegPut HKLM:\SOFTWARE\Policies\BraveSoftware\Brave -Key BlockThirdPartyCookies -Value 1
        
        # Chrome/Brave -- Disable background processes when browser is not running
        RegPut HKLM:\SOFTWARE\Policies\Google\Chrome -Key BackgroundModeEnabled -Value 0
        RegPut HKLM:\SOFTWARE\Policies\BraveSoftware\Brave -Key BackgroundModeEnabled -Value 0
        
        # IE -- Block files with an invalid signature from running or installing (~MDE)
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download" -Key RunInvalidSignatures -Value 0
        
        # IE -- Disable navigation to file:// URLs from non-file:// URLs
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl" -Key FEATURE_BLOCK_CROSS_PROTOCOL_FILE_NAVIGATION -Value 1
        
        # IE -- Block outdated ActiveX controls for Internet Explorer (~MDE)
        RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext -Key VersionCheckEnabled -Value 1
        
        # IE -- Prevent per-user installation of ActiveX controls (~MSSB)
        RegPut "HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX" -Key BlockNonAdminActiveXInstall -Value 1
        
        if ($strict) {
            # IE -- Security Zones: Do not allow users to add/delete sites (~MSSB)
            RegPut "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Key Security_zones_map_edit -Value 1
            
            # IE -- Security Zones: Do not allow users to change policies (~MSSB)
            RegPut "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Key Security_options_edit -Value 1
            
            # IE --Security Zones: Use only machine settings (~MSSB)
            RegPut "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Key Security_HKLM_only -Value 1
        }
        
        # IE -- Specify use of ActiveX Installer Service for installation of ActiveX controls (~MSSB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\AxInstaller -Key OnlyUseAXISForActiveXInstall -Value 1
        
        # IE -- Turn off Crash Detection (~MSSB)
        RegPut "HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions" -Key NoCrashDetection -Value 1
        
        # IE -- Disable "Turn off the Security Settings Check feature" (~MSSB)
        RegPut "HKLM:\Software\Policies\Microsoft\Internet Explorer\Security" -Key DisableSecuritySettingsCheck -Value 0
        
        # ... skipped MSSB IExplore settings 1129-1156, 1175-1846 for now ...
        
        # IE -- Turn on Enhanced Protected Mode (~MSSB)
        RegPut "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main" -Key Isolation -Value PMEM -Value String  # wtf why cant you just use dwords like a normal person
        
        # IE -- Prevent downloading of enclosures (~MSSB, SHB)
        RegPut "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Key DisableEnclosureDownload -Value 1
        
        # IE -- Disable basic (plaintext) authentication for RSS feeds over HTTP (~SHB)
        RegPut "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Key AllowBasicAuthInClear -Value 0
        
        if ($strict) {
            # Edge -- Prevent bypassing Windows Defender SmartScreen prompts for sites (~MSSB, SHB)
            RegPut HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter -Key PreventOverride -Value 1
            
            # Edge -- Prevent bypassing Windows Defender SmartScreen prompts for files (~MSSB, SHB)
            RegPut HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter -Key PreventOverrideAppRepUnknown -Value 1
        
            # Edge -- Prevent certificate error overrides (~MSSB)
            RegPut "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Internet Settings" -Key PreventCertErrorOverrides -Value 1
        }
        
        if ($draconian) {
            # Edge -- Disable Password Manager (~MSSB, SHB)
            RegPut HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main -Key "FormSuggest Passwords" -Value "no" -VType String  # srsly just be a dword omg
        }

        # Edge -- Enable Windows Defender Smart Screen  (~SHB)
        RegPut HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter -Key EnabledV9 -Value 1
        

        ###### MISCELLANEOUS ######
        SysDebugLog "Applying additional security settings..."

        # Skip signatures that exploit vulnerabilities the system is already patched against
        RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\NIS\Consumers\IPS" -Key DisableSignatureRetirement -Value 0

        # Turn off Microsoft consumer experiences (~MSSB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\CloudContent -Key DisableWindowsConsumerFeatures -Value 1
        
        if ($strict) {
            # Disable "Windows Game Recording and Broadcasting" (~MSSB)
            RegPut HKLM:\Software\Policies\Microsoft\Windows\GameDVR -Key AllowGameDVR -Value 0
        }
        
        # Set "Allow Windows Ink Workspace" to "On, but disallow access above lock" (~MSSB)
        RegPut HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace -Key AllowWindowsInkWorkspace -Value 1
        
        # Turn on PowerShell Script Block Logging (but don't log invocation start/stop events) (~MSSB)
        RegPut HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Key EnableScriptBlockInvocationLogging -Value 0
        RegPut HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Key EnableScriptBlockLogging -Value 1  # (~SHB too)
        
        if ($draconian) {
            # Disable OneDrive
            RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Key DisableFileSyncNGSC -Value 1
        }
        
        
        SysDebugLog "Security policy version applied: 8/15/2023"
    }

    SysDebugLog "ElevatedAction exiting"
    exit
}



### POWERWASH FEATURES ###



PowerWashText ""
PowerWashText "### PERFORMANCE FEATURES ###"
PowerWashText ""


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
    
    # Disable power throttling
    RegPut HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling -Key PowerThrottlingOff -Value 1
    
    # Disable hibernation, as it prevents shutdowns from fully shutting down the computer.
    powercfg /hibernate off
    
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

    "- Disabling USB power saving..."
    $powerMgmt = Get-CimInstance -ClassName MSPower_DeviceEnable -Namespace root/WMI | Where-Object InstanceName -Like USB*
    foreach ($p in $powerMgmt) {
        $p.Enable = $false
        Set-CimInstance -InputObject $p
    }
    
    "- Complete"
}

# Prioritize low latency on network adapters
if (Confirm "Optimize network adapter settings for low latency?" -Auto $true -ConfigKey "Performance.NetworkResponsiveness") {
    RegPut "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Key NetworkThrottlingIndex -Value 0xFFFFFFFF
    RegPut HKLM:\SYSTEM\ControlSet001\Services\Ndu -Key Start -Value 0x4
    
    # Below settings may fail depending on network adapter's capabilities. This isn't a problem, so fail silently
    Set-NetAdapterAdvancedProperty -Name "*" -IncludeHidden -DisplayName "Throughput Booster" -DisplayValue Enabled -EA SilentlyContinue 2>$null | Out-Null
    Set-NetAdapterAdvancedProperty -Name "*" -IncludeHidden -DisplayName "Packet Coalescing" -DisplayValue Disabled -EA SilentlyContinue
    Enable-NetAdapterChecksumOffload -Name "*" -IncludeHidden -EA SilentlyContinue
    Disable-NetAdapterRsc -Name '*' -IncludeHidden -EA SilentlyContinue 2>$null | Out-Null  # Disables packet coalescing
    Disable-NetAdapterPowerManagement -Name '*' -IncludeHidden -EA SilentlyContinue 2>$null | Out-Null
    Restart-NetAdapter -Name '*' -IncludeHidden -EA SilentlyContinue 2>$null | Out-Null
    
    "- Complete"
}

# Enable MSI mode for devices that support it
# Message-signaled interrupts are an alternative to line-based interrupts,
# supporting a larger number of interrupts and lower latencies.
# https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-message-signaled-interrupts
if (Confirm "Enable Message-Signaled Interrupts for all devices that support them?" -Auto $true -ConfigKey "Performance.EnableDriverMsi") {
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
        if ($do_priority -and ($DeviceDesc -like "*PCIe Controller*" -or $DeviceDesc -like "*NVIDIA GeForce*" -or $DeviceDesc -like "*Ethernet Controller*")) {
            "  - Prioritizing interrupts from $DeviceDesc..."
            RegPut "HKLM:\SYSTEM\CurrentControlSet\Enum\$InstanceId\Device Parameters\Interrupt Management\Affinity Policy" -Key DevicePriority -Value 3
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
            RegPut "HKLM:\SYSTEM\CurrentControlSet\Enum\$InstanceId\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" -Key MSISupported -Value 1
            $N_MSI++
        }
    }
    "- MSI mode enabled for all $N_MSI supported devices. Restart required to take effect"
    "- Interrupts prioritized for $N_Prio devices. Restart required to take effect"
    "- Complete (restart required)"
}


# Disable HPET (high precision event timer)
# Some systems will benefit from this, some will suffer. Only way is to benchmark and see
if (Confirm "Disable the high-precision event timer? (May not improve performance on all systems)" -Auto $false -ConfigKey "Performance.DisableHpet") {
    Get-PnpDevice -FriendlyName "High precision event timer" | Disable-Pnpdevice -Confirm:$false
    "- Complete"
}

if (Confirm "Enable hardware-accelerated GPU scheduling?" -Auto $true -ConfigKey "Performance.HwGpuScheduling") {
    RegPut HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers -Key HwSchMode -Value 2
    "- Complete (restart required)"
}

# Multimedia related settings to prioritize audio
# https://learn.microsoft.com/en-us/windows/win32/procthread/multimedia-class-scheduler-service
if ($do_all -or (Confirm "Optimize multimedia settings for pro audio?" -Auto $true -ConfigKey "Performance.MultimediaResponsiveness")) {
    # Scheduling algorithm will reserve 10% (default is 20%) of CPU for low-priority tasks
    RegPut "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Key SystemResponsiveness -Value 10
    
    # May reduce idling, improving responsiveness
    RegPut "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Key NoLazyMode -Value 1
    
    # Max priority for Pro Audio tasks
    RegPut "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Key Priority -Value 1
    RegPut "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Key "Scheduling Category" -Value "High" -VType String
    
    "- Complete (restart required)"
}

if (Confirm "Adjust visual settings for better performance?" -Auto $false -ConfigKey "Performance.AdjustVisualEffects") {
    # Mostly from https://superuser.com/a/1246803
    Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        [StructLayout(LayoutKind.Sequential)] public struct ANIMATIONINFO {
            public uint cbSize;
            public bool iMinAnimate;
        }
        public class AnimationParamMgr {
            [DllImport("user32.dll")] public static extern bool SystemParametersInfoW(uint uiAction, uint uiParam, ref ANIMATIONINFO pvParam, uint fWinIni);
        }

        public class RegularParamMgr {
            [DllImport("user32.dll")] public static extern bool SystemParametersInfoW(uint uiAction, uint uiParam, ref object pvParam, uint fWinIni);
        }
"@
    $animInfo = New-Object ANIMATIONINFO
    $animInfo.cbSize = 8
    $animInfo.iMinAnimate = 0
    [AnimationParamMgr]::SystemParametersInfoW(0x49, 0, [ref]$animInfo, 3) | Out-Null

    $disable = @(
        0x1025, # Drop shadow on windows
        # 0x004B,  # Font smoothing - most will want to keep this enabled
        0x1005, # Combo box animation
        0x101B, # Cursor shadow
        0x1009, # Window title bar gradient effect
        # 0x1007,  # Smooth-scrolling for list boxes - most will want to keep this enabled
        0x1003, # Disabling this disables all menu animation features
        0x1015, # Selection fade effect
        0x1017, # Tooltip fade effect
        0x0025  # Show window contents while dragging
    )
    $disable | ForEach-Object {
        [RegularParamMgr]::SystemParametersInfoW($_, 0, [ref]$false, 3) | Out-Null
    }

    RegPut "HKCU:\Control Panel\Desktop" -Key DragFullWindows -Value 0

    "- Complete"
}

if (Confirm "Disable Fast Startup? (may fix responsiveness issues with some devices)" -Auto $true -ConfigKey "Performance.DisableFastStartup") {
    RegPut "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Key HiberbootEnabled -Value 0
    "- Complete (takes effect on next restart)"
}



PowerWashText ""
PowerWashText ""
PowerWashText "### TELEMETRY CONFIGURATION ###"
PowerWashText ""


# Disable Microsoft telemetry as much as we can
if (Confirm "Disable Microsoft telemetry?" -Auto $true -ConfigKey "DisableTelemetry") {
    # Windows has 4 levels of telemetry: Security, Required, Enhanced, Optional
    # According to Microsoft, only Enterprise supports Security as min telemetry level, other platforms only support Required
    # However, we can just always set it to Security and Windows will apply the lowest allowed setting.
    $min_telemetry = 0
    
    "- Disabling telemetry registry settings..."
    RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Key AllowTelemetry -Value $min_telemetry
    RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy -Key TailoredExperiencesWithDiagnosticDataEnabled -Value 0
    RegPut HKLM:\SOFTWARE\Microsoft\Input\TIPC -Key Enabled -Value 0  # Inking/typing
    RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat -Key AITEnable -Value 0  # Apps
    RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat -Key DisableInventory -Value 1  # Application Compatibility Program Inventory
    
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
    Disable-ScheduledTask -TaskName CreateObjectTask -TaskPath \Microsoft\Windows\CloudExperienceHost -EA SilentlyContinue | Out-Null
    
    try { Set-MpPreference -DisableNetworkProtectionPerfTelemetry $true -EA SilentlyContinue | Out-Null } catch {}
    
    Set-ProcessMitigation -System -Disable SEHOPTelemetry
    
    "- Complete (restart recommended)"
}



PowerWashText ""
PowerWashText ""
PowerWashText "### BLOATWARE REMOVAL ###"
PowerWashText ""


if (Confirm "Uninstall Microsoft Edge?" -Auto $false -ConfigKey "Debloat.RemoveEdge") {
    $aggressive = Confirm "--> Remove Microsoft Edge aggressively? (Removes extra traces of Edge from the filesystem and registry)" -Auto $false -ConfigKey "Debloat.RemoveEdge_ExtraTraces"
    $aggressive_flag = $(If ($aggressive) { "/Aggressive" } Else { "" })

    "- Stopping Microsoft Edge..."
    taskkill /f /im msedge.exe 2>$null | Out-Null
    taskkill /f /im MicrosoftEdgeUpdate.exe 2>$null | Out-Null
    
    "- Marking Edge as removable in registry..."
    RegPut "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" -Key NoRemove -Value 0
    RegPut "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" -Key NoRepair -Value 0

    "- Removing Edge from provisioned packages..."
    $provisioned = (Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*Edge*" }).PackageName
    if ($null -ne $provisioned) {
        Remove-AppxProvisionedPackage -PackageName $provisioned -Online -AllUsers 2>$null | Out-Null
    }

    "- Marking Edge as removable in Appx database..."
    $EdgePackages = @()
    Get-AppxPackage -Name "*Microsoft*Edge*" | ForEach-Object {
        $Pkg = $_
        $EdgePackages += $Pkg.PackageFullName
        $RK_AppxStores | ForEach-Object {
            New-Item -Path "$_\EndOfLife\$SID\$($Pkg.PackageFullName)" -Force | Out-Null
        }
    }

    "- Removing Edge from Appx database..."
    Get-AppxPackage -Name "*Microsoft*Edge*" | Remove-AppxPackage

    "- Cleaning up Edge entries in Appx database..."
    $EdgePackages | ForEach-Object {
        $PkgName = $_
        $RK_AppxStores | ForEach-Object {
            Remove-Item -Path "$_\EndOfLife\$SID\$PkgName" -Force | Out-Null
        }
    }

    if ($aggressive) {
        "- Attempting to remove Edge using setup tool..."
    
        # https://gist.github.com/ave9858/c3451d9f452389ac7607c99d45edecc6
        Get-ChildItem -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState" -EA SilentlyContinue | ForEach-Object { Remove-ItemProperty -Path "Registry::$_" -Name "experiment_control_labels" -EA SilentlyContinue }  
        RegPut HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev -Key AllowUninstall -Value 1
    
        $edge_base = "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application\"
        if (Test-Path "$edge_base") {
            foreach ($item in Get-ChildItem -Path "$edge_base") {
                $setup = "$edge_base\$item\Installer\setup.exe"
                if (Test-Path "$setup") {
                    "  - Attempting to remove Edge installation: $setup"
                    & "$setup" --uninstall --msedge --system-level --verbose-logging --force-uninstall
                }
            }
        }

        # Many folders to remove are protected by SYSTEM
        Write-Host "- Removing Edge from filesystem..." -NoNewline
        RunScriptAsSystem -Path "$PSScriptRoot/$global:ScriptName" -ArgString "/ElevatedAction /RemoveEdge $aggressive_flag /FilesystemStage"

        # Many registry keys to remove are protected by SYSTEM
        Write-Host "- Removing traces of Edge from registry..." -NoNewline
        RunScriptAsSystem -Path "$PSScriptRoot/$global:ScriptName" -ArgString "/ElevatedAction /RemoveEdge $aggressive_flag /RegistryStage"
        if (Test-Path "$env:SystemDrive\.PowerWashAmcacheStatus.tmp") {
            # Removal from Amcache is totally overkill, but it's fun and technically implied by "removing traces from registry"
            $amcache_status = Get-Content "$env:SystemDrive\.PowerWashAmcacheStatus.tmp"
            Remove-Item "$env:SystemDrive\.PowerWashAmcacheStatus.tmp"
            if ($amcache_status -eq "Failure") {
                "  - NOTICE: Could not remove Edge from Amcache registry hive, probably because it is in use by another process. You can restart your computer and try again later."
            }
        }

        "- Removing Edge services..."
        $services_to_delete = @(
            "edgeupdate",
            "edgeupdatem",
            "MicrosoftEdgeElevationService"
        )
        $services_to_delete | ForEach-Object {
            sc.exe stop $_ | Out-Null
            sc.exe config $_ start=disabled | Out-Null
            sc.exe delete $_ | Out-Null
        }

        "- Disabling Edge tasks..."
        TryDisableTask "MicrosoftEdgeUpdateTaskMachineCore"
        TryDisableTask "MicrosoftEdgeUpdateTaskMachineUA"

        "- Disabling Edge in Windows Update..."
        # https://github.com/AveYo/fox/blob/main/Edge_Removal.bat
        # https://learn.microsoft.com/en-us/deployedge/microsoft-edge-update-policies
        $update_locations = @("HKLM:\SOFTWARE\Microsoft\EdgeUpdate", "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate")
        $update_locations | ForEach-Object {
            RegPut "$_" -Key DoNotUpdateToEdgeWithChromium -Value 1
            RegPut "$_" -Key UpdaterExperimentationAndConfigurationServiceControl -Value 0

            RegPut "$_" -Key UpdatesSuppressedStartHour -Value 0x0
            RegPut "$_" -Key UpdatesSuppressedStartMin -Value 0x0
            RegPut "$_" -Key UpdatesSuppressedDurationMin -Value 0x5A0  # 1440 mins, or 24 hours

            RegPut "$_" -Key InstallDefault -Value 0
            RegPut "$_" -Key UpdateDefault -Value 0
        
            RegPut "$_" -Key "Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" -Value 1
            RegPut "$_" -Key "Install{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}" -Value 0
            RegPut "$_" -Key "Install{65C35B14-6C1D-4122-AC46-7148CC9D6497}" -Value 0
            RegPut "$_" -Key "Install{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}" -Value 0
            RegPut "$_" -Key "Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Value 0
        
            RegPut "$_" -Key "Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" -Value 1
            RegPut "$_" -Key "Update{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}" -Value 0
            RegPut "$_" -Key "Update{65C35B14-6C1D-4122-AC46-7148CC9D6497}" -Value 0
            RegPut "$_" -Key "Update{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}" -Value 0
            RegPut "$_" -Key "Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Value 0
        }
    }
    
    "- Note: May need to re-run this after Windows 'quality updates'"
    "- Complete"
}

if (Confirm "Remove Store?" -Auto $false -ConfigKey "Debloat.RemoveStore") {
    Get-AppxPackage -Name "Microsoft.StorePurchaseApp" | Remove-AppxPackage
    Get-AppxPackage -Name "Microsoft.WindowsStore" | Remove-AppxPackage
    "- Complete"
}

if (Confirm "Disable Cortana?" -Auto $true -ConfigKey "Debloat.DisableCortana") {
    RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Key AllowCortana -Value 0
    RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Key DisableWebSearch -Value 1
    RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Key ConnectedSearchUseWeb -Value 0
    RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Key ConnectedSearchUseWebOverMeteredConnections -Value 0
    "- Complete (restart recommended)"
}

if ($has_win_enterprise -and (Confirm "Disable Windows consumer features?" -Auto $true -ConfigKey "Debloat.DisableConsumerFeatures")) {
    RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent -Key DisableWindowsConsumerFeatures -Value 1
    RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent -Key DisableThirdPartySuggestions -Value 1
    RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent -Key DisableThirdPartySuggestions -Value 1
    RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent -Key DisableTailoredExperiencesWithDiagnosticData -Value 1
    "- Complete (restart required)"
}

if ($has_win_enterprise -and (Confirm "Disable preinstalled apps?" -Auto $true -ConfigKey "Debloat.DisablePreinstalled")) {
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Key FeatureManagementEnabled -Value 0
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Key OemPreInstalledAppsEnabled -Value 0
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Key PreInstalledAppsEnabled -Value 0
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Key ContentDeliveryAllowed -Value 0
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Key SilentInstalledAppsEnabled -Value 0
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Key PreInstalledAppsEverEnabled -Value 0
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Key SystemPaneSuggestionsEnabled -Value 0
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Key SoftLandingEnabled -Value 0
    "- Complete (restart required)"
}

if (Confirm "Remove configured list of preinstalled apps?" -Auto $true -ConfigKey "Debloat.RemovePreinstalled") {
    $Packages = Get-AppxPackage
    $ProvisionedPackages = Get-AppxProvisionedPackage -Online
    # Adapted from  https://www.kapilarya.com/how-to-uninstall-built-in-apps-in-windows-10
    $Packages | ForEach-Object {
        $Package = $_
        if ($Package.Name -in $global:config_map.Debloat.RemovePreinstalledList) {
            "- Attempting removal of $($Package.Name) installed package..."
            Set-NonRemovableAppsPolicy -Online -PackageFamilyName $Package.PackageFamilyName -NonRemovable 0 | Out-Null
            Remove-AppxPackage -package $Package.PackageFullName 2>$null | Out-Null
        }
    }
    $ProvisionedPackages | ForEach-Object {
        $Package = $_
        if ($Package.DisplayName -in $global:config_map.Debloat.RemovePreinstalledList) {
            "- Attempting removal of $($Package.displayName) provisioned package..."
            Remove-AppxProvisionedPackage -online -packagename $Package.PackageName 2>$null | Out-Null
        }
    }
    foreach ($pattern in $global:config_map.Debloat.RemovePreinstalledPatterns) {
        "- Removing any packages matching '$pattern'..."
        $Packages | Where-Object { $_.Name -match "$pattern" } | Remove-AppxPackage 2>$null
        $ProvisionedPackages | Where-Object { $_.DisplayName -match "$pattern" } | Remove-AppxProvisionedPackage -Online 2>$null | Out-Null
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

if (Confirm "Remove phantom applications?" -Auto $true -ConfigKey "Debloat.RemovePhantom") {
    $RK_Uninst_Locs | ForEach-Object {
        $root = $_
        Get-ChildItem -Path $root -EA SilentlyContinue | ForEach-Object {
            $path = "$_".replace("HKEY_LOCAL_MACHINE", "HKLM:")
            $name = (Get-ItemProperty -Path $path -Name "DisplayName" -EA SilentlyContinue).DisplayName
            $install = (Get-ItemProperty -Path $path -Name "InstallLocation" -EA SilentlyContinue).InstallLocation
            if ($install -and (-not (Test-Path -Path $install))) {
                "- Removing phantom app $name (method 1)"
                Remove-Item -Recurse -Force -Path $path
            }
        }
    }
    $RK_AppPath_Locs | ForEach-Object {
        $root = $_
        Get-ChildItem -Path $root -EA SilentlyContinue | ForEach-Object {
            $path = "$_".replace("HKEY_LOCAL_MACHINE", "HKLM:")
            $install = (Get-ItemProperty -Path $path -Name "Path" -EA SilentlyContinue).Path
            if ($install -and (-not (Test-Path -Path $install))) {
                $name = [System.IO.Path]::GetFileName($install)
                "- Removing phantom app $name (method 2)"
                Remove-Item -Recurse -Force -Path $path
            }
        }
    }
    $RK_AppxStores | ForEach-Object {
        $root = $_
        $RK_AppxStores_Subkeys | ForEach-Object {
            $sub = "$root\$_"
            Get-ChildItem -Path $sub -EA SilentlyContinue | ForEach-Object {
                $path = "$_".replace("HKEY_LOCAL_MACHINE", "HKLM:")
                $install = (Get-ItemProperty -Path $path -Name "Path" -EA SilentlyContinue).Path
                if ($install -and (-not (Test-Path -Path $install))) {
                    $name = [System.IO.Path]::GetFileName($install)
                    if ($name -notin @("Application", "AppxManifest.xml", "AppxBundleManifest.xml")) {
                        "- Removing phantom app $name (method 3)"
                        Remove-Item -Recurse -Force -Path $path
                    }
                }
            }
        }
    }
    "- Complete"
}



PowerWashText ""
PowerWashText ""
PowerWashText "### WINDOWS UPDATE CONFIGURATION ###"
PowerWashText ""


# Disable automatic updates
if ($has_win_pro) {
    if (Confirm "Disable automatic Windows updates?" -Auto $true -ConfigKey "WindowsUpdate.DisableAutoUpdate") {
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Key NoAutoUpdate -Value 1
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Key AutoInstallMinorUpdates -Value 0
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Key AUOptions -Value 2
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Key AllowMUUpdateService -Value 1
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Key EnableFeaturedSoftware -Value 0
        RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate -Key AutoDownload -Value 5
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore -Key AutoDownload -Value 4
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore -Key DisableOSUpgrade -Value 1
        RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Key AUPowerManagement -Value 0
        "- Complete"
    }
}
else {
    PowerWashText "Not applicable: Disable automatic Windows updates"
    PowerWashText "* Windows Home edition does not support disabling only automatic updates, skipping this feature"
    PowerWashText "* If you want to disable automatic updates on Home, you can try setting your internet connection to Metered. Otherwise, you can disable updates entirely below."
}

# Disable all updates
if (Confirm "Disable all Windows updates? (You will need to manually re-enable them when you want to check or install updates)" -Auto $false -ConfigKey "WindowsUpdate.DisableAllUpdate") {
    sc.exe stop UsoSvc | Out-Null
    sc.exe config UsoSvc start=disabled | Out-Null

    sc.exe stop WaaSMedicSvc | Out-Null
    RegPut HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc -Key Start -Value 4

    sc.exe stop wuauserv | Out-Null
    sc.exe config wuauserv start=disabled | Out-Null
    
    "- Complete"
}

# Add update toggle script to desktop
# This is the next best thing for Home users to being able to disable automatic updates. They can toggle updates on when they want to check or install updates, and toggle updates back off when they're done.
if ((-not (Test-Path "$home\Documents\.ToggleUpdates.bat")) -or (-not (Test-Path "$home\Desktop\Toggle Updates.lnk"))) {
    if (Confirm "Add a script to your desktop that lets you toggle Windows updates on or off?" -Auto $false -ConfigKey "WindowsUpdate.AddUpdateToggleScriptToDesktop") {
        DownloadFile -Url "https://raw.githubusercontent.com/PublicSatanicVoid/WindowsPowerWash/main/extra/ToggleUpdates.bat" -DestFile "$home\Documents\.ToggleUpdates.bat"
        
        CreateShortcut -Dest "$home\Desktop\Toggle Updates.lnk" -Source "$home\Documents\.ToggleUpdates.bat" -Admin $true
        
        "- Complete (script in Documents, shortcut on Desktop)"
    }
}
else {
    PowerWashText "Not applicable: Add Windows Update toggle script to Desktop (Already added)"
}




PowerWashText ""
PowerWashText ""
PowerWashText "### WINDOWS DEFENDER CONFIGURATION ###"
PowerWashText ""


if (Confirm "Apply high-security system settings? (Attack Surface Reduction, etc.)" -Auto $false -ConfigKey "Defender.ApplyRecommendedSecurityPolicies") {
    $apply_strict_policies = Confirm "--> Apply strict security settings? (Warning-May break certain applications especially with third-party antivirus installed)" -Auto $false -ConfigKey "Defender.ApplyStrictSecurityPolicies"
    $apply_draconian_policies = $false
    if ($apply_strict_policies) {
        $apply_draconian_policies = Confirm "--> Apply extra strict security settings? (Warning-Very likely to break certain applications! Evaluate this in a test environment and ensure the breakage is acceptable!)" -Auto $false -ConfigKey "Defender.ApplyExtraStrictSecurityPolicies"
    }
    Write-Host "- Applying policies..." -Nonewline
    RunScriptAsSystem -Path "$PSScriptRoot/$global:ScriptName" -ArgString "/ElevatedAction /ApplySecurityPolicy $(If ($apply_strict_policies) { '/StrictMode'} Else {''}) $(If ($apply_draconian_policies) { '/DraconianMode'} Else {''})"
    "- Complete (restart required)"
	
	"- NOTE: If you experience problems with applications loading after you restart, you can clear the process mitigation options by setting all bytes to zero in this registry key: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel!MitigationOptions"
}

$legal_notice_text = RegGet HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Key legalnoticetext
if ($legal_notice_text -eq "") {
    if (Confirm "Add a warning screen prior to sign-in to deter unauthorized access?" -Auto $false -ConfigKey "Defender.AddWarningScreen") {
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Key legalnoticecaption -Value "Secure System" -VType String
        RegPut HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Key legalnoticetext -Value "This is a secure system equipped with hardware- and software-level intrusion detection and prevention. It is a violation of 18 U.S.C. 1030 to attempt to access this system without authorization. Attempts to access this system without authorization will be prosecuted to the fullest extent of the law. Notwithstanding applicable law, this system may not be accessed by anyone other than the person(s) to whom it was issued." -VType String
        "- Complete"
    }
}
else {
    PowerWashText "Not applicable: Add a warning screen prior to sign-in (Warning text already exists. Since this is typically used for legal notices, it should not be overwritten.)"
}

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
    RunScriptAsSystem -Path "$PSScriptRoot/$global:ScriptName" -ArgString "/ElevatedAction /DisableRealtimeMonitoring $(If ($disable_all_defender) {'/DisableAllDefender'} Else {''})"
    
    "- Complete (requires Tamper Protection disabled to take effect)"
}



PowerWashText ""
PowerWashText ""
PowerWashText "### CONVENIENCE SETTINGS ###"
PowerWashText ""


$restart_explorer = $false

if (Confirm "Disable app startup delay?" -Auto $true -ConfigKey "Convenience.DisableStartupDelay") {
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize -Key StartupDelayInMSec -Value 0
    "- Complete"
}

# Seconds in taskbar
if (Confirm "Show seconds in the taskbar clock?" -Auto $false -ConfigKey "Convenience.ShowSecondsInTaskbar") {
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Key ShowSecondsInSystemClock -Value 1
    $restart_explorer = $true
    "- Complete (will take effect shortly)"
}

# Show "Run as different user"
if (Confirm "Show 'Run as different user' in Start?" -Auto $true -ConfigKey "Convenience.ShowRunAsDifferentUser") {
    RegPut HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Key ShowRunAsDifferentUserInStart -Value 1
    $restart_explorer = $true
    "- Complete (will take effect shortly)"
}

# Show useful Explorer stuff
if (Confirm "Show file extensions and hidden files in Explorer?" -Auto $true -ConfigKey "Convenience.ShowHiddenExplorer") {
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Key Hidden -Value 1
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Key HideFileExt -Value 0
    $restart_explorer = $true
    "- Complete (will take effect shortly)"
}

if (Confirm "Remove 3D Objects / Music / Pictures / Videos from File Explorer?" -Auto $false -ConfigKey "Convenience.RemoveFileExplorerCruft") {
	TryRemoveItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
	TryRemoveItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
	
	TryRemoveItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
	TryRemoveItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
	
	TryRemoveItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
	TryRemoveItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
	
	TryRemoveItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
	TryRemoveItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"

	$restart_explorer = $true
	"- Complete (will take effect shortly)"
}

# Clean up taskbar
if (Confirm "Clean up taskbar? (Recommended for a cleaner out-of-box Windows experience)" -Auto $false -ConfigKey "Convenience.CleanupTaskbar") {
    UnpinApp("Microsoft Store")
    UnpinApp("Microsoft Edge")
    RegPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Key EnableFeeds -Value 0
    $restart_explorer = $true
    "- Complete (will take effect shortly)"
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
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Key TraySearchBoxVisible -Value 1
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Key SearchboxTaskbarMode -Value 2
}
elseif ($searchbox_mode -eq "Icon") {
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Key TraySearchBoxVisible -Value 0
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Key SearchboxTaskbarMode -Value 1
}
elseif ($searchbox_mode -eq "Hidden") {
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Key TraySearchBoxVisible -Value 0
    RegPut HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Key SearchboxTaskbarMode -Value 0
}
if ($searchbox_mode -ne "NoChange") {
    $restart_explorer = $true
    "- Complete (will take effect shortly)"
}

if ($restart_explorer) {
    "Restarting Explorer to apply above settings..."
    taskkill /f /im explorer.exe | Out-Null
    Start-Process explorer.exe
    "- Complete"
}

# Show UAC Prompt on Same Desktop
if (Confirm "Show UAC prompt on same desktop?" -Auto $true -ConfigKey "Convenience.ShowUacPromptOnSameDesktop") {
    RegPut HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Key PromptOnSecureDesktop -Value 0
    "- Complete (restart required)"
}

# Disable mono audio
if (Confirm "Disable mono audio?" -Auto $true -ConfigKey "Convenience.DisableMonoAudio") {
	RegPut HKCU:\Software\Microsoft\Multimedia\Audio -Key AccessibilityMonoMixState -Value 0
	net.exe stop AudioSrv
	net.exe start AudioSrv
}



PowerWashText ""
PowerWashText ""
PowerWashText "### INSTALLATION CONFIGURATION ###"
PowerWashText ""


# Install Group Policy editor, which isn't installed by default on Home editions
# Allows easy tweaking of a wide range of settings without needing to edit registry
if (-not $has_win_pro) {
    if ( (-not $noinstall) -and (Confirm "Install Group Policy editor? (Not installed by default on Home editions)" -Auto $true -ConfigKey "Install.InstallGpEdit")) {
        "- Installing Group Policy editor..."
        cmd /c 'FOR %F IN ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum") DO (DISM /Online /NoRestart /Add-Package:"%F")' | Out-Null
        cmd /c 'FOR %F IN ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum") DO (DISM /Online /NoRestart /Add-Package:"%F")' | Out-Null
        
        "- Complete"
    }
}
else {
    PowerWashText "Not applicable: Install Group Policy editor (Already installed by default on non-Home editions)"
}

if ((Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online).State -ne "Enabled") {
    if (-not $has_win_pro) {
        if ((-not $noinstall) -and (Confirm "Install Hyper-V? (Not installed by default on Home editions)" -Auto $false -ConfigKey "Install.InstallHyperV")) {
            "- Enumerating packages..."
            $pkgs = Get-ChildItem $env:SystemDrive\Windows\servicing\Packages | Where-Object { $_.Name -like "*Hyper*V*mum" }
            
            "- Installing packages..."
            $i = 1
            $pkgs | ForEach-Object {
                $pkg = $_.Name
                "  - ($i/$($pkgs.Length)) $pkg"
                DISM.exe /Online /NoRestart /Add-Package:"$env:SystemDrive\Windows\servicing\Packages\$pkg" 2>$null | Out-Null
                $i++
            }    

            "- Enabling Hyper-V..."
            Enable-WindowsOptionalFeature -Online -NoRestart -FeatureName Microsoft-Hyper-V -All | Out-Null

            "- Complete (restart required)"
        }
    }
    else {
        if (Confirm "Enable Hyper-V?" -Auto $false -ConfigKey "Install.InstallHyperV") {
            Enable-WindowsOptionalFeature -Online -NoRestart -FeatureName Microsoft-Hyper-V -All | Out-Null
            "-Complete (restart required)"
        }
    }
}
else {
    PowerWashText "Not applicable: Install/Enable Hyper-V (Already enabled on this computer)"
}

if (-not $global:has_winget) {
    if ((Confirm "Install Winget package manager?" -Auto $false -ConfigKey "Install.InstallWinget")) {
        "- Installing Winget dependencies..."
        
        Install-Winget
        Start-Sleep -Seconds 1;

        "- Winget installed, waiting up to 10s for path to show up"
        $retry = 0
        while ($retry -lt 10 -and -not (Test-Path $global:winget_cmd)) {
            $retry += 1;
            Start-Sleep -Seconds 1;
        }
        if (Test-Path $global:winget_cmd) {
            "  (Winget path shows up)"
        }
        else {
            "  (Timed out - warning, Winget may not be installed correctly)"
        }
        
        "- Complete"
    }
}
else {
    PowerWashText "Not applicable: Install Winget package manager (Already installed on this computer)"
}

if ($global:has_winget) {
    if (Confirm "Install configured applications?" -Auto $false -ConfigKey "Install.InstallConfigured") {
        foreach ($params in $global:config_map.Install.InstallConfiguredList) {
            & $global:winget_cmd "install" "--accept-package-agreements" "--accept-source-agreements" "$params"
        }
        "- Complete"
    }
}
else {
    PowerWashText "Skipping install of configured applications: Winget not installed"
}



PowerWashText ""
PowerWashText ""
PowerWashText "### SCANS AND AUTOMATIC REPAIRS ###"
PowerWashText ""


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



PowerWashText ""
""
PowerWashText "### POWERWASH COMPLETE ###"
"A restart is recommended"
""



if ($is_unattend -and (-not $will_restart)) {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show('Custom Windows configuration has been successfully applied. A restart is recommended.', 'PowerWash Setup', 'OK', [System.Windows.Forms.MessageBoxIcon]::Information)
}

if ($will_restart) {
    Restart-Computer
}
