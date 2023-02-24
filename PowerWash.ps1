#
# PowerWash (Alpha)
#
# Aims to improve system responsiveness, performance, and latency
# by tuning settings to uncompromisingly favor performance and
# low latencies. Also removes some usually unwanted default Windows
# behaviors.
#
# USE AT YOUR OWN RISK. BACKUP SYSTEM BEFORE USING.
#

if ($args[0] -eq "/?") {
	".\PowerWash.ps1 [/all] [/noinstalls] [/noscans] [/autorestart]"
	exit
}

$global:do_all="/all" -in $args
$noinstall="/noinstalls" -in $args
$noscan="/noscans" -in $args
$autorestart="/autorestart" -in $args

function RegistryPut ($Path, $Key, $Value, $ValueType) {
	If (-NOT (Test-Path "$Path")) {
		New-Item -Path "$Path" -Force | Out-Null
	}
	New-ItemProperty -Path "$Path" -Name "$Key" -Value "$Value" -PropertyType "$ValueType" -Force | Out-Null
}

function Confirm ($Prompt) {
	if ($global:do_all) {
		return $true
	}
	return (Read-Host "$Prompt y/n") -eq "y"
}

# Check system file integrity
$do_sfc=(-not $noscan) -and (Confirm "Run system file integrity checks? (May take a few minutes)")
if ($do_sfc) {
	sfc /scannow
	dism /online /cleanup-image /restorehealth
}

# Install Group Policy editor, which isn't installed by default on Home editions
# Allows easy tweaking of a wide range of settings without needing to edit registry
$do_gpedit=(-not $noinstall) -and (Confirm "Install Group Policy editor? (Not installed by default on Home editions)")
if ($do_gpedit) {
	cmd /c 'FOR %F IN ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum") DO (DISM /Online /NoRestart /Add-Package:"%F")'
	cmd /c 'FOR %F IN ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum") DO (DISM /Online /NoRestart /Add-Package:"%F")'
}

# Disable HPET (high precision event timer)
# Some systems will benefit from this, some will suffer. Only way is to benchmark and see
$disable_hpet=Confirm "Do you want to disable the high-precision event timer? (May not improve performance on all systems)"
if ($disable_hpet) {
	Get-PnpDevice -FriendlyName "High precision event timer" | Disable-Pnpdevice -Confirm:$false
	"High-precision event timer disabled"
}

# Disable automatic updates
$disable_autoupdate=Confirm "Do you want to disable automatic Windows updates?"
if ($disable_autoupdate) {
	RegistryPut -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "NoAutoUpdate" -Value 1 -ValueType "DWord"
	"Automatic Windows updates disabled"
}

# Disable Microsoft telemetry
$disable_telemetry=Confirm "Do you want to disable Microsoft telemetry?"
if ($disable_telemetry) {
	# Unclear whether or not this should have spaces
	RegistryPut -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Key "Allow Telemetry" -Value 0 -ValueType "DWord"
	RegistryPut -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Key "AllowTelemetry" -Value 0 -ValueType "DWord"
	
	cmd /c "sc config DiagTrack start=disabled"
	cmd /c "sc config dmwappushservice start=disabled"
	
	"Microsoft telemetry disabled"
}

# Multimedia related settings to prioritize audio
$opt_mmcss=Confirm "Do you want to optimize multimedia settings for pro audio?"
if ($do_all -or $opt_mmcss -eq 'y') {
	# Scheduling algorithm will reserve 10% (default is 20%) of CPU for low-priority tasks
	RegistryPut -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Key "SystemResponsiveness" -Value 10 -ValueType "DWord"
	
	# May reduce idling, improving responsiveness
	RegistryPut -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Key "NoLazyMode" -Value 1 -ValueType "DWord"
	
	# Max priority for Pro Audio tasks
	RegistryPut -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Key "Priority" -Value 1 -ValueType "DWord"
	RegistryPut -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Key "Scheduling Category" -Value "High" -ValueType "String"
	
	"Multimedia settings optimized for pro audio"
}

# Power management settings for high performance - "Ultimate" power scheme bundled with newer Windows versions
$redline=Confirm "Redline power settings for maximum performance? (May reduce latency, but will use more power)"
if ($redline) {
	$scheme=((powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61) -ireplace '.*GUID: (\w+-\w+-\w+-\w+-\w+).*', '$1')
	powercfg /setacvalueindex $scheme 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0  # Disable usb selective suspend
	powercfg /setacvalueindex $scheme 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 0  # Disable wake timers
	powercfg /setacvalueindex $scheme SUB_PROCESSOR LATENCYHINTPERF1 99  # Latency sensitive tasks will raise performance level
	powercfg /setacvalueindex $scheme SUB_VIDEO VIDEOIDLE 0  # Don't automatically turn off display
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
	RegistryPut -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Key "PowerThrottlingOff" -Value 1 -ValueType "DWord"
	
	"High performance power settings installed"
}

# Prioritize low latency on network adapters
$net=Confirm "Optimize network adapter settings for low latency?"
if ($net) {
	RegistryPut -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Key "NetworkThrottlingIndex" -Value 0xFFFFFFFF -ValueType "DWord"
	# Below settings may fail depending on network adapter's capabilities. This isn't a problem, so fail silently
	Set-NetAdapterAdvancedProperty -Name "*" -IncludeHidden -DisplayName "Throughput Booster" -DisplayValue "Enabled" -erroraction 'silentlycontinue'
	Enable-NetAdapterChecksumOffload -Name "*" -IncludeHidden -erroraction 'silentlycontinue'
	Disable-NetAdapterRsc -Name '*' -IncludeHidden -erroraction 'silentlycontinue'  # Disables packet coalescing
	Disable-NetAdapterPowerManagement -Name '*' -IncludeHidden -erroraction 'silentlycontinue'
	Restart-NetAdapter -Name '*' -IncludeHidden -erroraction 'silentlycontinue'
	"Network adapter settings optimized"
}

$disable_faststartup=Confirm "Disable Fast Startup? (may fix responsiveness issues with some devices)"
if ($disable_faststartup) {
	RegistryPut -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Key "HiberbootEnabled" -Value 0 -ValueType "DWord"
	"Fast Startup disabled"
}

# Enable MSI mode for devices that support it
# Message-signaled interrupts are an alternative to line-based interrupts,
# supporting a larger number of interrupts and lower latencies.
$do_msi=Confirm "Do you want to enable Message-Signaled Interrupts for all devices that support them?"
if ($do_msi) {
	$do_acpi_spread=Confirm "--> Do you also want to spread ACPI interrupts across all processors?"
	$do_priority=Confirm "--> Do you also want to prioritize interrupts from certain devices like the GPU and PCIe controller?"
	
	"Applying interrupt policies..."
	
	$N_MSI = 0
	$N_ACPI = 0
	$N_Prio = 0
	$Devices = Get-CimInstance -ClassName Win32_PnPEntity
	foreach ($Device in $Devices) {
		# https://powershell.one/wmi/root/cimv2/win32_pnpentity-GetDeviceProperties
		$Properties = Invoke-CimMethod -MethodName GetDeviceProperties -InputObject $Device | Select-Object -ExpandProperty DeviceProperties
		
		$DeviceDesc = ($Properties | Where-Object {$_.KeyName -eq 'DEVPKEY_Device_DeviceDesc'}).Data
		$InstanceId = ($Properties | Where-Object {$_.KeyName -eq 'DEVPKEY_Device_InstanceId'}).Data
		
		# Spread interrupts across multiple cores
		if ($do_acpi_spread -and $DeviceDesc -like "*ACPI*") {
			"- Enabling interrupt spreading for $DeviceDesc..."
			RegistryPut -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$InstanceId\Device Parameters\Interrupt Management\Affinity Policy" -Key "DevicePolicy" -Value 5 -ValueType "DWord"
			$N_ACPI++
		}
		
		# Prioritize interrupts from PCIe controller and graphics card
		if ($do_priority -and ($DeviceDesc -like "*PCIe Controller*" -or $DeviceDesc -like "*NVIDIA GeForce*")) {
			"- Prioritizing interrupts from $DeviceDesc..."
			RegistryPut -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$InstanceId\Device Parameters\Interrupt Management\Affinity Policy" -Key "DevicePriority" -Value 3 -ValueType "DWord"
			$N_Prio++
		}
		
		# https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/shared/pciprop.h#L345
		# 1 = LineBased, 2 = Msi, 4 = MsiX
		# Only devices that support MSI should have it enabled. Attempting to enable MSI on a device
		# that does not support it *can* make Windows unbootable. The "InterruptSupport" key tells us
		# what interrupt types are supported, so we can ensure they're only enabled where valid
		$InterruptModes = ($Properties | Where-Object {$_.KeyName -eq 'DEVPKEY_PciDevice_InterruptSupport'}).Data
		if ($InterruptModes -gt 1) {
			"- Enabling MSI mode for $DeviceDesc..."
			RegistryPut -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$InstanceId\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" -Key "MSISupported" -Value 1 -ValueType "DWord"
			$N_MSI++
		}
	}
	"MSI mode enabled for all $N_MSI supported devices. Restart required to take effect"
	"Interrupt spreading enabled for $N_ACPI supported devices. Restart required to take effect"
	"Interrupts prioritized for $N_Prio devices. Restart required to take effect"
}

# Checks for IRQ conflicts
$check_irq=Confirm "Do you want to check for IRQ conflicts?"
if ($check_irq) {
	"Checking for IRQ conflicts..."
	Get-CimInstance Win32_PNPAllocatedResource | Out-File -FilePath "IRQDump.txt"
	(Select-String -Path "IRQDump.txt" -Pattern "IRQNumber") -ireplace '.*IRQNumber = (\d+).*', '$1' | Out-File -FilePath IRQNumbers.txt
	$SharedIRQ=(Get-Content IRQNumbers.txt | Group-Object | Where-Object {$_.Count -gt 1 } | Select -ExpandProperty Name)
	if ($SharedIRQ.Length > 0) {
		"Alert: IRQ conflicts found at: $SharedIRQ"
		"This means that more than one device is sharing an interrupt line to the CPU, which *may* cause resource contention and degrade performance of those devices."
	}
	else {
		"No IRQ conflicts found"
	}
}

# Checks for third-party antivirus products (generally not needed)
$av_product=(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).displayName
if ($av_product -ne "Windows Defender") {
	"Notice: You are using a third-party antivirus product. These can slow down your system and often don't provide any extra benefit."
	if ($av_product -like "*McAffee*") {
		"Warning: McAffee software is especially notorious for bloating your system and providing low-quality protection!"
	}
}

""

"PowerWash complete, a restart is recommended."
if ($autorestart) {
	Restart-Computer
}
