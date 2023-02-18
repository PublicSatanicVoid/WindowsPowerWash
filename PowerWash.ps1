#
# PowerWash (Alpha)
#

$do_all=($args[0] -eq "all")

function RegistryPut ($Path, $Key, $Value, $ValueType)
{
	If (-NOT (Test-Path "$Path")) {
		New-Item -Path "$Path" -Force | Out-Null
	}
	New-ItemProperty -Path "$Path" -Name "$Key" -Value "$Value" -PropertyType "$ValueType" -Force | Out-Null
}

# Check system file integrity
$do_sfc=Read-Host "Run system file integrity checks? (May take a few minutes) y/n: "
if ($do_all -or $do_sfc -eq 'y') {
	sfc /scannow
	dism /online /cleanup-image /restorehealth
}

# Install Group Policy editor, which isn't installed by default on Home editions
$do_gpedit=Read-Host "Install Group Policy editor? (Not installed by default on Home editions) y/n: "
if ($do_all -or $do_gpedit -eq 'y') {
	cmd /c 'FOR %F IN ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum") DO (DISM /Online /NoRestart /Add-Package:"%F")'
	cmd /c 'FOR %F IN ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum") DO (DISM /Online /NoRestart /Add-Package:"%F")'
}

# Disable HPET (high precision event timer)
$disable_hpet=Read-Host "Do you want to disable the high-precision event timer? (May not improve performance on all systems) y/n: "
if ($do_all -or $disable_hpet -eq 'y') {
	Get-PnpDevice -FriendlyName "High precision event timer" | Disable-Pnpdevice
	"High-precision event timer disabled"
}

# Disable Packet Coalescing
$disable_rsc=Read-Host "Do you want to disable packet coalescing? (May improve network driver latency) y/n: "
if ($do_all -or $disable_rsc -eq 'y') {
	Disable-NetAdapterRsc -Name '*' -IncludeHidden
	"Packet coalescing disabled"
}

# Disable automatic updates
$disable_autoupdate=Read-Host "Do you want to disable automatic Windows updates? y/n: "
if ($do_all -or $disable_autoupdate -eq 'y') {
	RegistryPut -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Key "NoAutoUpdate" -Value 1 -ValueType "DWord"
	"Automatic Windows updates disabled"
}

# Disable telemetry
$disable_telemetry=Read-Host "Do you want to disable Microsoft telemetry? y/n: "
if ($do_all -or $disable_telemetry -eq 'y') {
	RegistryPut -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Key "Allow Telemetry" -Value 0 -ValueType "DWord"
	RegistryPut -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Key "AllowTelemetry" -Value 0 -ValueType "DWord"
	cmd /c "sc config DiagTrack start=disabled"
	cmd /c "sc config dmwappushservice start=disabled"
	"Microsoft telemetry disabled"
}

# Multimedia related settings to prioritize audio
$opt_mmcss=Read-Host "Do you want to optimize multimedia settings for pro audio? y/n: "
if ($do_all -or $opt_mmcss -eq 'y') {
	RegistryPut -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Key "System Responsiveness" -Value 0x14 -ValueType "DWord"
	RegistryPut -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Key "NoLazyMode" -Value 1 -ValueType "DWord"
	RegistryPut -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Key "Priority" -Value 1 -ValueType "DWord"
	RegistryPut -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -Key "Scheduling Category" -Value "High" -ValueType "String"
	"Multimedia settings optimized for pro audio"
}

# Disable power throttling
$disable_powerthrottling=Read-Host "Do you want to disable power throttling? y/n: "
if ($do_all -or $disable_powerthrottling -eq 'y') {
	RegistryPut -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Key "PowerThrottlingOff" -Value 1 -ValueType "DWord"
	"Powre throttling disabled"
}

# Power management settings for high performance - "Ultimate" power scheme bundled with newer Windows versions
$redline=Read-Host "Redline power settings for maximum performance? (May reduce latency, but will use more power) y/n: "
if ($do_all -or $redline -eq 'y') {
	$scheme=((powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61) -ireplace '.*GUID: (\w+-\w+-\w+-\w+-\w+).*', '$1')
	powercfg /setacvalueindex $scheme 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0  # Disable usb selective suspend
	powercfg /setacvalueindex $scheme SUB_PROCESSOR LATENCYHINTPERF1 99
	powercfg /setacvalueindex $scheme SUB_VIDEO VIDEOIDLE 0
	# Below are documented at https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/hardware/power/power-performance-tuning
	powercfg /setacvalueindex $scheme SUB_PROCESSOR DISTRIBUTEUTIL 0
	powercfg /setacvalueindex $scheme SUB_PROCESSOR CPMINCORES 100
	powercfg /setacvalueindex $scheme SUB_PROCESSOR PERFINCPOL 2
	powercfg /setacvalueindex $scheme SUB_PROCESSOR PERFDECPOL 1
	powercfg /setacvalueindex $scheme SUB_PROCESSOR PERFINCTHRESHOLD 10
	powercfg /setacvalueindex $scheme SUB_PROCESSOR PERFDECTHRESHOLD 8
	powercfg /setacvalueindex $scheme SUB_PROCESSOR PERFBOOSTMODE 2  # Aggressive mode
	powercfg /setactive $scheme
	
	Disable-NetAdapterPowerManagement -Name '*' -IncludeHidden
	
	"High performance power settings installed"
}

# Enable MSI mode for devices that support it
$do_msi=Read-Host "Do you want to enable Message-Signaled Interrupts for all devices that support them? y/n: "
if ($do_all -or $do_msi -eq 'y') {
	$N_MSI = 0
	$Devices = Get-CimInstance -ClassName Win32_PnPEntity
	foreach ($Device in $Devices) {
		# https://powershell.one/wmi/root/cimv2/win32_pnpentity-GetDeviceProperties
		$Properties = Invoke-CimMethod -MethodName GetDeviceProperties -InputObject $Device | Select-Object -ExpandProperty DeviceProperties
		
		$DeviceDesc = ($Properties | Where-Object {$_.KeyName -eq 'DEVPKEY_Device_DeviceDesc'}).Data
		$InstanceId = ($Properties | Where-Object {$_.KeyName -eq 'DEVPKEY_Device_InstanceId'}).Data
		
		# https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/shared/pciprop.h#L345
		# 1 = LineBased, 2 = Msi, 4 = MsiX
		$InterruptModes = ($Properties | Where-Object {$_.KeyName -eq 'DEVPKEY_PciDevice_InterruptSupport'}).Data
		if ($InterruptModes -gt 1) {
			"Enabling MSI mode for $DeviceDesc..."
			RegistryPut -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\$InstanceId\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" -Key "MSISupported" -Value 1 -ValueType "DWord"
			$N_MSI++
		}
	}
	"MSI mode enabled for $N_MSI supported devices. Restart required to take effect"
}

# Checks for IRQ conflicts
$check_irq=Read-Host "Do you want to check for IRQ conflicts? y/n: "
if ($do_all -or $check_irq -eq 'y') {
	"Checking for IRQ conflicts..."
	Get-CimInstance Win32_PNPAllocatedResource | Out-File -FilePath "IRQDump.txt"
	(Select-String -Path "IRQDump.txt" -Pattern "IRQNumber") -ireplace '.*IRQNumber = (\d+).*', '$1' | Out-File -FilePath IRQNumbers.txt
	$SharedIRQ=(Get-Content IRQNumbers.txt | Group-Object | Where-Object {$_.Count -gt 1 } | Select -ExpandProperty Name)
	if ($SharedIRQ.Length > 0) {
		"Alert: IRQ conflicts found at: $SharedIRQ"
		"This means that more than one device is sharing a physical interrupt line to the CPU, which *may* cause resource contention and degrade performance of those devices."
	}
	else {
		"No IRQ conflicts found"
	}
}

"PowerWash complete, a restart is recommended"
