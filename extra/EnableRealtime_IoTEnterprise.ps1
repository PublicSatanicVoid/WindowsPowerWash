$edition = (Get-WindowsEdition -online).Edition
if (-not ($edition -like "*IoTEnterprise*")) {
    "ERROR: Real-time features are only available on IoT Enterprise editions of Windows. Your edition is $edition."
    exit
}

$N_REALTIME_CORES = 2

function Get-SID() {
    return (New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([Security.Principal.SecurityIdentifier]).Value
}

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

function RunScriptAsSystem($Path, $ArgString) {
    Write-Host "  [Invoking task as SYSTEM..." -NoNewline

    # Adapted from https://github.com/mkellerm1n/Invoke-CommandAs/blob/master/Invoke-CommandAs/Private/Invoke-ScheduledTask.ps1
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "$Path $ArgString"
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Task = Register-ScheduledTask SystemLevelTask -Action $Action -Principal $Principal
    $Job = $Task | Start-ScheduledTask -AsJob -ErrorAction Stop
    $Job | Wait-Job | Remove-Job -Force -Confirm:$False
    While (($Task | Get-ScheduledtaskInfo).LastTaskResult -eq 267009) { Start-Sleep -Milliseconds 200 }
    $Task | Unregister-ScheduledTask -Confirm:$false
    Write-Host " Complete]"
}

if ("/ElevatedAction" -in $args) {
    if ("$(whoami)" -ne "nt authority\system") {
        ""
        "ERROR: Can only run /ElevatedAction features as SYSTEM."
        ""
        exit
    }


	$nameSpaceName="root\cimv2\mdm\dmmap"
    $className="MDM_WindowsIoT_SoftRealTimeProperties01"
    $obj = Get-CimInstance -Namespace $namespaceName -ClassName $className

    Add-Type -AssemblyName System.Web

    Set-CimInstance -CimInstance $obj
    $obj.SetRTCores = $N_REALTIME_CORES
    Set-CimInstance -CimInstance $obj
}
else {
    "Windows IoT Enterprise -- Enable Real-time Execution"
    ""
    "WARNING: This operation will dedicate $N_REALTIME_CORES cores to soft real-time applications."
    "WARNING: They will be unavailable for other use."
    ""
    "WARNING: Enabling real-time execution will DISABLE the audio service, diagnostics service,"
    "WARNING: Superfetch service, and Windows Update."
    ""
    "WARNING: This generally will NOT improve your system's performance! It will ONLY improve LATENCY"
    "WARNING: for processes/threads that are set to REALTIME priority and whose affinity matches the"
    "WARNING: CPU cores assigned to realtime execution. The rest of your system performance may suffer!"
    ""
    "Learn more: https://learn.microsoft.com/en-us/windows/iot/iot-enterprise/soft-real-time/soft-real-time"
    ""
    if ((Read-Host "Proceed with this operation? (y/n)") -ne "y") {
        ""
        "==================="
        "Operation canceled."
        "==================="
        ""
        exit
    }
}


"- Disabling idle power states..."
powercfg.exe /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR IdleDisable 1 | Out-Null
powercfg.exe /setactive SCHEME_CURRENT | Out-Null
"  (Done)"
""

"- Disabling DPS service..."
sc.exe stop dps | Out-Null
sc.exe config dps start=disabled | Out-Null
"  (Done)"
""

"- Disabling AudioSrv service..."
sc.exe stop Audiosrv | Out-Null
sc.exe config Audiosrv start=disabled | Out-Null
"  (Done)"
""

"- Disabling SysMain service..."
sc.exe stop SysMain | Out-Null
sc.exe config SysMain start=disabled | Out-Null
"  (Done)"
""

"- Disabling Windows Update..."
RegistryPut "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Key "DoNotConnectToWindowsUpdateInternetLocations" -Value 1 -VType "DWORD"
RegistryPut "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Key "DisableWindowsUpdateAccess" -Value 1 -VType "DWORD"
RegistryPut "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Key "WUServer" -Value " " -VType "String"
RegistryPut "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Key "WUStatusServer" -Value " " -VType "String"
RegistryPut "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Key "UpdateServiceUrlAlternate" -Value " " -VType "String"
RegistryPut "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Key "UseWUServer" -Value 1 -VType "DWORD"
sc.exe stop UsoSvc | Out-Null
sc.exe config UsoSvc start=disabled | Out-Null
sc.exe stop WaaSMedicSvc | Out-Null
RegistryPut "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Key "Start" -Value 4 -VType "DWORD"
sc.exe stop wuauserv | Out-Null
sc.exe config wuauserv start=disabled | Out-Null
"  (Done)"
""

"- Disabling threaded DPCs..."
RegistryPut "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" -Key "ThreadDpcEnable" -Value 0 -VType "DWORD"
"  (Done)"
""

Write-Host "- Dedicating top $N_REALTIME_CORES CPU cores to real-time applications..." -NoNewline
$scriptName = $MyInvocation.MyCommand.Name
RunScriptAsSystem -Path "$PSScriptRoot/$scriptName" -ArgString "/ElevatedAction"
"  (Done)"
""

""
"========================================================"
"The system is now configured for real-time applications."
"========================================================"
""
