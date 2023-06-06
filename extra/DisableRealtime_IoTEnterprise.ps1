$edition = (Get-WindowsEdition -online).Edition
if (-not ($edition -like "*IoTEnterprise*")) {
    "ERROR: Real-time features are only available on IoT Enterprise editions of Windows. Your edition is $edition."
    exit
}

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
    $obj.SetRTCores = 0
    Set-CimInstance -CimInstance $obj
}
else {
    "Windows IoT Enterprise -- Disable Real-time Execution"
    ""
    "WARNING: This operation will release $N_REALTIME_CORES cores from soft real-time applications."
    "WARNING: They will now be available for other use."
    ""
    "WARNING: This will DISABLE IoT Enterprise's Soft Real-Time features."
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


"- Enabling idle power states..."
powercfg.exe /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR IdleDisable 0 | Out-Null
powercfg.exe /setactive SCHEME_CURRENT | Out-Null
"  (Done)"
""

"- Enabling DPS service..."
sc.exe config dps start=auto | Out-Null
sc.exe start dps | Out-Null
"  (Done)"
""

"- Enabling AudioSrv service..."
sc.exe config Audiosrv start=auto | Out-Null
sc.exe start Audiosrv | Out-Null
"  (Done)"
""

"- Enabling SysMain service..."
sc.exe config SysMain start=auto | Out-Null
sc.exe start SysMain | Out-Null
"  (Done)"
""

"- Enabling Windows Update..."
Remove-ItemProperty -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -EA SilentlyContinue
Remove-ItemProperty -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -EA SilentlyContinue
Remove-ItemProperty -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -EA SilentlyContinue
Remove-ItemProperty -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -EA SilentlyContinue
Remove-ItemProperty -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "UpdateServiceUrlAlternative" -EA SilentlyContinue
Remove-ItemProperty -Force -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -EA SilentlyContinue
sc.exe config UsoSvc start=delayed-auto | Out-Null
sc.exe start UsoSvc | Out-Null
RegistryPut "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Key "Start" -Value 3 -VType "DWORD"
sc.exe config wuauserv start=demand | Out-Null
"  (Done)"
""

"- Enabling threaded DPCs..."
RegistryPut "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" -Key "ThreadDpcEnable" -Value 1 -VType "DWORD"
"  (Done)"
""

Write-Host "- Releasing all CPU cores from real-time applications..." -NoNewline
$scriptName = $MyInvocation.MyCommand.Name
RunScriptAsSystem -Path "$PSScriptRoot/$scriptName" -ArgString "/ElevatedAction"
"  (Done)"
""

""
"=============================================================="
"The system is no longer configured for real-time applications."
"=============================================================="
""
