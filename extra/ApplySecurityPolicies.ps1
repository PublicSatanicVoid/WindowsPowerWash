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

    "$home" | Out-File -FilePath "C:\.PowerWashHome.tmp" -Force -NoNewline
    (Get-LocalUser -Name $env:USERNAME).Sid.Value | Out-File -FilePath "C:\.PowerWashSID.tmp" -Force -NoNewline

    # Adapted from https://github.com/mkellerm1n/Invoke-CommandAs/blob/master/Invoke-CommandAs/Private/Invoke-ScheduledTask.ps1
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "$Path $ArgString"
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Task = Register-ScheduledTask PowerWashSystemTask -Action $Action -Principal $Principal
    $Job = $Task | Start-ScheduledTask -AsJob -ErrorAction Stop
    $Job | Wait-Job | Remove-Job -Force -Confirm:$False
    While (($Task | Get-ScheduledtaskInfo).LastTaskResult -eq 267009) { Start-Sleep -Milliseconds 200 }
    $Task | Unregister-ScheduledTask -Confirm:$false
    Write-Host " Complete]"

    Remove-Item -Path "C:\.PowerWashHome.tmp"
    Remove-Item -Path "C:\.PowerWashSID.tmp"
}

if ("/ApplySecurityPolicy" -in $args) {
	RegistryPut "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Key "EnableNetworkProtection" -Value 1 -VType "DWORD"
	RegistryPut "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Key "EnableControlledFolderAccess" -Value 1 -VType "DWORD"
	RegistryPut "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Key "ExploitGuard_ASR_Rules" -Value 1 -VType "DWORD"
	$asr_guids = @(
		"26190899-1602-49e8-8b27-eb1d0a1ce869",
		"3b576869-a4ec-4529-8536-b80a7769e899",
		"56a863a9-875e-4185-98a7-b882c64b5ce5",
		"5beb7efe-fd9a-4556-801d-275e5ffc04cc",
		"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
		"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
		"92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
		"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
		"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
		"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
		"c1db55ab-c21a-4637-bb3f-a12568109d35",
		"d3e037e1-3eb8-44c8-a917-57927947596d",
		"e6db77e5-3df2-4cf1-b95a-636979351e5b"
	)
	$asr_guids | ForEach-Object {
		RegistryPut "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Key "$_" -Value 1 -VType "String"
	}
	
	RegistryPut "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Key "DisableRemovableDriveScanning" -Value 0 -VType "DWORD"
	
	RegistryPut "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Key "RestrictAnonymous" -Value 1 -VType "DWORD"
	RegistryPut "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Key "LmCompatibilityLevel" -Value 5 -VType "DWORD"
	RegistryPut "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Key "RunAsPPL" -Value 1 -VType "DWORD"
	
	RegistryPut "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext" -Key "VersionCheckEnabled" -Value 1 -VType "DWORD"
	RegistryPut "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Key "EnumerateAdministrators" -Value 0 -VType "DWORD"
	RegistryPut "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Key "NoAutorun" -Value 1 -VType "DWORD"
	RegistryPut "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Key "NoDriveTypeAutoRun" -Value 255 -VType "DWORD"
	
	RegistryPut "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Key "AllowAppHVSI_ProviderSet" -Value 3 -VType "DWORD"
	
	RegistryPut "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Key "RequireSecuritySignature" -Value 1 -VType "DWORD"
	RegistryPut "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Key "DisableIPSourceRouting" -Value 2 -VType "DWORD"
	RegistryPut "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Key "DisableIPSourceRouting" -Value 2 -VType "DWORD"
	
	RegistryPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Key "AllowBasic" -Value 0 -VType "DWORD"
	RegistryPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Key "AllowBasic" -Value 0 -VType "DWORD"
	
	RegistryPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Key "NoAutoplayfornonVolume" -Value 1 -VType "DWORD"
	
	RegistryPut "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Key "UseAdvancedStartup" -Value 1 -VType "DWORD"
	RegistryPut "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Key "MinimumPIN" -Value 6 -VType "DWORD"
	
	RegistryPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Key "NC_ShowSharedAccessUI" -Value 0 -VType "DWORD"
	RegistryPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Key "NC_StdDomainUserSetLocation" -Value 1 -VType "DWORD"
	
	RegistryPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "UserAuthentication" -Value 1 -VType "DWORD"
	
	RegistryPut "HKLM:\Software\Policies\Microsoft\Tpm" -Key "StandardUserAuthorizationFailureTotalThreshold" -Value 10 -VType "DWORD"
	
	RegistryPut "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Key "fAllowToGetHelp" -Value 0 -VType "DWORD"
	RegistryPut "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download" -Key "RunInvalidSignatures" -Value 0 -VType "DWORD"

	RegistryPut "HKLM:\SOFTWARE\Policies\Google\Chrome" -Key "BlockThirdPartyCookies" -Value 1 -VType "DWORD"
	RegistryPut "HKLM:\SOFTWARE\Policies\Google\Chrome" -Key "BackgroundModeEnabled" -Value 0 -VType "DWORD"
}
else {
	$scriptName = $MyInvocation.MyCommand.Name
	RunScriptAsSystem -Path "$PSScriptRoot/$scriptName" -ArgString "/Elevated /ApplySecurityPolicy"
}
