@echo off

sc queryex UsoSvc | find "STATE" | find /v "RUNNING" > NUL && (
	reg delete HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v DoNotConnectToWindowsUpdateInternetLocations /f
	reg delete HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /f
	reg delete HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer /f
	reg delete HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUStatusServer /f
	reg delete HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer /f
	
	sc config UsoSvc start=delayed-auto > NUL
	sc start UsoSvc > NUL
		
	reg add HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc /v Start /t REG_DWORD /d 3 /f > NUL
	
	sc config wuauserv start=demand > NUL
	
	echo Windows Updates have been ENABLED
) || (
	reg add HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v DoNotConnectToWindowsUpdateInternetLocations /t REG_DWORD /d 1 /f
	reg add HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 1 /f
	reg add HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer /t REG_SZ /d " " /f
	reg add HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUStatusServer /t REG_SZ /d " " /f
	reg add HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v UpdateServiceUrlAlternative /t REG_SZ /d " " /f
	reg add HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer /t REG_DWORD /d 1 /f

	sc stop UsoSvc > NUL
	sc config UsoSvc start=disabled > NUL

	sc stop WaaSMedicSvc > NUL
	reg add HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc /v Start /t REG_DWORD /d 4 /f > NUL

	sc stop wuauserv > NUL
	sc config wuauserv start=disabled > NUL
	
	echo Windows Updates have been DISABLED
)

pause
