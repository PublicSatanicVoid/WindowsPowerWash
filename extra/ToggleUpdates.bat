@echo off

sc queryex UsoSvc | find "STATE" | find /v "RUNNING" > NUL && (
	sc config UsoSvc start=delayed-auto > NUL
	sc start UsoSvc > NUL
		
	reg add HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc /v Start /t REG_DWORD /d 3 /f > NUL
	
	sc config wuauserv start=demand > NUL
	
	echo Windows Updates have been ENABLED
) || (
	sc stop UsoSvc > NUL
	sc config UsoSvc start=disabled > NUL

	sc stop WaaSMedicSvc > NUL
	reg add HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc /v Start /t REG_DWORD /d 4 /f > NUL

	sc stop wuauserv > NUL
	sc config wuauserv start=disabled > NUL
	
	echo Windows Updates have been DISABLED
)

pause
