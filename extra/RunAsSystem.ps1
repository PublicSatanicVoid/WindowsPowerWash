function RunMeAsSystem() {
	# TODO: Put PowerShell code to run as SYSTEM in here
}


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

function RunScriptAsSystem($Path, $ArgString) {
    Write-Host "  [Invoking task as SYSTEM..." -NoNewline

    "$home" | Out-File -FilePath "C:\.SystemTaskUserHome.tmp" -Force -NoNewline
    (Get-LocalUser -Name $env:USERNAME).Sid.Value | Out-File -FilePath "C:\.SystemTaskUserSID.tmp" -Force -NoNewline

    # Adapted from https://github.com/mkellerm1n/Invoke-CommandAs/blob/master/Invoke-CommandAs/Private/Invoke-ScheduledTask.ps1
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "$Path $ArgString"
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Task = Register-ScheduledTask SystemLevelTask -Action $Action -Principal $Principal
    $Job = $Task | Start-ScheduledTask -AsJob -ErrorAction Stop
    $Job | Wait-Job | Remove-Job -Force -Confirm:$False
    While (($Task | Get-ScheduledtaskInfo).LastTaskResult -eq 267009) { Start-Sleep -Milliseconds 200 }
    $Task | Unregister-ScheduledTask -Confirm:$false
    Write-Host " Complete]"

    Remove-Item -Path "C:\.SystemTaskUserHome.tmp"
    Remove-Item -Path "C:\.SystemTaskUserSID.tmp"
}

if ("/ElevatedAction" -in $args) {
    if ("$(whoami)" -ne "nt authority\system") {
        ""
        "ERROR: Can only run /ElevatedAction features as SYSTEM."
        ""
        exit
    }

    $UserHome = Get-Content "C:\.SystemTaskUserHome.tmp"
    $UserSID = Get-Content "C:\.SystemTaskUserSID.tmp"
    $HKCU = "Registry::HKEY_USERS\$UserSID"  # SYSTEM user's HKCU is not the script user's HKCU	

	RunMeAsSystem
}


### BOOTSTRAP ###
$scriptName = $MyInvocation.MyCommand.Name
RunScriptAsSystem -Path "$PSScriptRoot/$scriptName" -ArgString "/ElevatedAction"
