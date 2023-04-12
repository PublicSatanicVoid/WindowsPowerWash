# This file is needed so our Unattend file's command line stays within the character limit.

$GH_PUBLIC_REPO = "UniverseCraft/WindowsPowerWash"

curl -o PowerWash.ps1 https://raw.githubusercontent.com/$GH_PUBLIC_REPO/main/PowerWash.ps1
curl -o PowerWashSettings.json https://raw.githubusercontent.com/$GH_PUBLIC_REPO/main/PowerWashSettings.json
Set-ExecutionPolicy Unrestricted -Force -Confirm:$false
.\PowerWash.ps1 /config /noscans /is-unattend -Confirm:$false
