# This file is needed so our Unattend file's command line stays within the character limit.

"PowerWash initializing..."

$unattend = Get-Content "C:\Windows\Panther\unattend.xml"
$m = $unattend | Select-String -Pattern "githubusercontent\.com\/([a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+)\/main"
$gh_repo_id = $m.Matches.Groups[1].Value

"Downloading from GitHub repo: $gh_repo_id"
curl -o PowerWash.ps1 https://raw.githubusercontent.com/$gh_repo_id/main/PowerWash.ps1
curl -o PowerWashSettings.json https://raw.githubusercontent.com/$gh_repo_id/main/PowerWashSettings.json
Set-ExecutionPolicy Unrestricted -Force -Confirm:$false

"Bootstrapping into PowerWash..."
.\PowerWash.ps1 /config /noscans /is-unattend -Confirm:$false
