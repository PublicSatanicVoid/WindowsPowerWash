$gh_repo_id = "PublicSatanicVoid/WindowsPowerWash"

"Downloading sources from GitHub repo: $gh_repo_id"
curl -o .PowerWash.ps1 "https://raw.githubusercontent.com/$gh_repo_id/main/PowerWash.ps1"
Set-ExecutionPolicy Unrestricted -Force -Confirm:$false

""
"======================================================================================"
"                         MICROSOFT EDGE REMOVAL TOOL (MSERT)"
"======================================================================================"
" This script is a wrapper around the PowerWash tool and provides a standalone way"
" to quickly and completely remove Edge from your system."
""
" There are no guarantees that this will prevent *traces* of Edge from coming back"
" in an update, nor that Microsoft's tactics will not evolve and render this tool"
" obsolete."
""
" Warning - Make sure you have a web browser other than Edge installed, if you want"
" to have a web browser after removing Edge!"
""
" Note - All license terms and advisories from the PowerWash script also apply to this"
" tool."
"======================================================================================"
""
Read-Host "Press Enter to proceed, or Ctrl+C to cancel."
""

.\.PowerWash.ps1 /msert -Confirm:$false
Remove-Item ".PowerWash.ps1"
