@echo OFF

echo "This utility will modify your Windows installation media to automatically run PowerWash when Windows setup completes."
echo "This will not change your local (active) Windows installation."
echo ""
echo "This assumes that:"
echo "1) You have created Windows installation media and it is mounted on your computer"
echo "2) You have forked (and probably modified) the PowerWash repository on GitHub"
echo "3) That repository has an unattend.xml file in the root of the main (default) branch"
echo ""
echo "If you have not yet done these steps, please follow the instructions at"
echo "  https://github.com/UniverseCraft/WindowsPowerWash/tree/main/USAGE_DEPLOYMENT.md"
echo "before continuing."

set /p drive_letter="Enter the drive letter of the installation media (eg F): "
set /p repo_id="Enter your repository identifier (eg AwesomeUser/AutoPowerWash): "

mkdir %drive_letter%:\sources\$OEM$\$$\Panther
curl -o %drive_letter%:\sources\$OEM$\$$\Panther\unattend.xml https://github.com/%repo_id%/tree/main/unattend.xml

echo "That's all! Your USB drive %drive_letter%: will now run PowerWash along with the Windows installation."
