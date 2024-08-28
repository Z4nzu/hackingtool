@echo off
setlocal enabledelayedexpansion

REM Check if WSL is installed
wsl --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing WSL...
    wsl --install
    echo WSL installation complete. Please restart your computer and run this script again.
    exit /b
)

REM Check if Ubuntu is installed
wsl -l -v | findstr /i "Ubuntu" >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing Ubuntu...
	
REM Display instructions for the user
echo.
echo The following commands will install and run the Hackingtool in WSL:
echo.
echo "  sudo apt update && sudo apt upgrade -y && sudo apt install -y git docker.io docker-compose && rm -rf hackingtool && git clone  https://github.com/Z4nzu/hackingtool.git && cd hackingtool && chmod -R 755 . && sudo bash install.sh && sudo hackingtool  "
echo.
echo Please copy the above command and paste (or right click) into the Ubuntu terminal. [Without quotes]
echo.
	
    wsl --install -d Ubuntu
    echo Ubuntu installation complete. Please restart your computer and run this script again.
    exit /b
)

pause
