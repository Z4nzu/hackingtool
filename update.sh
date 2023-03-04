#!/bin/bash

RED='\e[1;31m'
GREEN='\e[1;32m'
YELLOW='\e[1;33m'
BLUE='\e[1;34m'

echo "███████╗██╗  ██╗███╗   ██╗███████╗██╗   ██╗    ";
echo "╚══███╔╝██║  ██║████╗  ██║╚══███╔╝██║   ██║    ";
echo "  ███╔╝ ███████║██╔██╗ ██║  ███╔╝ ██║   ██║    ";
echo " ███╔╝  ╚════██║██║╚██╗██║ ███╔╝  ██║   ██║    ";
echo "███████╗     ██║██║ ╚████║███████╗╚██████╔╝    ";
echo "╚══════╝     ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝     ";
echo "                                               ";

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR]\e[0m This script must be run as root."
   exit 1
fi

install_dir="/usr/share/hackingtool"
# Change to the directory containing the install.sh script
cd $install_dir || { echo -e "${RED}[ERROR]\e[0m Could not change to directory containing install.sh."; exit 1; }
echo -e "${YELLOW}[*] Checking Internet Connection ..${NC}"
echo "";
if curl -s -m 10 https://www.google.com > /dev/null || curl -s -m 10 https://www.github.com > /dev/null; then
    echo -e "${GREEN}[✔] Internet connection is OK [✔]${NC}"
    echo ""
else
    echo -e "${RED}[✘] Please check your internet connection[✘]"
    echo ""
    exit 1
fi
echo -e "[*]Marking hackingtool directory as safe-directory"
git config --global --add safe.directory $install_dir
# Update the repository and the tool itself
echo -e "${BLUE}[INFO]\e[0m Updating repository and tool..."
if ! sudo git pull; then
    echo -e "${RED}[ERROR]\e[0m Failed to update repository or tool."
    exit 1
fi

# Re-run the installation script
echo -e "${GREEN}[INFO]\e[0m Running installation script..."
if ! sudo bash install.sh; then
    echo -e "${RED}[ERROR]\e[0m Failed to run installation script."
    exit 1
fi

echo -e "${GREEN}[SUCCESS]\e[0m Tool updated successfully."
