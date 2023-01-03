#!/bin/bash

set -e

clear

BLACK='\e[30m'
RED='\e[31m'
GREEN='\e[92m'
YELLOW='\e[33m'
ORANGE='\e[93m'
BLUE='\e[34m'
PURPLE='\e[35m'
CYAN='\e[36m'
WHITE='\e[37m'
NC='\e[0m'
purpal='\033[35m'

echo -e "${ORANGE} "
echo ""
echo "   ▄█    █▄       ▄████████  ▄████████    ▄█   ▄█▄  ▄█  ███▄▄▄▄      ▄██████▄           ███      ▄██████▄   ▄██████▄   ▄█       ";
echo "  ███    ███     ███    ███ ███    ███   ███ ▄███▀ ███  ███▀▀▀██▄   ███    ███      ▀█████████▄ ███    ███ ███    ███ ███       ";
echo "  ███    ███     ███    ███ ███    █▀    ███▐██▀   ███▌ ███   ███   ███    █▀          ▀███▀▀██ ███    ███ ███    ███ ███       ";
echo " ▄███▄▄▄▄███▄▄   ███    ███ ███         ▄█████▀    ███▌ ███   ███  ▄███                 ███   ▀ ███    ███ ███    ███ ███       ";
echo "▀▀███▀▀▀▀███▀  ▀███████████ ███        ▀▀█████▄    ███▌ ███   ███ ▀▀███ ████▄           ███     ███    ███ ███    ███ ███       ";
echo "  ███    ███     ███    ███ ███    █▄    ███▐██▄   ███  ███   ███   ███    ███          ███     ███    ███ ███    ███ ███       ";
echo "  ███    ███     ███    ███ ███    ███   ███ ▀███▄ ███  ███   ███   ███    ███          ███     ███    ███ ███    ███ ███▌    ▄ ";
echo "  ███    █▀      ███    █▀  ████████▀    ███   ▀█▀ █▀    ▀█   █▀    ████████▀          ▄████▀    ▀██████▀   ▀██████▀  █████▄▄██ ";
echo "                                         ▀                                                                            ▀         ";

echo -e "${BLUE}                                    https://github.com/Z4nzu/hackingtool ${NC}"
echo -e "${RED}                                     [!] This Tool Must Run As ROOT [!]${NC}\n"
echo -e ${CYAN}                "Select Best Option : \n"
echo -e "${WHITE}              [1] Kali Linux / Parrot-Os (apt)"
echo -e "${WHITE}              [2] Arch Linux (pacman)" # added arch linux support because of feature request #231
echo -e "${WHITE}              [3] macOS"
echo -e "${WHITE}              [0] Exit "
echo -n -e "Z4nzu >> "
read choice
INSTALL_DIR="/usr/share/doc/hackingtool"
BIN_DIR="/usr/bin/"

if [ $choice == 3 ]; then
	INSTALL_DIR="/opt/hackingtool" # Fuck SIP & Apple in general (read more info: https://gist.github.com/Northernside/853f08e7ae1baa78bc2cf6737ecdcbc1)
fi

if [ $choice == 1 ] || [ $choice == 2 ] || [ $choice == 3 ]; then
	echo "[*] Checking Internet Connection .."
	wget -q --tries=10 --timeout=20 --spider https://google.com
	if [[ $? == 0 ]]; then
        echo -e ${BLUE}"[✔] Loading ... "
        if [ $choice == 1 ]; then
            sudo apt-get update -y && apt-get upgrade -y
            sudo apt-get install python3-pip -y
        elif [ $choice == 2 ]; then # added arch linux support because of feature request #231
            sudo pacman -Suy
            sudo pacman -S python-pip yay
        elif [ $choice == 3 ]; then
            sudo curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py # I prefer using homebrew, but there's only a python package, containing both python and pip and I don't know if we want to potentially overwrite an existing python installation from the user
            sudo python3 get-pip.py
        fi

	    echo "[✔] Checking directories..."
	    if [ -d "$INSTALL_DIR" ]; then
	        echo "[!] A Directory hackingtool Was Found.. Do You Want To Replace It ? [y/n]:" ;
	        read input
	        if [ "$input" = "y" ]; then
                sudo rm -R "$INSTALL_DIR"
	        else
	            exit
	        fi
	    fi

        echo "[✔] Installing ...\n";
        sudo git clone https://github.com/Z4nzu/hackingtool.git "$INSTALL_DIR";
        sudo echo "#!/bin/bash
        python3 $INSTALL_DIR/hackingtool.py" '${1+"$@"}' > hackingtool;
        sudo chmod +x hackingtool;
        if [ $choice != 3 ]; then
            sudo cp hackingtool /usr/bin/ && rm hackingtool;
        else
            sudo cp hackingtool $INSTALL_DIR/hackingtool && rm hackingtool;
            case $SHELL in
                */zsh)
                   echo "alias hackingtool=$INSTALL_DIR/hackingtool" >> ~/.zshrc
                   echo "[*] Please run 'source ~/.zshrc' to reload the shell configuration"
                   ;;
                */bash)
                   echo "alias hackingtool=$INSTALL_DIR/hackingtool" >> ~/.bashrc
                   echo "[*] Please run 'source ~/.bashrc' to reload the shell configuration"
                   ;;
                *)
                   echo "[!] Could not detect shell, therefore can't create an alias for the executable."
            esac
        fi

        echo "\n[✔] Trying to installing Requirements ..."
        if [ $choice == 1 ]; then
            sudo pip3 install lolcat boxes flask requests
            sudo apt-get install -y figlet
        elif [ $choice == 2 ]; then # added arch linux support because of feature request #231
            sudo pip3 install lolcat boxes flask requests
            yay -S boxes --noconfirm
            sudo pacman -S figlet
        fi

	else
		  echo -e $RED "Please Check Your Internet Connection ..!!"
	fi

    if [ -d "$INSTALL_DIR" ]; then
        echo "";
        echo "[✔] Successfuly Installed !!! \n\n";
        echo -e $ORANGE "       [+]+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[+]"
        echo            "       [+]                                                             [+]"
        echo -e $ORANGE "       [+]     ✔✔✔ Now Just Type In Terminal (hackingtool) ✔✔✔         [+]"
        echo            "       [+]                                                             [+]"
        echo -e $ORANGE "       [+]+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++[+]"
    else
        echo "[✘] Installation Failed !!! [✘]";
        exit
    fi
elif [ $choice == 0 ] && [ $choice != 1 ] && [ $choice != 2 ] && [ $choice != 3 ]; then # fixed the "./test.sh: line 107: [: asd: integer expression expected" when entering any invalid input containing letters
    echo -e $RED "[✘] THank Y0u !! [✘] "
    exit
else
    echo -e $RED "[!] Select Valid Option [!]"
fi
