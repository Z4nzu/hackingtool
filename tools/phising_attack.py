# coding=utf-8
import os

from core import HackingTool
from core import HackingToolsCollection
from core.utils import run_command, get_go_path


class Setoolkit(HackingTool):
    TITLE = "Setoolkit"
    DESCRIPTION = "The Social-Engineer Toolkit is an open-source penetration\n" \
                  "testing framework designed for social engineering"
    INSTALL_COMMANDS = [
        dict(
            cmd=
            "git clone https://github.com/trustedsec/social-engineer-toolkit.git"
        ),
        dict(cmd="sudo python3 setup.py", cwd="social-engineer-toolkit"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo setoolkit"),
    ]
    PROJECT_URL = "https://github.com/trustedsec/social-engineer-toolkit"


class SocialFish(HackingTool):
    TITLE = "SocialFish"
    DESCRIPTION = "Automated Phishing Tool & Information Collector NOTE: username is 'root' and password is 'pass'"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/UndeadSec/SocialFish.git"),
        dict(cmd="sudo apt-get install python3 python3-pip python3-dev -y"),
        dict(cmd="sudo python3 -m pip install -r requirements.txt",
             cwd="SocialFish"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo python3 SocialFish.py root pass", cwd="SocialFish"),
    ]
    PROJECT_URL = "https://github.com/UndeadSec/SocialFish"


class HiddenEye(HackingTool):
    TITLE = "HiddenEye"
    DESCRIPTION = "Modern Phishing Tool With Advanced Functionality And " \
                  "Multiple Tunnelling Services \n" \
                  "\t [!]https://github.com/DarkSecDevelopers/HiddenEye"
    INSTALL_COMMANDS = [
        dict(
            cmd=
            "sudo git clone https://github.com/DarkSecDevelopers/HiddenEye.git"
        ),
        dict(cmd="sudo chmod 777 HiddenEye"),
        dict(
            cmd="sudo pip3 install -r requirements.txt",
            cwd="HiddenEye",
        ),
        dict(
            cmd="sudo pip3 install requests",
            cwd="HiddenEye",
        ),
        dict(
            cmd="pip3 install pyngrok",
            cwd="HiddenEye",
        ),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo python3 HiddenEye.py", cwd="HiddenEye"),
    ]
    PROJECT_URL = "https://github.com/DarkSecDevelopers/HiddenEye"


class Evilginx2(HackingTool):
    TITLE = "Evilginx2"
    DESCRIPTION = "evilginx2 is a man-in-the-middle attack framework used " \
                  "for phishing login credentials along with session cookies,\n" \
                  "which in turn allows to bypass 2-factor authentication protection.\n\n\t " \
                  "[+]Make sure you have installed GO of version at least 1.14.0 \n" \
                  "[+]After installation, add this to your ~/.profile, assuming that you installed GO in /usr/local/go\n\t " \
                  "[+]export GOPATH=$HOME/go \n " \
                  "[+]export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin \n" \
                  "[+]Then load it with source ~/.profiles."
    INSTALL_COMMANDS = [
        dict(cmd="sudo apt-get install git make"),
        dict(cmd="go get -u github.com/kgretzky/evilginx2"),
        dict(
            cmd="make",
            cwd=f"${get_go_path()}/src/github.com/kgretzky/evilginx2",
        ),
        dict(
            cmd="sudo make install",
            cwd=f"${get_go_path()}/src/github.com/kgretzky/evilginx2",
        ),
        dict(
            cmd="sudo evilginx",
            cwd=f"${get_go_path()}/src/github.com/kgretzky/evilginx2",
        ),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo evilginx"),
    ]
    PROJECT_URL = "https://github.com/kgretzky/evilginx2"


class ISeeYou(HackingTool):
    TITLE = "I-See_You(Get Location using phishing attack)"
    DESCRIPTION = "[!] ISeeYou is a tool to find Exact Location of Victom By" \
                  " User SocialEngineering or Phishing Engagment..\n" \
                  "[!] Users can expose their local servers to the Internet " \
                  "and decode the location coordinates by looking at the log file"
    INSTALL_COMMANDS = [
        dict(
            cmd="sudo git clone https://github.com/Viralmaniar/I-See-You.git"),
        dict(cmd="sudo chmod u+x ISeeYou.sh", cwd="I-See-You"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo bash ISeeYou.sh", cwd="I-See-You"),
    ]
    PROJECT_URL = "https://github.com/Viralmaniar/I-See-You"


class SayCheese(HackingTool):
    TITLE = "SayCheese (Grab target's Webcam Shots)"
    DESCRIPTION = "Take webcam shots from target just sending a malicious link"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/hangetzzu/saycheese"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo bash saycheese.sh", cwd="saycheese"),
    ]
    PROJECT_URL = "https://github.com/hangetzzu/saycheese"


class QRJacking(HackingTool):
    TITLE = "QR Code Jacking"
    DESCRIPTION = "QR Code Jacking (Any Website)"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/cryptedwolf/ohmyqr.git"),
        dict(cmd="sudo apt-get -y install scrot"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo bash ohmyqr.sh", cwd="ohmyqr"),
    ]
    PROJECT_URL = "https://github.com/cryptedwolf/ohmyqr"


class ShellPhish(HackingTool):
    TITLE = "ShellPhish"
    DESCRIPTION = "Fhishing Tool for 18 social media"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/An0nUD4Y/shellphish.git"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo bash shellphish.sh", cwd="shellphish"),
    ]
    PROJECT_URL = "https://github.com/An0nUD4Y/shellphish"


class BlackPhish(HackingTool):
    TITLE = "BlackPhish"
    INSTALL_COMMANDS = [
        dict(
            cmd="sudo git clone https://github.com/iinc0gnit0/BlackPhish.git"),
        dict(cmd="sudo bash install.sh", cwd="BlackPhish"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo python3 blackphish.py", cwd="BlackPhish"),
    ]
    PROJECT_URL = "https://github.com/iinc0gnit0/BlackPhish"

    def __init__(self):
        super(BlackPhish, self).__init__([('Update', self.update)])

    def update(self):
        run_command("sudo bash update.sh", cwd="BlackPhish")


class PhishingAttackTools(HackingToolsCollection):
    TITLE = "Phishing attack tools"
    TOOLS = [
        Setoolkit(),
        SocialFish(),
        HiddenEye(),
        Evilginx2(),
        ISeeYou(),
        SayCheese(),
        QRJacking(),
        ShellPhish(),
        BlackPhish()
    ]
