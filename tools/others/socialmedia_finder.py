# coding=utf-8
import os
import subprocess

from core import HackingTool
from core import HackingToolsCollection


class FacialFind(HackingTool):
    TITLE = "Find SocialMedia By Facial Recognation System"
    DESCRIPTION = "A Social Media Mapping Tool that correlates profiles\n " \
                  "via facial recognition across different sites."
    INSTALL_COMMANDS = [
        "sudo apt install -y software-properties-common",
        "sudo add-apt-repository ppa:mozillateam/firefox-next && sudo apt update && sudo apt upgrade",
        "sudo git clone https://github.com/Greenwolf/social_mapper.git",
        "sudo apt install -y build-essential cmake libgtk-3-dev libboost-all-dev",
        "cd social_mapper/setup",
        "sudo python3 -m pip install --no-cache-dir -r requirements.txt",
        'echo "[!]Now You have To do some Manually\n'
        '[!] Install the Geckodriver for your operating system\n'
        '[!] Copy & Paste Link And Download File As System Configuration\n'
        '[#] https://github.com/mozilla/geckodriver/releases\n'
        '[!!] On Linux you can place it in /usr/bin "| boxes | lolcat'
    ]
    PROJECT_URL = "https://github.com/Greenwolf/social_mapper"

    def run(self):
        os.system("cd social_mapper/setup")
        os.system("sudo python social_mapper.py -h")
        print("""\033[95m 
                You have to set Username and password of your AC Or Any Fack Account
                [#] Type in Terminal nano social_mapper.py
        """)
        os.system(
            'echo "python social_mapper.py -f [<imageFoldername>] -i [<imgFolderPath>] -m fast [<AcName>] -fb -tw"| boxes | lolcat')


class FindUser(HackingTool):
    TITLE = "Find SocialMedia By UserName"
    DESCRIPTION = "Find usernames across over 75 social networks"
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/xHak9x/finduser.git",
        "cd finduser && sudo chmod +x finduser.sh"
    ]
    RUN_COMMANDS = ["cd finduser && sudo bash finduser.sh"]
    PROJECT_URL = "https://github.com/xHak9x/finduser"


class Sherlock(HackingTool):
    TITLE = "Sherlock"
    DESCRIPTION = "Hunt down social media accounts by username across social networks \n " \
                  "For More Usage \n" \
                  "\t >>python3 sherlock --help"
    INSTALL_COMMANDS = [
        "git clone https://github.com/sherlock-project/sherlock.git",
        "cd sherlock;sudo python3 -m pip install -r requirements.txt"
    ]
    PROJECT_URL = "https://github.com/sherlock-project/sherlock"

    def run(self):
        name = input("Enter Username >> ")
        os.chdir('sherlock')
        subprocess.run(["sudo", "python3", "sherlock", f"{name}"])


class SocialScan(HackingTool):
    TITLE = "SocialScan | Username or Email"
    DESCRIPTION = "Check email address and username availability on online " \
                  "platforms with 100% accuracy"
    INSTALL_COMMANDS = ["sudo pip install socialscan"]
    PROJECT_URL = "https://github.com/iojw/socialscan"

    def run(self):
        name = input(
            "Enter Username or Emailid (if both then please space between email & username) >> ")
        subprocess.run(["sudo", "socialscan", f"{name}"])


class SocialMediaFinderTools(HackingToolsCollection):
    TITLE = "SocialMedia Finder"
    TOOLS = [
        FacialFind(),
        FindUser(),
        Sherlock(),
        SocialScan()
    ]
