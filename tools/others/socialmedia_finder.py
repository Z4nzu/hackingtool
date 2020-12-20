# coding=utf-8
import os
import subprocess

from core import HackingTool
from core import HackingToolsCollection
from core.utils import run_command


class FacialFind(HackingTool):
    TITLE = "Find SocialMedia By Facial Recognation System"
    DESCRIPTION = "A Social Media Mapping Tool that correlates profiles\n " \
                  "via facial recognition across different sites."
    INSTALL_COMMANDS = [
        dict(cmd="sudo apt install -y software-properties-common"),
        dict(cmd="sudo add-apt-repository ppa:mozillateam/firefox-next"),
        dict(cmd="sudo apt update"),
        dict(cmd="sudo apt upgrade"),
        dict(
            cmd="sudo git clone https://github.com/Greenwolf/social_mapper.git"
        ),
        dict(
            cmd=
            "sudo apt install -y build-essential cmake libgtk-3-dev libboost-all-dev"
        ),
        dict(
            cmd=
            "sudo python3 -m pip install --no-cache-dir -r requirements.txt",
            cwd="social_mapper/setup",
        ),
        dict(cmd='''
            echo "[!]Now You have To do some Manually\n
            [!] Install the Geckodriver for your operating system\n
            [!] Copy & Paste Link And Download File As System Configuration\n
            [#] https://github.com/mozilla/geckodriver/releases\n
            [!!] On Linux you can place it in /usr/bin "| boxes | lolcat
            ''')
    ]
    PROJECT_URL = "https://github.com/Greenwolf/social_mapper"

    def run(self):
        run_command("sudo python social_mapper.py -h",
                    cwd="social_mapper/setup")
        print("""\033[95m 
                You have to set Username and password of your AC Or Any Fack Account
                [#] Type in Terminal nano social_mapper.py
        """)
        run_command(
            'echo "python social_mapper.py -f [<imageFoldername>] -i [<imgFolderPath>] -m fast [<AcName>] -fb -tw"| boxes | lolcat'
        )


class FindUser(HackingTool):
    TITLE = "Find SocialMedia By UserName"
    DESCRIPTION = "Find usernames across over 75 social networks"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/xHak9x/finduser.git"),
        dict(cmd="sudo chmod +x finduser.sh", cwd="finduser")
    ]
    RUN_COMMANDS = [dict(cmd="sudo bash finduser.sh", cwd="finduser")]
    PROJECT_URL = "https://github.com/xHak9x/finduser"


class Sherlock(HackingTool):
    TITLE = "Sherlock"
    DESCRIPTION = "Hunt down social media accounts by username across social networks \n " \
                  "For More Usege \n" \
                  "\t >>python3 sherlock --help"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/sherlock-project/sherlock.git"),
        dict(cmd="sudo python3 -m pip install -r requirements.txt",
             cwd="sherlock")
    ]
    PROJECT_URL = "https://github.com/sherlock-project/sherlock"

    def run(self):
        name = input("Enter Username >> ")
        os.system("cd sherlock;")
        subprocess.run(["sudo", "python3", "sherlock", f"{name}"])


class SocialScan(HackingTool):
    TITLE = "SocialScan | Username or Email"
    DESCRIPTION = "Check email address and username availability on online " \
                  "platforms with 100% accuracy"
    INSTALL_COMMANDS = ["sudo pip install socialscan"]
    PROJECT_URL = "https://github.com/iojw/socialscan"

    def run(self):
        name = input(
            "Enter Username or Emailid (if both then please space between email & username) >> "
        )
        run_command(f"sudo socialscan {name}", cwd="sherlock")


class SocialMediaFinderTools(HackingToolsCollection):
    TITLE = "SocialMedia Finder"
    TOOLS = [FacialFind(), FindUser(), Sherlock(), SocialScan()]
