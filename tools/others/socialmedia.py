# coding=utf-8
import os
import subprocess

from core import HackingTool
from core import HackingToolsCollection
from core.utils import run_command


class InstaBrute(HackingTool):
    TITLE = "Instagram Attack"
    DESCRIPTION = "Brute force attack against Instagram"
    INSTALL_COMMANDS = [
        dict(
            cmd="sudo git clone https://github.com/chinoogawa/instaBrute.git"),
        dict(cmd="sudo pip install -r requirements.txt", cwd="instaBrute")
    ]
    PROJECT_URL = "https://github.com/chinoogawa/instaBrute"

    def run(self):
        name = input("Enter Username >> ")
        wordlist = input("Enter wordword list >> ")
        run_command(
            f"sudo python instaBrute.py -u {name} -d {wordlist}",
            cwd="instaBrute",
        )


class BruteForce(HackingTool):
    TITLE = "AllinOne SocialMedia Attack"
    DESCRIPTION = "Brute_Force_Attack Gmail Hotmail Twitter Facebook Netflix \n" \
                  "[!] python3 Brute_Force.py -g <Account@gmail.com> -l <File_list>"
    INSTALL_COMMANDS = [
        dict(
            cmd="sudo git clone https://github.com/Matrix07ksa/Brute_Force.git"
        ),
        dict(
            cmd="sudo pip3 install proxylist;pip3 install mechanize",
            cwd="Brute_Force",
        )
    ]
    RUN_COMMANDS = [dict(cmd="python3 Brute_Force.py -h", cwd="Brute_Force")]
    PROJECT_URL = "https://github.com/Matrix07ksa/Brute_Force"


class Faceshell(HackingTool):
    TITLE = "Facebook Attack"
    DESCRIPTION = "Facebook BruteForcer"
    INSTALL_COMMANDS = [
        dict(
            cmd="sudo git clone https://github.com/Matrix07ksa/Brute_Force.git"
        ),
        dict(
            cmd="sudo pip3 install proxylist;pip3 install mechanize",
            cwd="Brute_Force",
        )
    ]
    PROJECT_URL = "https://github.com/Matrix07ksa/Brute_Force"

    def run(self):
        name = input("Enter Username >> ")
        wordlist = input("Enter Wordlist >> ")
        run_command(
            f"python3 Brute_Force.py -f {name} -l {wordlist}",
            cwd="Brute_Force",
        )


class AppCheck(HackingTool):
    TITLE = "Application Checker"
    DESCRIPTION = "Tool to check if an app is installed on the target device through a link."
    INSTALL_COMMANDS = [
        dict(
            cmd="sudo git clone https://github.com/jakuta-tech/underhanded.git"
        ),
        dict(cmd="sudo chmod +x underhanded.sh", cwd="underhanded")
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo bash underhanded.sh", cwd="underhanded"),
    ]
    PROJECT_URL = "https://github.com/jakuta-tech/underhanded"


class SocialMediaBruteforceTools(HackingToolsCollection):
    TITLE = "SocialMedia Bruteforce"
    TOOLS = [InstaBrute(), BruteForce(), Faceshell(), AppCheck()]
