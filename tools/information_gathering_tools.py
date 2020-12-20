# coding=utf-8
import os
import socket
import subprocess
import webbrowser

from core import HackingTool
from core import HackingToolsCollection
from core import clear_screen
from core.utils import run_command


class NMAP(HackingTool):
    TITLE = "Network Map (nmap)"
    DESCRIPTION = "Free and open source utility for network discovery and security auditing"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/nmap/nmap.git"),
        dict(cmd="sudo chmod -R 755 nmap", cwd="nmap"),
        dict(cmd="sudo ./configure", cwd="nmap"),
        dict(cmd="make", cwd="nmap"),
        dict(cmd="sudo make install", cwd="nmap"),
    ]
    PROJECT_URL = "https://github.com/nmap/nmap"

    def __init__(self):
        super(NMAP, self).__init__(runnable=False)


class Dracnmap(HackingTool):
    TITLE = "Dracnmap"
    DESCRIPTION = "Dracnmap is an open source program which is using to \n" \
                  "exploit the network and gathering information with nmap help."
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/Screetsec/Dracnmap.git"),
        dict(cmd="chmod +x dracnmap-v2.2-dracOs.sh dracnmap-v2.2.sh", cwd="Dracnmap")
    ]
    RUN_COMMANDS = ["sudo ./dracnmap-v2.2.sh"]
    PROJECT_URL = "https://github.com/Screetsec/Dracnmap"

    def __init__(self):
        super(Dracnmap, self).__init__(runnable=False)


class PortScan(HackingTool):
    TITLE = "Port scanning"

    def __init__(self):
        super(PortScan, self).__init__(installable=False)

    def run(self):
        clear_screen()
        target = input('Select a Target IP: ')
        run_command(f"sudo nmap -O -Pn {target}")


class Host2IP(HackingTool):
    TITLE = "Host to IP "

    def __init__(self):
        super(Host2IP, self).__init__(installable=False)

    def run(self):
        clear_screen()
        host = input("Enter host name (e.g. www.google.com):-  ")
        ips = socket.gethostbyname(host)
        print(ips)


class XeroSploit(HackingTool):
    TITLE = "Xerosploit"
    DESCRIPTION = "Xerosploit is a penetration testing toolkit whose goal is to perform\n" \
                  "man-in-the-middle attacks for testing purposes"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/LionSec/xerosploit.git"),
        dict(cmd="sudo python install.py", cwd="xerosploit")
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo xerosploit"),
    ]
    PROJECT_URL = "https://github.com/LionSec/xerosploit"


class RedHawk(HackingTool):
    TITLE = "RED HAWK (All In One Scanning)"
    DESCRIPTION = "All in one tool for Information Gathering and Vulnerability Scanning."
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/Tuhinshubhra/RED_HAWK.git")
    ]
    RUN_COMMANDS = [
        dict(cmd="php rhawk.php", cwd="RED_HAWK"),
    ]
    PROJECT_URL = "https://github.com/Tuhinshubhra/RED_HAWK"


class ReconSpider(HackingTool):
    TITLE = "ReconSpider(For All Scaning)"
    DESCRIPTION = "ReconSpider is most Advanced Open Source Intelligence (OSINT)" \
                  " Framework for scanning IP Address, Emails, \n" \
                  "Websites, Organizations and find out information from" \
                  " different sources.\n"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/bhavsec/reconspider.git"),
        dict(cmd="sudo apt install python3 python3-pip"),
        dict(cmd="sudo python3 setup.py install", cwd="reconspider"),
    ]
    PROJECT_URL = "https://github.com/bhavsec/reconspider"

    def __init__(self):
        super(ReconSpider, self).__init__(runnable=False)


class IsItDown(HackingTool):
    TITLE = "IsItDown (Check Website Down/Up)"
    DESCRIPTION = "Check Website Is Online or Not"

    def __init__(self):
        super(IsItDown, self).__init__([('Open', self.open)],
                                       installable=False,
                                       runnable=False)

    def open(self):
        webbrowser.open_new_tab("https://www.isitdownrightnow.com/")


class Infoga(HackingTool):
    TITLE = "Infoga - Email OSINT"
    DESCRIPTION = "Infoga is a tool gathering email accounts informations\n" \
                  "(ip, hostname, country,...) from different public source"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/m4ll0k/Infoga.git"),
        dict(cmd="sudo python setup.py install", cwd="infoga"),
    ]
    RUN_COMMANDS = [
        dict(cmd="python infoga.py", cwd="infoga"),
    ]
    PROJECT_URL = "https://github.com/m4ll0k/Infoga"


class ReconDog(HackingTool):
    TITLE = "ReconDog"
    DESCRIPTION = "ReconDog Information Gathering Suite"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/s0md3v/ReconDog.git"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo python dog", cwd="ReconDog"),
    ]
    PROJECT_URL = "https://github.com/s0md3v/ReconDog"


class Striker(HackingTool):
    TITLE = "Striker"
    DESCRIPTION = "Recon & Vulnerability Scanning Suite"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/s0md3v/Striker.git"),
        dict(cmd="pip3 install -r requirements.txt", cwd="Striker")
    ]
    PROJECT_URL = "https://github.com/s0md3v/Striker"

    def run(self):
        site = input("Enter Site Name (example.com) >> ")
        run_command(f"sudo python3 striker.py {site}", cwd="Striker")


class SecretFinder(HackingTool):
    TITLE = "SecretFinder (like API & etc)"
    DESCRIPTION = "SecretFinder - A python script for find sensitive data \n" \
                  "like apikeys, accesstoken, authorizations, jwt,..etc \n " \
                  "and search anything on javascript files.\n\n " \
                  "Usage: python SecretFinder.py -h"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/m4ll0k/SecretFinder.git"),
        dict(cmd="sudo pip3 install -r requirements.txt", cwd="secretfinder"),
    ]
    PROJECT_URL = "https://github.com/m4ll0k/SecretFinder"

    def __init__(self):
        super(SecretFinder, self).__init__(runnable=False)


class Shodan(HackingTool):
    TITLE = "Find Info Using Shodan"
    DESCRIPTION = "Get ports, vulnerabilities, informations, banners,..etc \n " \
                  "for any IP with Shodan (no apikey! no rate limit!)\n" \
                  "[X] Don't use this tool because your ip will be blocked by Shodan!"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/m4ll0k/Shodanfy.py.git"),
    ]
    PROJECT_URL = "https://github.com/m4ll0k/Shodanfy.py"

    def __init__(self):
        super(Shodan, self).__init__(runnable=False)


class PortScannerRanger(HackingTool):
    TITLE = "Port Scanner - rang3r"
    DESCRIPTION = "rang3r is a python script which scans in multi thread\n " \
                  "all alive hosts within your range that you specify."
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/floriankunushevci/rang3r.git"),
        dict(cmd="sudo pip install termcolor"),
    ]
    PROJECT_URL = "https://github.com/floriankunushevci/rang3r"

    def run(self):
        ip = input("Enter Ip >> ")
        run_command(f"sudo python rang3r.py --ip {ip}", cwd="rang3r")


class Breacher(HackingTool):
    TITLE = "Breacher"
    DESCRIPTION = "An advanced multithreaded admin panel finder written in python."
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/s0md3v/Breacher.git"),
    ]
    PROJECT_URL = "https://github.com/s0md3v/Breacher"

    def __init__(self):
        super(Breacher, self).__init__(runnable=False)


class InformationGatheringTools(HackingToolsCollection):
    TITLE = "Information gathering tools"
    TOOLS = [
        NMAP(),
        Dracnmap(),
        PortScan(),
        Host2IP(),
        XeroSploit(),
        RedHawk(),
        ReconSpider(),
        IsItDown(),
        Infoga(),
        ReconDog(),
        Striker(),
        SecretFinder(),
        Shodan(),
        PortScannerRanger(),
        Breacher()
    ]
