# coding=utf-8
import os
import subprocess

from core import HackingTool
from core import HackingToolsCollection
from core.utils import run_command


class Dalfox(HackingTool):
    TITLE = "DalFox(Finder of XSS)"
    DESCRIPTION = "XSS Scanning and Parameter Analysis tool."
    INSTALL_COMMANDS = [
        dict(cmd="sudo apt-get install golang"),
        dict(cmd="sudo git clone https://github.com/hahwul/dalfox"),
        dict(cmd="go install", cwd="dalfox"),
    ]
    RUN_COMMANDS = [
        dict(cmd=f"{os.environ['HOME']}/go/bin/dalfox"),
        dict(
            cmd=
            'echo "You Need To Run manually by using [!]~/go/bin/dalfox [options]"'
        ),
    ]
    PROJECT_URL = "https://github.com/hahwul/dalfox"


class XSSPayloadGenerator(HackingTool):
    TITLE = "XSS Payload Generator"
    DESCRIPTION = "XSS PAYLOAD GENERATOR -XSS SCANNER-XSS DORK FINDER"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/capture0x/XSS-LOADER.git"),
        dict(cmd="sudo pip3 install -r requirements.txt", cwd="XSS-LOADER"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo python3 payloader.py", cwd="XSS-LOADER"),
    ]
    PROJECT_URL = "https://github.com/capture0x/XSS-LOADER.git"


class XSSFinder(HackingTool):
    TITLE = "Extended XSS Searcher and Finder"
    DESCRIPTION = "Extended XSS Searcher and Finder"
    INSTALL_COMMANDS = [
        dict(
            cmd="git clone https://github.com/Damian89/extended-xss-search.git"
        ),
    ]
    PROJECT_URL = "https://github.com/Damian89/extended-xss-search"

    def after_install(self):
        print("""\033[96m 
        Follow This Steps After Installation:-
            \033[31m [*] Go To extended-xss-search directory,
                and Rename the example.app-settings.conf to app-settings.conf
        """)
        input("Press ENTER to continue")

    def run(self):
        print("""\033[96m 
        You have To Add Links to scan
        \033[31m[!] Go to extended-xss-search
            [*] config/urls-to-test.txt
            [!] python3 extended-xss-search.py
        """)


class XSSFreak(HackingTool):
    TITLE = "XSS-Freak"
    DESCRIPTION = "XSS-Freak is an XSS scanner fully written in python3 from scratch"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/PR0PH3CY33/XSS-Freak.git"),
        dict(cmd="sudo pip3 install -r requirements.txt", cwd="XSS-Freak"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo python3 XSS-Freak.py", cwd="XSS-Freak"),
    ]
    PROJECT_URL = "https://github.com/PR0PH3CY33/XSS-Freak"


class XSpear(HackingTool):
    TITLE = "XSpear"
    DESCRIPTION = "XSpear is XSS Scanner on ruby gems"
    INSTALL_COMMANDS = [
        dict(cmd="gem install XSpear"),
    ]
    RUN_COMMANDS = [
        dict(cmd="XSpear -h"),
    ]
    PROJECT_URL = "https://github.com/hahwul/XSpear"


class XSSCon(HackingTool):
    TITLE = "XSSCon"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/menkrep1337/XSSCon.git"),
        dict(cmd="sudo chmod 755 -R XSSCon"),
    ]
    PROJECT_URL = "https://github.com/menkrep1337/XSSCon"

    def run(self):
        website = input("Enter Website >> ")
        run_command(f"python3 xsscon.py -u {website}", cwd="XSSCon")


class XanXSS(HackingTool):
    TITLE = "XanXSS"
    DESCRIPTION = "XanXSS is a reflected XSS searching tool\n " \
                  "that creates payloads based from templates"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/Ekultek/XanXSS.git"),
    ]
    PROJECT_URL = "https://github.com/Ekultek/XanXSS"

    def run(self):
        run_command("python xanxss.py -h", cwd="XanXSS")
        print("\033[96m You Have to run it manually By Using\n"
              " [!]python xanxss.py [Options]")


class XSSStrike(HackingTool):
    TITLE = "Advanced XSS Detection Suite"
    DESCRIPTION = "XSStrike is a python script designed to detect and exploit XSS vulnerabilites."
    INSTALL_COMMANDS = [
        dict(cmd="sudo rm -rf XSStrike"),
        dict(cmd="git clone https://github.com/UltimateHackers/XSStrike.git"),
        dict(cmd="pip install -r requirements.txt", cwd="XSStrike"),
    ]
    PROJECT_URL = "https://github.com/UltimateHackers/XSStrike"

    def __init__(self):
        super(XSSStrike, self).__init__(runnable=False)


class RVuln(HackingTool):
    TITLE = "RVuln"
    DESCRIPTION = "RVuln is multi-threaded and Automated Web Vulnerability " \
                  "Scanner written in Rust"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/iinc0gnit0/RVuln.git"),
        dict(
            cmd=
            "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh;"),
        dict(cmd=f"source {os.environ['HOME']}/.cargo/env"),
        dict(cmd="sudo apt install librust-openssl-dev"),
        dict(cmd="sudo su", cwd="RVuln"),
        dict(cmd="cargo build --release", cwd="RVuln"),
        dict(cmd="mv target/release/RVuln", cwd="RVuln"),
    ]
    RUN_COMMANDS = [
        dict(cmd="RVuln"),
    ]
    PROJECT_URL = "https://github.com/iinc0gnit0/RVuln"


class XSSAttackTools(HackingToolsCollection):
    TITLE = "XSS Attack Tools"
    TOOLS = [
        Dalfox(),
        XSSPayloadGenerator(),
        XSSFinder(),
        XSSFreak(),
        XSpear(),
        XSSCon(),
        XanXSS(),
        XSSStrike(),
        RVuln()
    ]
