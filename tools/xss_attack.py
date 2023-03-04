# coding=utf-8
import os
import subprocess

from core import HackingTool
from core import HackingToolsCollection


class Dalfox(HackingTool):
    TITLE = "DalFox(Finder of XSS)"
    DESCRIPTION = "XSS Scanning and Parameter Analysis tool."
    INSTALL_COMMANDS = [
        "sudo apt-get install golang",
        "sudo git clone https://github.com/hahwul/dalfox",
        "cd dalfox;go install"
    ]
    RUN_COMMANDS = [
        "~/go/bin/dalfox",
        'echo "You Need To Run manually by using [!]~/go/bin/dalfox [options]"'
    ]
    PROJECT_URL = "https://github.com/hahwul/dalfox"


class XSSPayloadGenerator(HackingTool):
    TITLE = "XSS Payload Generator"
    DESCRIPTION = "XSS PAYLOAD GENERATOR -XSS SCANNER-XSS DORK FINDER"
    INSTALL_COMMANDS = [
        "git clone https://github.com/capture0x/XSS-LOADER.git",
        "cd XSS-LOADER;sudo pip3 install -r requirements.txt"
    ]
    RUN_COMMANDS = ["cd XSS-LOADER;sudo python3 payloader.py"]
    PROJECT_URL = "https://github.com/capture0x/XSS-LOADER.git"


class XSSFinder(HackingTool):
    TITLE = "Extended XSS Searcher and Finder"
    DESCRIPTION = "Extended XSS Searcher and Finder"
    INSTALL_COMMANDS = [
        "git clone https://github.com/Damian89/extended-xss-search.git"]
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
        "git clone https://github.com/PR0PH3CY33/XSS-Freak.git",
        "cd XSS-Freak;sudo pip3 install -r requirements.txt"
    ]
    RUN_COMMANDS = ["cd XSS-Freak;sudo python3 XSS-Freak.py"]
    PROJECT_URL = "https://github.com/PR0PH3CY33/XSS-Freak"


class XSpear(HackingTool):
    TITLE = "XSpear"
    DESCRIPTION = "XSpear is XSS Scanner on ruby gems"
    INSTALL_COMMANDS = ["gem install XSpear"]
    RUN_COMMANDS = ["XSpear -h"]
    PROJECT_URL = "https://github.com/hahwul/XSpear"


class XSSCon(HackingTool):
    TITLE = "XSSCon"
    INSTALL_COMMANDS = [
        "git clone https://github.com/menkrep1337/XSSCon.git",
        "sudo chmod 755 -R XSSCon"
    ]
    PROJECT_URL = "https://github.com/menkrep1337/XSSCon"

    def run(self):
        website = input("Enter Website >> ")
        os.system("cd XSSCon;")
        subprocess.run(["python3", "xsscon.py", "-u", website])


class XanXSS(HackingTool):
    TITLE = "XanXSS"
    DESCRIPTION = "XanXSS is a reflected XSS searching tool\n " \
                  "that creates payloads based from templates"
    INSTALL_COMMANDS = ["git clone https://github.com/Ekultek/XanXSS.git"]
    PROJECT_URL = "https://github.com/Ekultek/XanXSS"

    def run(self):
        os.system("cd XanXSS ;python xanxss.py -h")
        print("\033[96m You Have to run it manually By Using\n"
              " [!]python xanxss.py [Options]")


class XSSStrike(HackingTool):
    TITLE = "Advanced XSS Detection Suite"
    DESCRIPTION = "XSStrike is a python script designed to detect and exploit XSS vulnerabilities."
    INSTALL_COMMANDS = [
        "sudo rm -rf XSStrike",
        "git clone https://github.com/UltimateHackers/XSStrike.git "
        "&& cd XSStrike && pip install -r requirements.txt"
    ]
    PROJECT_URL = "https://github.com/UltimateHackers/XSStrike"

    def __init__(self):
        super(XSSStrike, self).__init__(runnable = False)


class RVuln(HackingTool):
    TITLE = "RVuln"
    DESCRIPTION = "RVuln is multi-threaded and Automated Web Vulnerability " \
                  "Scanner written in Rust"
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/iinc0gnit0/RVuln.git;"
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh;"
        "source $HOME/.cargo/env;"
        "sudo apt install librust-openssl-dev;"
        "cd RVuln;sudo su;cargo build --release;mv target/release/RVuln"
    ]
    RUN_COMMANDS = ["RVuln"]
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
