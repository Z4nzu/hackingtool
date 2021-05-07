# coding=utf-8
from core import HackingTool
from core import HackingToolsCollection


class Sqlmap(HackingTool):
    TITLE = "Sqlmap tool"
    DESCRIPTION = "sqlmap is an open source penetration testing tool that " \
                  "automates the process of \n" \
                  "detecting and exploiting SQL injection flaws and taking " \
                  "over of database servers \n " \
                  "[!] python3 sqlmap.py -u [<http://example.com>] --batch --banner \n " \
                  "More Usage [!] https://github.com/sqlmapproject/sqlmap/wiki/Usage"
    INSTALL_COMMANDS = [
        "sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev"]
    RUN_COMMANDS = ["cd sqlmap-dev;python3 sqlmap.py --wizard"]
    PROJECT_URL = "https://github.com/sqlmapproject/sqlmap"

class NoSqlMap(HackingTool):
    TITLE = "NoSqlMap"
    DESCRIPTION = "NoSQLMap is an open source Python tool designed to \n " \
                  "audit for as well as automate injection attacks and exploit.\n " \
                  "\033[91m " \
                  "[*] Please Install MongoDB \n "
    INSTALL_COMMANDS = [
        "git clone https://github.com/codingo/NoSQLMap.git",
        "sudo chmod -R 755 NoSQLMap;cd NoSQLMap;python setup.py install"
    ]
    RUN_COMMANDS = ["python NoSQLMap"]
    PROJECT_URL = "https://github.com/codingo/NoSQLMap"


class SQLiScanner(HackingTool):
    TITLE = "Damn Small SQLi Scanner"
    DESCRIPTION = "Damn Small SQLi Scanner (DSSS) is a fully functional SQL " \
                  "injection\nvulnerability scanner also supporting GET and " \
                  "POST parameters.\n" \
                  "[*]python3 dsss.py -h[help] | -u[URL]"
    INSTALL_COMMANDS = ["git clone https://github.com/stamparm/DSSS.git"]
    PROJECT_URL = "https://github.com/stamparm/DSSS"

    def __init__(self):
        super(SQLiScanner, self).__init__(runnable = False)


class Explo(HackingTool):
    TITLE = "Explo"
    DESCRIPTION = "Explo is a simple tool to describe web security issues " \
                  "in a human and machine readable format.\n " \
                  "Usage:- \n " \
                  "[1] explo [--verbose|-v] testcase.yaml \n " \
                  "[2] explo [--verbose|-v] examples/*.yaml"
    INSTALL_COMMANDS = [
        "git clone https://github.com/dtag-dev-sec/explo.git",
        "cd explo;sudo python setup.py install"
    ]
    PROJECT_URL = "https://github.com/dtag-dev-sec/explo"

    def __init__(self):
        super(Explo, self).__init__(runnable = False)


class Blisqy(HackingTool):
    TITLE = "Blisqy - Exploit Time-based blind-SQL injection"
    DESCRIPTION = "Blisqy is a tool to aid Web Security researchers to find " \
                  "Time-based Blind SQL injection \n on HTTP Headers and also " \
                  "exploitation of the same vulnerability.\n " \
                  "For Usage >> \n"
    INSTALL_COMMANDS = ["git clone https://github.com/JohnTroony/Blisqy.git"]
    PROJECT_URL = "https://github.com/JohnTroony/Blisqy"

    def __init__(self):
        super(Blisqy, self).__init__(runnable = False)


class Leviathan(HackingTool):
    TITLE = "Leviathan - Wide Range Mass Audit Toolkit"
    DESCRIPTION = "Leviathan is a mass audit toolkit which has wide range " \
                  "service discovery,\nbrute force, SQL injection detection " \
                  "and running custom exploit capabilities. \n " \
                  "[*] It Requires API Keys \n " \
                  "More Usage [!] https://github.com/utkusen/leviathan/wiki"
    INSTALL_COMMANDS = [
        "git clone https://github.com/leviathan-framework/leviathan.git",
        "cd leviathan;sudo pip install -r requirements.txt"
    ]
    RUN_COMMANDS = ["cd leviathan;python leviathan.py"]
    PROJECT_URL = "https://github.com/leviathan-framework/leviathan"


class SQLScan(HackingTool):
    TITLE = "SQLScan"
    DESCRIPTION = "sqlscan is quick web scanner for find an sql inject point." \
                  " not for educational, this is for hacking."
    INSTALL_COMMANDS = [
        "sudo apt install php php-bz2 php-curl php-mbstring curl",
        "sudo curl https://raw.githubusercontent.com/Cvar1984/sqlscan/dev/build/main.phar --output /usr/local/bin/sqlscan",
        "chmod +x /usr/local/bin/sqlscan"
    ]
    RUN_COMMANDS = ["sudo sqlscan"]
    PROJECT_URL = "https://github.com/Cvar1984/sqlscan"


class SqlInjectionTools(HackingToolsCollection):
    TITLE = "SQL Injection Tools"
    TOOLS = [
        Sqlmap(),
        NoSqlMap(),
        SQLiScanner(),
        Explo(),
        Blisqy(),
        Leviathan(),
        SQLScan()
    ]
