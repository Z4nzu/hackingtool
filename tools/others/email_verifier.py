# coding=utf-8
from core import HackingTool
from core import HackingToolsCollection


class KnockMail(HackingTool):
    TITLE = "Knockmail"
    DESCRIPTION = "KnockMail Tool Verify If Email Exists"
    INSTALL_COMMANDS = [
        "git clone https://github.com/4w4k3/KnockMail.git",
        "cd KnockMail;sudo pip install -r requeriments.txt"
    ]
    RUN_COMMANDS = ["cd KnockMail;python knock.py"]
    PROJECT_URL = "https://github.com/4w4k3/KnockMail"


class EmailVerifyTools(HackingToolsCollection):
    TITLE = "Email Verify tools"
    TOOLS = [KnockMail()]
