# coding=utf-8
from core import HackingTool
from core import HackingToolsCollection


class KnockMail(HackingTool):
    TITLE = "Knockmail"
    DESCRIPTION = "KnockMail Tool Verify If Email Exists"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/4w4k3/KnockMail.git"),
        dict(cmd="sudo pip install -r requeriments.txt", cwd="KnockMail")
    ]
    RUN_COMMANDS = [
        dict(cmd="python knock.py", cwd="KnockMail"),
    ]
    PROJECT_URL = "https://github.com/4w4k3/KnockMail"


class EmailVerifyTools(HackingToolsCollection):
    TITLE = "Email Verify tools"
    TOOLS = [KnockMail()]
