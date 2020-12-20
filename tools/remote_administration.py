# coding=utf-8
from core import HackingTool
from core import HackingToolsCollection


class Stitch(HackingTool):
    TITLE = "Stitch"
    DESCRIPTION = "Stitch is a cross platform python framework.\n" \
                  "which allows you to build custom payloads\n" \
                  "For Windows, Mac and Linux."
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/nathanlopez/Stitch.git"),
        dict(cmd="sudo pip install -r lnx_requirements.txt", cwd="Stitch"),
    ]
    RUN_COMMANDS = [
        dict(cmd="python main.py", cwd="Stitch"),
    ]
    PROJECT_URL = "https://github.com/nathanlopez/Stitch"


class Pyshell(HackingTool):
    TITLE = "Pyshell"
    DESCRIPTION = "Pyshell is a Rat Tool that can be able to download & upload " \
                  "files,\n Execute OS Command and more.."
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/knassar702/Pyshell.git"),
        dict(cmd="sudo pip install pyscreenshot python-nmap requests"),
    ]
    RUN_COMMANDS = [
        dict(cmd="./Pyshell", cwd="Pyshell"),
    ]
    PROJECT_URL = "https://github.com/knassar702/pyshell"


class RemoteAdministrationTools(HackingToolsCollection):
    TITLE = "Remote Administrator Tools (RAT)"
    TOOLS = [Stitch(), Pyshell()]
