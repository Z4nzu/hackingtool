# coding=utf-8
import os

from core import HackingTool
from core import HackingToolsCollection


class AnonymouslySurf(HackingTool):
    TITLE = "Anonmously Surf"
    DESCRIPTION = "It automatically overwrites the RAM when\n" \
                  "the system is shutting down and also change Ip."
    INSTALL_COMMANDS = [
        dict(
            cmd="sudo git clone https://github.com/Und3rf10w/kali-anonsurf.git"
        ),
        dict(cmd="sudo ./installer.sh", cwd="kali-anonsurf"),
        dict(cmd="sudo rm -r kali-anonsurf"),
    ]
    RUN_COMMANDS = [dict(cmd="sudo anonsurf start")]
    PROJECT_URL = "https://github.com/Und3rf10w/kali-anonsurf"

    def __init__(self):
        super(AnonymouslySurf, self).__init__([('Stop', self.stop)])

    def stop(self):
        run_command("sudo anonsurf stop")


class Multitor(HackingTool):
    TITLE = "Multitor"
    DESCRIPTION = "How to stay in multi places at the same time"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/trimstray/multitor.git"),
        dict(cmd="sudo bash setup.sh install", cwd="multitor"),
    ]
    PROJECT_URL = "https://github.com/trimstray/multitor"

    def __init__(self):
        super(Multitor, self).__init__(runnable=False)


class AnonSurfTools(HackingToolsCollection):
    TITLE = "Anonymously Hiding Tools"
    DESCRIPTION = ""
    TOOLS = [AnonymouslySurf(), Multitor()]
