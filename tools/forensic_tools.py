# coding=utf-8
import os

from core import HackingTool
from core import HackingToolsCollection
from core.utils import run_command


class Autopsy(HackingTool):
    TITLE = "Autopsy"
    DESCRIPTION = "Autopsy is a platform that is used by Cyber Investigators.\n" \
                  "[!] Works in any Os\n" \
                  "[!] Recover Deleted Files from any OS & MEdia \n" \
                  "[!] Extract Image Metadata"

    INSTALL_COMMANDS = [
        dict(cmd="sudo apt install autopsy"),
    ]

    RUN_COMMANDS = [
        dict(
            cmd="sudo autopsy",
            shell=True,
        ),
    ]

    def __init__(self):
        super(Autopsy, self).__init__(installable=True)


class Wireshark(HackingTool):
    TITLE = "Wireshark"
    DESCRIPTION = "Wireshark is a network capture and analyzer \n" \
                  "tool to see what’s happening in your network.\n " \
                  "And also investigate Network related incident"

    INSTALL_COMMANDS = [
        dict(cmd="sudo apt install wireshark"),
    ]

    RUN_COMMANDS = [
        dict(
            cmd="sudo wireshark",
            shell=True,
        ),
    ]

    def __init__(self):
        super(Wireshark, self).__init__(installable=True)


class BulkExtractor(HackingTool):
    TITLE = "Bulk extractor"
    DESCRIPTION = ""
    PROJECT_URL = "https://github.com/simsong/bulk_extractor"

    def __init__(self):
        super(BulkExtractor, self).__init__(
            [('GUI Mode (Download required)', self.gui_mode),
             ('CLI Mode', self.cli_mode)],
            installable=False,
            runnable=False,
        )

    def gui_mode(self):
        run_command(
            "sudo git clone https://github.com/simsong/bulk_extractor.git")
        run_command("./BEViewer", cwd="bulk_extractor/java_gui")
        print(
            "If you getting error after clone go to /java_gui/src/ And Compile .Jar file && run ./BEViewer"
        )
        print(
            "Please Visit For More Details About Installation >> https://github.com/simsong/bulk_extractor"
        )

    def cli_mode(self):
        run_command("sudo apt-get install bulk_extractor")
        print("bulk_extractor and options")
        run_command("bulk_extractor")
        run_command(
            'echo "bulk_extractor [options] imagefile" | boxes -d headline | lolcat'
        )


class Guymager(HackingTool):
    TITLE = "Disk Clone and ISO Image Aquire"
    DESCRIPTION = "Guymager is a free forensic imager for media acquisition."
    INSTALL_COMMANDS = [
        dict(cmd="sudo apt install guymager -y"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo guymager"),
    ]
    PROJECT_URL = "https://guymager.sourceforge.io/"


class Toolsley(HackingTool):
    TITLE = "Toolsley"
    DESCRIPTION = "Toolsley got more than ten useful tools for investigation.\n" \
                  "[+]File signature verifier\n" \
                  "[+]File identifier \n" \
                  "[+]Hash & Validate \n" \
                  "[+]Binary inspector \n " \
                  "[+]Encode text \n" \
                  "[+]Data URI generator \n" \
                  "[+]Password generator"
    PROJECT_URL = "https://www.toolsley.com/"

    def __init__(self):
        super(Toolsley, self).__init__(installable=False, runnable=False)


class ForensicTools(HackingToolsCollection):
    TITLE = "Forensic tools"
    TOOLS = [Autopsy(), Wireshark(), BulkExtractor(), Guymager(), Toolsley()]
