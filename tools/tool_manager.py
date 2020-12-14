# coding=utf-8
import os
from time import sleep

from core import HackingTool
from core import HackingToolsCollection
from core.utils import run_command


class UpdateTool(HackingTool):
    TITLE = "Update Tool or System"
    DESCRIPTION = "Update Tool or System"

    def __init__(self):
        super(UpdateTool,
              self).__init__([("Update System", self.update_sys),
                              ("Update Hackingtool", self.update_ht)],
                             installable=False,
                             runnable=False)

    def update_sys(self):
        run_command("sudo apt update && sudo apt full-upgrade -y")
        run_command("sudo apt-get install tor openssl curl")
        run_command("sudo apt-get update tor openssl curl")
        run_command("sudo apt-get install python3-pip")

    def update_ht(self):
        run_command("sudo chmod +x /etc/;")
        run_command("sudo chmod +x /usr/share/doc;")
        run_command("sudo rm -rf /usr/share/doc/hackingtool/;")
        run_command("sudo rm -rf /etc/hackingtool/;", cwd="$/etc/")
        run_command("mkdir hackingtool;", cwd="$/etc/")
        run_command(
            "git clone https://github.com/Z4nzu/hackingtool.git;",
            cwd="$/etc/hackingtool",
        )
        run_command("sudo chmod +x install.sh;", cwd="$/etc/hackingtool")
        run_command("./install.sh", cwd="$/etc/hackingtool")


class UninstallTool(HackingTool):
    TITLE = "Uninstall HackingTool"
    DESCRIPTION = "Uninstall HackingTool"

    def __init__(self):
        super(UninstallTool, self).__init__(
            [('Uninstall', self.uninstall)],
            installable=False,
            runnable=False,
        )

    def uninstall(self):
        print("hackingtool started to uninstall..\n")
        sleep(1)
        run_command("sudo chmod +x /etc/;")
        run_command("sudo chmod +x /usr/share/doc;")
        run_command("sudo rm -rf /usr/share/doc/hackingtool/;")
        run_command("sudo rm -rf /etc/hackingtool/;", cwd="$/etc/")
        print("\nHackingtool Successfully Uninstalled..")
        print("Happy Hacking..!!")
        sleep(1)


class ToolManager(HackingToolsCollection):
    TITLE = "Update or Uninstall | Hackingtool"
    TOOLS = [UpdateTool(), UninstallTool()]
