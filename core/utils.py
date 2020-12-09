import subprocess, os


def get_path():
    """
    Absolute path of current working directory.
    """
    try:
        # opens hackingtoolpath and 
        # retrieves configured path
        with open('/home/hackingtoolpath.txt') as path_file:
            path = path_file.read().strip()
    except Exception as e:
        print(f"[+] Error: {str(e)}")
        path = os.path.dirname(os.path.realpath(__file__))
    finally:
        return path


def run_command(cmd_string, cwd='', **kwargs):
    """
    Runs an os command using subprocess module.
    Supports pipe operator.
    `;`, `&&` and other shell operators not recommended.
    """
    piped_commands, exit_codes, procs = cmd_string.split('|'), [], []
    tasks, output = list(map(str.strip, piped_commands)), None
    cwd = cwd[1:] if cwd.startswith('$') else os.path.join(get_path(), cwd)

    for task in tasks:
        args = task.split()
        print(args, cwd)
        if len(procs):
            proc = subprocess.Popen(
                args,
                stdin=procs[-1].stdout,
                stdout=subprocess.PIPE,
                cwd=cwd,
            )
        else:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                cwd=cwd,
            )
        procs.append(proc)
    else:
        if len(procs):
            output = procs[-1].communicate()[0]
            print(output.decode('utf-8'))
    exit_codes = [ps.wait() for ps in procs]
    return exit_codes
