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


def run_inshell(*args, **kwargs):
    """
    Abstract method to mask subprocess API for running commands as in shell.
    """
    # print(args, kwargs)
    return subprocess.run(*args, **kwargs)


def run_asprocess(*args, **kwargs):
    """
    Abstract method to mask subprocess API to execute commands.
    Returns the process.
    """
    # print(args, kwargs)
    return subprocess.Popen(*args, **kwargs)


def run_command(cmd_string, cwd='', shell=False, **kwargs):
    """
    Runs an os command using subprocess module.
    Supports pipe operator.
    `;`, `&&` and other shell operators not recommended.
    """
    piped_commands, exit_codes, procs = cmd_string.split('|'), [], []
    tasks, output = list(map(str.strip, piped_commands)), None
    cwd = cwd[1:] if cwd.startswith('$') else os.path.join(get_path(), cwd)

    if shell:
        return run_inshell(*tasks[0].split(), shell=True, cwd=cwd)

    for task in tasks:
        args = task.split()
        if len(procs):
            proc = run_asprocess(
                args,
                stdin=procs[-1].stdout,
                stdout=subprocess.PIPE,
                cwd=cwd,
            )
        else:
            proc = run_asprocess(
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


def get_go_path(key='GOPATH', recursive=False):
    """
    Returns Go working directory.
    For version 1.8+, default value -> $HOME/go
    Prior version 1.8, $GOPATH or $GOROOT
    """
    try:
        go_dir = os.environ[key]
    except KeyError:
        if recursive:
            raise
        go_dir = get_go_path(key='GOROOT')
    except:
        go_dir = f"{os.environ['HOME']}/go"
    return go_dir
