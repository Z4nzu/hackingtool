import subprocess, os
from functools import reduce, partial
from collections import Sequence
from itertools import groupby


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
    result = None
    try:
        print("shell -- ", args, kwargs)
        result = subprocess.run(args, **kwargs)
    except KeyboardInterrupt:
        pass
    finally:
        return result


def run_asprocess(*args, stdout=subprocess.PIPE, **kwargs):
    """
    Abstract method to mask subprocess API to execute commands.
    Returns the process.
    """
    print("process -- ", args, kwargs)
    return subprocess.Popen(*args, stdout=stdout, **kwargs)


def pipe_process(proc, task, cwd=get_path()):
    """
    """
    if proc is None:
        return run_asprocess(task, cwd=cwd)
    return run_asprocess(task, stdin=proc.stdout, cwd=cwd)


def get_command_args(command):
    """
    """
    if isinstance(command, str):
        return command.split()

    if isinstance(command, Sequence):
        return command

    raise Exception("Invalid command")


def parse_tasks(command):
    """
    """
    t = list(map(str.strip, get_command_args(command)))
    print("t", t)
    g = [list(group) for k, group in groupby(t, lambda x: x == "|") if not k]
    print(g)
    return g if len(g) else t


def run_command(command, cwd='', shell=False, **kwargs):
    """
    Runs an os command using subprocess module.
    Supports pipe operator.
    `;`, `&&` and other shell operators not recommended.
    """
    tasks = parse_tasks(command)
    print(tasks)
    status, procs = 1, []
    cwd = cwd[1:] if cwd.startswith('$') else os.path.join(get_path(), cwd)

    if shell:
        # print(tasks)
        return run_inshell(*tasks[0], cwd=cwd)

    try:
        process = reduce(
            partial(pipe_process, cwd=cwd),
            tasks,
            None,
        )
        output = process.communicate()[0]
        if output is not None:
            print(output.decode('utf-8'))
    except KeyboardInterrupt:
        pass
    return status


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
