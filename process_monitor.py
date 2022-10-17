#!c:\\python\\python.exe
from __future__ import print_function

import click

from boofuzz.constants import DEFAULT_PROCMON_PORT
from boofuzz.utils.debugger_thread_simple import DebuggerThreadSimple
from boofuzz.utils.debugger_thread_vtrace import DebuggerThreadVtrace
from boofuzz.utils.process_monitor_pedrpc_server import ProcessMonitorPedrpcServer

def serve_procmon(port, crash_bin, proc_name, ignore_pid, log_level, debugger_class, auto_restart):
    with ProcessMonitorPedrpcServer(
        host="0.0.0.0",
        port=port,
        crash_filename=crash_bin,
        debugger_class=debugger_class,
        proc_name=proc_name,
        pid_to_ignore=ignore_pid,
        level=log_level,
        coredump_dir=None,
        auto_restart = auto_restart
    ) as servlet:
        servlet.serve_forever()

# app.args.add_argument("-c", "--crash_bin", help='filename to serialize crash bin class to',
#                       default='boofuzz-crash-bin', metavar='FILENAME')
# app.args.add_argument("-i", "--ignore_pid", help='PID to ignore when searching for target process', type=int,
#                       metavar='PID')
# app.args.add_argument("-l", "--log_level", help='log level: default 1, increase for more verbosity', type=int,
#                       default=1, metavar='LEVEL')
# app.args.add_argument("-p", "--proc_name", help='process name to search for and attach to', metavar='NAME')
# app.args.add_argument("-P", "--port", help='TCP port to bind this agent to', type=int, default=DEFAULT_PROCMON_PORT)
# app.args.add_argument("-dt", "--debugger_class", help='type of process monitor debugger thread to use (simple, vtrace); 
#                       defaults to vtrace', type=str, default=vtrace)
# app.args.add_argument("-ar", "--auto_restart", help='tells the procmon how long to wait for the target to automatically 
#                       restart itself after a crash', type=int, default=0)
@click.command()
@click.option(
    "--crash-bin",
    "--crash-bin",
    "-c",
    help="filename to serialize crash bin class to",
    default="boofuzz-crash-bin",
    metavar="FILENAME",
)
@click.option(
    "--ignore-pid",
    "--ignore_pid",
    "-i",
    type=int,
    help="PID to ignore when searching for target process",
    metavar="PID",
)
@click.option(
    "--log-level",
    "--log_level",
    "-l",
    help="log level: default 1, increase for more verbosity",
    type=int,
    default=1,
    metavar="LEVEL",
)
@click.option("--proc-name", "--proc_name", "-p", help="process name to search for and attach to", metavar="NAME")
@click.option("--port", "-P", help="TCP port to bind this agent to", type=int, default=DEFAULT_PROCMON_PORT)

@click.option(
    "--debugger_class",
    "-dt",
    help="type of process monitor debugger thread to use (simple, vtrace); defaults to vtrace",
    type=str,
    default='vtrace',
    metavar="DEBUGGER_THREAD_CLASS"
)
@click.option(
    "--auto_restart",
    "-ar",
    help="tells the procmon how long to wait for the target to automatically restart itself after a crash",
    type=int,
    default=0,
    metavar="AUTO_RESTART"
)

def go(crash_bin, ignore_pid, log_level, proc_name, port, debugger_class, auto_restart):
    serve_procmon(port=port, crash_bin=crash_bin, proc_name=proc_name, ignore_pid=ignore_pid, \
                  log_level=log_level, debugger_class=debugger_class, auto_restart=auto_restart)


if __name__ == "__main__":
    go()
