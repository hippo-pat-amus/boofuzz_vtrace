from __future__ import print_function

import os
import shlex
import subprocess
import time
import datetime
from builtins import str

from past.builtins import map

from boofuzz import pedrpc, utils

from boofuzz.utils.debugger_thread_simple import DebuggerThreadSimple
from boofuzz.utils.debugger_thread_vtrace import DebuggerThreadVtrace

def _split_command_if_str(command):
    """Splits a shell command string into a list of arguments.

    If any individual item is not a string, item is returned unchanged.

    Designed for use with subprocess.Popen.

    Args:
        command (Union[basestring, :obj:`list` of :obj:`basestring`]): List of commands. Each command
        should be a string or a list of strings.
proc_name
    Returns:
        (:obj:`list` of :obj:`list`: of :obj:`str`): List of lists of command arguments.
    """
    if isinstance(command, str):
        return shlex.split(command, posix=(os.name == "posix"))

    else:
        return command

class ProcessMonitorPedrpcServer(pedrpc.Server):
    def __init__(
        self, host, port, crash_filename, debugger_class, proc_name=None, pid_to_ignore=None, level=1, coredump_dir=None, auto_restart=0
    ):
        """
        @type  host:           str
        @param host:           Hostname or IP address
        @type  port:           int
        @param port:           Port to bind server to
        @type  crash_filename: str
        @param crash_filename: Name of file to (un)serialize crash bin to/from
        @type  proc_name:      str
        @param proc_name:      (Optional, def=None) Process name to search for and attach to
        @type  pid_to_ignore:  int
        @param pid_to_ignore:  (Optional, def=None) Ignore this PID when searching for the target process
        @type  level:          int
        @param level:          (Optional, def=1) Log output level, increase for more verbosity
        @type  auto_restart:   int
        @param auto_restart:   (Optional, def=0) If set, tells procmon how many seconds to wait for the target to auto-restart after a crash
        """

        # initialize the PED-RPC server.
        pedrpc.Server.__init__(self, host, port)

        self.crash_filename = os.path.abspath(crash_filename)
        if(debugger_class == "simple"):
            self.debugger_class = DebuggerThreadSimple
        else:
            self.debugger_class = DebuggerThreadVtrace
        self.proc_name = proc_name
        self.ignore_pid = pid_to_ignore
        self.log_level = level
        self.capture_output = False

        self.stop_commands = []
        self.start_commands = []
        self.test_number = None
        self.debugger_thread = None
        self.crash_bin = utils.crash_binning.CrashBinning()

        self.last_synopsis = ""

        self.coredump_dir = coredump_dir

        self.auto_restart = auto_restart

        if not os.access(os.path.dirname(self.crash_filename), os.X_OK):
            self.log("Invalid path specified for crash bin: %s" % self.crash_filename)
            raise Exception

        self.log("Process Monitor PED-RPC server initialized:")
        self.log("\t listening on:  %s:%s" % (host, port))
        self.log("\t crash file:    %s" % self.crash_filename)
        self.log("\t # records:     %d" % len(self.crash_bin.bins))
        self.log("\t proc name:     %s" % self.proc_name)
        self.log("\t log level:     %d" % self.log_level)
        self.log("Awaiting requests...")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.debugger_thread is not None and self.debugger_thread.is_alive():
            self.debugger_thread.stop_target()
        self.stop()

    # noinspection PyMethodMayBeStatic
    def alive(self):
        """
        Returns True. Useful for PED-RPC clients who want to see if the PED-RPC connection is still alive.
        """

        return True

    def get_crash_synopsis(self):
        """
        Return the last recorded crash synopsis.

        @rtype:  String
        @return: Synopsis of last recorded crash.
        """
        # Since crash synopsis is called only after a failure, check for failures again:
        self.debugger_thread.post_send()

        return self.last_synopsis

    def log(self, msg="", level=1):
        """
        If the supplied message falls under the current log level, print the specified message to screen.

        @type  msg: str
        @param msg: Message to log
        """

        if self.log_level >= level:
            print("[%s] [pedrpc-server] %s" % (time.strftime("%I:%M.%S"), msg))

    def post_send(self):
        """
        This routine is called after the fuzzer transmits a test case and returns the status of the target.

        Returns:
            bool: True if the target is still active, False otherwise.
        """
        if self.debugger_thread is not None:
            return self.debugger_thread.post_send()
        else:
            raise Exception("post_send called before pre_send!")

    def pre_send(self, test_number):
        """
        This routine is called before the fuzzer transmits a test case and ensure the debugger thread is operational.

        @type  test_number: Integer
        @param test_number: Test number to retrieve PCAP for.
        """
        self.log("pre_send(%d)" % test_number, 10)
        self.test_number = test_number

        if self.debugger_thread is None or not self.debugger_thread.is_alive():
            self.start_target()
            self.debugger_thread.pre_send()

    def start_target(self):
        """
        Start up the target process by issuing the commands in self.start_commands.

        @returns True if successful.
        """
        if not self.auto_restart:
            self.log("Starting target...")
            self._stop_target_if_running()
        else:
            pass
        
        self.log("Creating debugger thread...")
        self.debugger_thread = self.debugger_class(
            self.start_commands,
            self,
            proc_name=self.proc_name,
            ignore_pid=self.ignore_pid,
            log_level=self.log_level,
            coredump_dir=self.coredump_dir,
            capture_output=self.capture_output
        )
        self.debugger_thread.daemon = True
        self.debugger_thread.start()
        self.debugger_thread.finished_starting.wait()
        self.log("giving debugger thread 2 seconds to settle in", 5)
        time.sleep(2)
        return True

    def stop_target(self):
        """
        Kill the current debugger thread and stop the target process by issuing the commands in self.stop_commands.
        """
        self.log("Stopping target...")

        if self._target_is_running():
            self._stop_target()
            self.log("Target stopped.")
        else:
            self.log("Target already stopped.")

    def _stop_target_if_running(self):
        """Stop target, if it is running. Return true if it was running; otherwise false."""
        if self._target_is_running():
            self.log("Target still running; stopping first...")
            self._stop_target()
            self.log("Target stopped.")
            return True
        else:
            self.log("Target is not running; starting...")
            return False

    def _stop_target(self):
        # give the debugger thread a chance to exit.
        time.sleep(1)
        if len(self.stop_commands) < 1:
            self.debugger_thread.stop_target()
            while self.debugger_thread.is_alive():
                time.sleep(0.1)
        else:
            for command in self.stop_commands:
                if command == ["TERMINATE_PID"] or command == "TERMINATE_PID":
                    self.debugger_thread.stop_target()
                    while self.debugger_thread.is_alive():
                        time.sleep(0.1)
                else:
                    self.log("Executing stop command: '{0}'".format(command), 2)
                    subprocess.Popen(command)

    def _target_is_running(self):
        return self.debugger_thread is not None and self.debugger_thread.is_alive()

    def restart_target(self):
        """
        Stop and start the target process.

        @returns True if successful.
        """
        if not self.auto_restart:
            self.log("Restarting target...")
            self.stop_target()
        else:
            self.log(f"Giving target {self.auto_restart} seconds to automatically restart...")
            time.sleep(self.auto_restart)
            self.log("Done. Target should be running.")
            
        return self.start_target()

    def set_capture_output(self, capture_output):
        self.log("Updating capture_output to '%s'" % capture_output)
        self.capture_output = capture_output

    def set_proc_name(self, new_proc_name):
        self.log("Updating target process name to '%s'" % new_proc_name)
        self.proc_name = new_proc_name

    def set_start_commands(self, new_start_commands):
        self.log("Updating start commands to: {0}".format(list(new_start_commands)))
        self.start_commands = map(_split_command_if_str, new_start_commands)

    def set_stop_commands(self, new_stop_commands):
        self.log("Updating stop commands to: {0}".format(list(new_stop_commands)))
        self.stop_commands = new_stop_commands
        self.stop_commands = map(_split_command_if_str, new_stop_commands)

    def set_crash_filename(self, new_crash_filename):
        self.log("Updating crash bin filename to '%s'" % new_crash_filename)
        self.crash_filename = os.path.abspath(new_crash_filename)
        
    def set_debugger_thread(self, debugger_thread):
        self.log(f"Updating process debugger thread class to {debugger_thread}")
        if(debugger_thread == "vtrace"):
            self.debugger_class = DebuggerThreadVtrace
        elif(debugger_thread == "simple"):
            self.debugger_class = DebuggerThreadSimple
        else:
            self.log(f'Unknown debugger thread class: {debugger_thread}. Keeping default type of {self.debugger_class}')
            
    def set_auto_restart_timeout(self, new_auto_restart_timeout):
        self.log("Updating auto restart timeout value to '%s'" % new_auto_restart_timeout)
        self.auto_restart = new_auto_restart_timeout
