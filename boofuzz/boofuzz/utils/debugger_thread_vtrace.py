#
# Vtrace-based Debugger Thread for Boofuzz
# $Id: debugger_thread_vtrace.py
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

'''
@authors:      Pedram Amini
               github/pdasilva
               Pat Cousineau (github/hippo-pat-amus)
@license:      GNU General Public License 2.0 or later
'''

import os
import subprocess
import sys
import threading
import time
import psutil

import vtrace

class VtraceCallbackNotifier(vtrace.Notifier):
    '''
    Callback class used to capture vtrace events
    '''

    def __init__(self, debugger_thread):
        vtrace.Notifier.__init__(self)
        self.debugger_thread = debugger_thread

    def notify(self, event, trace):
        '''
        Handle debugger events
        '''
        if event == vtrace.NOTIFY_SIGNAL:       #1
            # sound the alarm, we caught an exception!
            self.debugger_thread.access_violation = True

            # record the crash to the procmon crash bin for return to Boofuzz
            # include the test case number in the "extra" info block for correlation
            self.debugger_thread.process_monitor.crash_bin.record_crash(trace, extra=self.debugger_thread.process_monitor.test_number)

            # save the crash synopsis
            self.debugger_thread.process_monitor.last_synopsis = self.debugger_thread.process_monitor.crash_bin.crash_synopsis()
            first_line = self.debugger_thread.process_monitor.last_synopsis.split("\n")[0]

            self.debugger_thread.log(f"Debugger Thread {self.debugger_thread.getName()} caught access violation:\n\t{first_line}")

            # kill the process
            trace.kill()
    
        elif event == vtrace.NOTIFY_BREAK:      #2
            pass
        elif event == vtrace.NOTIFY_STEP:       #3
            pass
        elif event == vtrace.NOTIFY_SYSCALL:    #4
            pass
        elif event == vtrace.NOTIFY_CONTINUE:   #5
            pass
        elif event == vtrace.NOTIFY_EXIT:       #6
            self.debugger_thread.log(f"Target Process Exited. Exit Code: {trace.getMeta('ExitCode')}")
            pass
        elif event == vtrace.NOTIFY_ATTACH:     #7
            pass
        elif event == vtrace.NOTIFY_DETACH:     #8
            self.debugger_thread.log(f"Debugger Thread detaching from target.")
        elif event == vtrace.NOTIFY_LOAD_LIBRARY:   #9
            pass
        elif event == vtrace.NOTIFY_UNLOAD_LIBRARY: #10
            pass
        elif event == vtrace.NOTIFY_CREATE_THREAD:  #11
            self.debugger_thread.log(f"[vtrace] Target Thread Created: {trace.getMeta('ThreadId')}", 5)
        elif event == vtrace.NOTIFY_EXIT_THREAD:    #12
            self.debugger_thread.log(f"[vtrace] Target Thread Closed: {trace.getMeta('ExitThread')}", 5)
        elif event == vtrace.NOTIFY_DEBUG_PRINT:    #13
            self.debugger_thread.log(f"Debug print event: {event}")
            self.dbg_callback_dbg(trace, self.debugger_thread)
        elif event == vtrace.NOTIFY_MAX:            #20
            pass
        else:
            self.debugger_thread.log(f"Other event detected with id: {event}")

        trace.runAgain()

    def dbg_callback_debug(self, trace, debugger_thread):
        if(trace.getMeta('Platform') == 'windows'):
            debug_info = trace.getMeta('Win32Event')['DebugString']
            self.debugger_thread.log("DebugPrint: \n%s" % (debug_info, ))
        return True

class DebuggerThreadVtrace(threading.Thread):
    def __init__(
        self, start_commands, process_monitor, proc_name=None, ignore_pid=None, log_level=1, **kwargs
    ):
        """
        Instantiate a new Vtrace instance and register debugger event callbacks.
        """
        threading.Thread.__init__(self)
        
        self.start_commands = start_commands
        self.process_monitor = process_monitor
        self.finished_starting = threading.Event()
        self.proc_name = proc_name
        self.ignore_pid = ignore_pid

        self.access_violation = False
        self.active = True
        self.pid = None

        # give this thread a unique name
        self.setName("%d" % time.time())

        self.process_monitor.log(f"Debugger Thread initialized with UID {self.getName()}")

        # set the user callback which is called when the vtrace debugger receives a signal
        # self.trace.registerNotifier(vtrace.NOTIFY_ALL, VtraceCallbackNotifier(self))
        self.log_level = log_level
        self._process = None

    def log(self, msg="", level=1):
        """
        If the supplied message falls under the current log level, print the specified message to screen.

        @type  msg: str
        @param msg: Message to log
        """
        if self.log_level >= level:
            print(f"[{time.strftime('%I:%M.%S')}] [dbg-thread] {msg}")

    def spawn_target(self):
        self.log("Spawining target processs...")
        for command in self.start_commands:
            self.log(f"Executing start command: {command}")
            try:
                self._process = subprocess.Popen(command)
            except OSError as e:
                print('OSError "{0}" while starting "{1}"'.format(e.strerror, command), file=sys.stderr)
                raise
                return False
            
        self.log("Done. target up and running, giving it 5 seconds to settle in.")
        time.sleep(5)
        self.pid = self._process.pid
        return True
        
    def run(self):
        """
        Main thread routine, called on thread.start(). Thread exits when this routine returns.
        """
        try:
            if len(self.start_commands) > 0:
                self.spawn_target()
            elif self.proc_name is not None:
                self.watch()
            else:
                self.log("Error: procmon has no start command or process name to attach to!")
                return False 
            
            # attach trace to the target process
            self.log(f"Debugger Thread {self.getName()} attaching to PID {self.pid}")
            self.trace = vtrace.getTrace()
            self.trace.attach(self.pid)

            # set the user callback which is called when the vtrace debugger receives a signal
            self.trace.registerNotifier(vtrace.NOTIFY_ALL, VtraceCallbackNotifier(self))
            self.log("Attached to target process.")
            self.finished_starting.set()
        except Exception as e:
            self.log(f"Failed to attach to target:\n\t{e}")
            self.log(f"Exiting.")
            return

        self.log(f"Debugger Thread running.")
        self.trace.run()

        self.log(f"Debugger Thread {self.getName()} exiting")
        self.trace.release()
        return

    def watch(self):
        """
        Continuously loop, watching for the target process. This routine "blocks" until the target process is found.
        Update self.pid when found and return.
        """
        self.log(f"looking for process name: {self.proc_name}")
        self.pid = self._scan_proc_names_blocking()
        self.log(f"match on pid {self.pid}")

    def _enumerate_processes(self):
        for pid in psutil.pids():
            try:
                yield (pid, psutil.Process(pid).name())
            except Exception as e:
                continue

    def _scan_proc_names_blocking(self):
        pid = None
        while pid is None:
            pid = self._scan_proc_names_once()
        return pid

    def _scan_proc_names_once(self):
        for (pid, name) in self._enumerate_processes():
            if name.lower() == self.proc_name.lower() and pid != self.ignore_pid:
                return pid
        return None

    def stop_target(self):
        try:
            if self.trace.getMeta('Platform') == 'windows':
                exit_code = os.system(f"taskkill -f -pid {self.pid}")
            else:
                exit_code = os.system(f"pkill {self.proc_name}")
        except OSError as e:
            self.log(f"Exception while trying to stop target: {e}")
            # TODO interpret some basic errors
        return
            
    def pre_send(self):
        # un-serialize the crash bin from disk. this ensures we have the latest copy (ie: vmware image is cycling).
        try:
            self.process_monitor.crash_bin.import_file(self.process_monitor.crash_filename)
        except IOError: 
            pass # ignore missing file, etc.
        return

    def post_send(self):
        """
        This routine is called after the fuzzer transmits a test case and returns the status of the target.

        Returns:
            bool: True if the target is still active, False otherwise.
        """
        # sleep to synchronize the debugger and procmon threads
        time.sleep(0.1)
        
        crash = self.access_violation

        # if there was an exception caused, wait for the Debugger Thread to finish then kill thread handle.
        # it is important to wait for the Debugger Thread to finish because it could be taking its sweet ass time
        # uncovering the details of the access violation.
        if crash:
            while self.is_alive():
                time.sleep(1)
            
        # serialize the crash bin to disk.
        self.process_monitor.crash_bin.export_file(self.process_monitor.crash_filename)

        return not crash
