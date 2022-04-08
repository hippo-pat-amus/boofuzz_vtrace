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
               Patrick Cousineau (github/hippo-pat-amus)
@license:      GNU General Public License 2.0 or later
@contact:      cousineau.pat@gmail.com
'''

from __future__ import print_function

import os
import subprocess
import sys
import threading
import time
import psutil

import vtrace
import envi.memory as e_memory
import envi.bits as e_bits

def _enumerate_processes():
    for pid in psutil.pids():
        try:
            yield (pid, psutil.Process(pid).name())
        except Exception as e:
            continue

class VtraceCallbackNotifier(vtrace.Notifier):
    '''
    Callback class used to capture vtrace events
    '''

    def __init__(self, dbg_thread):
        vtrace.Notifier.__init__(self)
        self.dbg_thread = dbg_thread

    def notify(self, event, trace):
        '''
        Handle debugger events
        '''         
        if event == vtrace.NOTIFY_SIGNAL:       #1
            # sound the alarm, we caught an exception!
            self.dbg_thread.caught_exception = True
            
            thread = trace.getCurrentThread()
            signo = trace.getCurrentSignal()
            self.dbg_thread.log(f"Process Received Signal {hex(signo)} (Thread: {thread})")
            
            # TODO make this platoform independant as Win32Events are specific to Windows
            event_info = trace.getMeta('Win32Event')
            for event in event_info.keys():
                try:
                    self.dbg_thread.log(f'\t{event} Value: {hex(event_info[event])}')
                except:
                    self.dbg_thread.log(f'\t{event} Value: {event_info[event]}')
            
            # leverage Vtrace's native memory fault detection function to categorize the exception
            faddr,fperm = trace.getMemoryFault()
            if faddr is not None:
                accstr = e_memory.getPermName(fperm)
                self.dbg_thread.log(f"Memory Fault. Address: {e_bits.hex(faddr, 4)} Operation: {accstr}")
            else:
                self.dbg_thread.log(f"Non-memory fault exception.")

            # record the crash to the procmon crash bin for return to Boofuzz
            # include the test case number in the "extra" info block for correlation
            self.dbg_thread.process_monitor.crash_bin.record_crash(trace, thread, extra=self.dbg_thread.process_monitor.test_number)

            # save the crash synopsis
            self.dbg_thread.process_monitor.last_synopsis = self.dbg_thread.process_monitor.crash_bin.crash_synopsis()
            head = self.dbg_thread.process_monitor.last_synopsis.split("\n")[0]      
            self.dbg_thread.log(f"Debugger thread {self.dbg_thread.getName()} caught exception:\n\t{head}")
            
            # save this data to a file
            self.dbg_thread.process_monitor.crash_bin.export_file(self.dbg_thread.process_monitor.crash_filename)
    
        elif event == vtrace.NOTIFY_BREAK:      #2
            pass
        elif event == vtrace.NOTIFY_STEP:       #3
            pass
        elif event == vtrace.NOTIFY_SYSCALL:    #4
            pass
        elif event == vtrace.NOTIFY_CONTINUE:   #5
            pass
        elif event == vtrace.NOTIFY_EXIT:       #6
            self.dbg_thread.log(f"Target Process Exited. Exit Code: {trace.getMeta('ExitCode')}")
            pass
        elif event == vtrace.NOTIFY_ATTACH:     #7
            pass
        elif event == vtrace.NOTIFY_DETACH:     #8
            self.dbg_thread.log(f"Debugger thread detaching from target.")
        elif event == vtrace.NOTIFY_LOAD_LIBRARY:   #9
            pass
        elif event == vtrace.NOTIFY_UNLOAD_LIBRARY: #10
            pass
        elif event == vtrace.NOTIFY_CREATE_THREAD:  #11
            self.dbg_thread.log(f"[vtrace] Target Thread Created: {trace.getMeta('ThreadId')}")
        elif event == vtrace.NOTIFY_EXIT_THREAD:    #12
            self.dbg_thread.log(f"[vtrace] Target Thread Closed: {trace.getMeta('ExitThread')}")
        elif event == vtrace.NOTIFY_DEBUG_PRINT:    #13
            self.dbg_thread.log(f"Debug print event: {event}")
            self.dbg_callback_dbg(trace, self.dbg_thread)
        elif event == vtrace.NOTIFY_MAX:            #20
            pass
        else:
            self.dbg_thread.log(f"Other event detected with id: {event}")

        # do we continue tracing or stop?
        if self.dbg_thread.caught_exception:
            trace.release()
        else:
            # release the trace object
            trace.runAgain()

    def dbg_callback_debug(self, trace, dbg_thread):
        debug_info = trace.getMeta('Win32Event')['DebugString']
        self.dbg_thread.log("DebugPrint: \n%s" % (debug_info, ))
        return True

class DebuggerThreadVtrace(threading.Thread):
    def __init__(
        self,
        start_commands,
        process_monitor,
        proc_name=None,
        ignore_pid=None,
        log_level=1,
        capture_output=False,
        **kwargs
    ):
        threading.Thread.__init__(self)
        
        self.proc_name = proc_name
        self.ignore_pid = ignore_pid
        self.start_commands = start_commands
        self.process_monitor = process_monitor

        self.capture_output = capture_output
        self.finished_starting = threading.Event()
        self.caught_exception = False
        self.active = True
        self.pid = None

        self.setName("%d" % time.time())

        self.trace = vtrace.getTrace()

        self.log_level = log_level
        self._process = None
        
        self.log(f"Debugger thread initialized with UID {self.getName()}")

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
                if self.capture_output:
                    self._process = subprocess.Popen(command, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                else:
                    self._process = subprocess.Popen(command)
            except Exception as e:
                self.log(f'Exception while executing start command {command}: {e}')
                return False
            
        self.log("Done. target up and running, giving it 5 seconds to settle in.")
        time.sleep(5)
        self.pid = self._process.pid
        self.log(f"{self.proc_name} initialized.")
        return True
        
    def run(self):
        """
        Main thread routine, called on thread.start(). Thread exits when this routine returns.
        """
        if len(self.start_commands) > 0:
            self.spawn_target()
        elif self.proc_name is not None:
            self.watch()
        else:
            self.log("Error: procmon has no start command or process name to attach to!")
            return False
        
        # tell the trace object what our target's name is
        self.trace.setMeta('proc_name', self.proc_name)

        try:
            self.log(f"Debugger thread {self.getName()} attaching to PID {self.pid}")
            self.trace.attach(self.pid)

            # set the callback notifier function which is triggered when vtrace receives a signal
            self.trace.registerNotifier(vtrace.NOTIFY_ALL, VtraceCallbackNotifier(self))
            self.finished_starting.set()
        except Exception as e:
            self.log(f"Failed to attach to target:\n\t{e}")
            self.log(f"Exiting.")
            return

        self.log(f"Debugger thread running.")
        self.trace.run()
        self.log(f"Debugger thread {self.getName()} exiting")
        return

    def watch(self):
        """
        Continuously loop, watching for the target process. This routine "blocks" until the target process is found.
        Update self.pid when found and return.
        """
        self.pid = None
        while not self.pid:
            for (pid, name) in _enumerate_processes():
                # ignore the optionally specified PID.
                if pid == self.ignore_pid:
                    continue

                if name.lower() == self.proc_name.lower():
                    self.pid = pid
                    break

    def stop_target(self):
        try:
            if self.pid is not None:
                self.log(f"Issuing stop command 'taskkill /F /PID {self.pid}'")
                exit_code = os.system(f"taskkill /F /PID {self.pid}")
            elif self.proc_name is not None:
                self.log(f"Issuing stop command 'taskkill /F /IM {self.proc_name}'")
                exit_code = os.system(f"taskkill /F /IM {self.proc_name}")
            else:
                self.log("No target PID or process name to stop... send help")
                
            if exit_code != 0:
                self.log(f"Unable stop target. Exit code: {exit_code}")
        except Exception as e:
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
        
        crash = self.caught_exception

        # if there was an exception caused, wait for the debugger thread to finish then kill thread handle.
        # it is important to wait for the debugger thread to finish because it could be taking its sweet ass time
        # uncovering the details of the access violation.
        if crash:
            while self.is_alive():
                time.sleep(1)
            
        # serialize the crash bin to disk.
        self.process_monitor.crash_bin.export_file(self.process_monitor.crash_filename)
        return not crash
