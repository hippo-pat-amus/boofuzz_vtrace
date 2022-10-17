# Vtrace-based Process Monitor for Boofuzz
Vivisect vtrace-based Process Monitor for Boofuzz. Re-introduces the debugger features offered by the legacy PyDby library.

# Features
- Full-featured Vtrace debugger-based target process monitor thread for Boofuzz
- Windows and Linux fuzzing target OS support
- New runtime options:
  - Auto Restart: allows user to define at runtime whether the target process automatically restarts itself after a crash, and if so how long the procmon should wait for it to settle after a crash
  - Set Debugger Thread: allows the user to define at runtime which type of debugger thread to use (simple or vtrace)

# Setup
1. Install vivisect on your fuzzing target machine
> pip install vivisect

2. Replace the original target-based Boofuzz files with these versions:
- boofuzz/process_monitor.py
- boofuzz/boofuzz/utils/crash_binning.py
- boofuzz/boofuzz/utils/process_monitor_pedrpc_server.py

3. Drop debugger_thread_vtrace.py into boofuzz/boofuzz/utils/ on your target machine

4. Configure the use of the process monitor on your fuzz controller script, e.g.

> options = {"proc_name":"target.exe", "start_commands":['C:/target.exe'], 'debugger_thread':'vtrace'}  
> procmon = ProcessMonitor(target_IP, 26002)  
> procmon.set_options(**options)  
> monitors = [procmon]  

5. run process_monitor.py on the target machine

6. Commence fuzzing! If you trigger a crash, the synopsis will be visible in both the web console and your post-mortem crash bins. 

![image](https://user-images.githubusercontent.com/85505707/196249139-4bae8d10-106a-4874-a489-f7eca4598d65.png)
