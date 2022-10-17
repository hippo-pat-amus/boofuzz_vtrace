#
# Crash Binning
# $Id: crash_binning.py
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

import json
import time
import envi.bits

class CrashBinStruct:
  def __init__(self):
    self.exception_module    = None
    self.exception_address   = 0
    self.write_violation     = 0
    self.violation_address   = 0
    self.violation_thread_id = 0
    self.context             = None
    self.context_dump        = None
    self.disasm              = None
    self.disasm_around       = []
    self.stack_unwind        = []
    self.seh_unwind          = []
    self.extra               = None
    self.signal              = 0

class CrashBinning:

  bins       = {}
  last_crash = None
  trace      = None
  
  ####################################################################################################################
  def __init__ (self):
    self.bins       = {}
    self.last_crash = None
    self.trace      = None

  ####################################################################################################################
  def record_crash (self, trace, extra=None):
    '''
    Given a vtrace instantiation that at the current time is assumed to have "crashed" (access violation for example)
    record various details such as the disassemly around the violating address, the ID of the offending thread, the
    call stack and the SEH unwind (on windows). Store the recorded data in an internal dictionary, binning them by 
    the exception address.

    @type  trace: vtrace
    @param trace: Instance of vtrace
    @type  extra: Mixed
    @param extra: (Optional, Def=None) Whatever extra data you want to store with this bin (usually the test case #)
    '''
    # Initializations
    self.trace = trace
    crash = CrashBinStruct()

    # The platform tells us which OS the target is running
    platform = trace.getMeta('Platform')

    # Populate the common data points
    crash.violation_thread_id = trace.getCurrentThread()
    crash.context             = trace.getRegisterContext(crash.violation_thread_id).getRegisters()
    crash.context_dump        = self.dump_register_context(trace, crash.context)
    crash.exception_address   = crash.context['rip'] 
    crash.extra               = extra

    # Vtrace gives us some windows-specific data points to pull for our synopsis
    if(platform == "windows"):
      crash.write_violation   = trace.getMeta('Win32Event')['ExceptionInformation'][0]
      crash.violation_address = trace.getMeta('Win32Event')['ExceptionInformation'][1]
      crash.seh_unwind  = self.seh_unwind(trace) 
    else:
      #TODO: test other OS platforms besides windows and linux
      crash.signal = trace.getCurrentSignal()

    # Populate the module name for the crash triggering memory address
    crash.exception_module = self.addr_to_module(trace, crash.exception_address)
    if not crash.exception_module:
      crash.exception_module = "[INVALID]"

    # Attempt to get the assembly instruction (opcode) which triggered the crash
    try:
      crash.disasm = trace.parseOpcode(crash.exception_address)
    except Exception as e:
      print(f"[{time.strftime('%I:%M.%S')}] [crash_binning] exception while gathering disam:\n{e}")
      crash.disasm  = "[INVALID OPCODE]"

    # Attempt to gather the assembly context
    crash.disasm_around = self.disasm_around(trace, crash.exception_address)
    crash.stack_unwind = self.stack_unwind(trace)

    # Create a new crash bin if required
    if crash.exception_address not in self.bins:
      self.bins[crash.exception_address] = []

    # Save this crash data to it's respective bin
    self.bins[crash.exception_address].append(crash)
    self.last_crash = crash

  ####################################################################################################################
  def disasm_around(self, trace, va_3):
    '''
    returns the disassembly surrounding (2 before and 2 after) the crash-triggering instruction.
    
    @type  trace: vtrace
    @param trace: instance of vtrace
    @type  va_3: int
    @param va_3: address of the crash-triggering instruction
    '''
    try:
      op_3 = trace.parseOpcode(va_3)
      va_2 = va_3 - op_3.size
      op_2 = trace.parseOpcode(va_2)
      va_1 = va_2 - op_2.size
      op_1 = trace.parseOpcode(va_1)
      va_4 = va_3 + op_3.size
      op_4 = trace.parseOpcode(va_4)
      va_5 = va_4 + op_4.size
      op_5 = trace.parseOpcode(va_5)
    except Exception as e:
      #TODO better error handling here... though with fuzzing, the addresses are often overflows and invalid anyways
      print(f"[{time.strftime('%I:%M.%S')}] [crash_binning] exception while gathering disam_around:\n{e}")
      return []

    return [(va_1, op_1),(va_2, op_2),(va_3,op_3),(va_4,op_4),(va_5,op_5)]

  ####################################################################################################################
  def dump_register_context(self, trace, regs):
    '''
    take a raw vtrace register context object and convert it to a human-readable string
    with best-fit labels for each regiester value.

    @type  trace: vtrace
    @param trace: Instance of vtrace
    @type  regs: vtrace register context
    @param thread: Vtrace register context object to walk and beautify for display

    @rtype:  string
    @return: pretty-print string containing register contents and best-fit label
    '''
    register_string = "Reg:\tHex:\t\tBest:\n"
   
    for i in regs.keys():
      if regs[i] != 0:
        addr = int(regs[i])
        best = self.addr_to_module(trace, addr)
        register_string += f'{i}: \t{envi.bits.hex(regs[i], 4)} \t{best}\n'
    return register_string

  ####################################################################################################################
  def stack_unwind(self, trace):
    '''
    walk and save the stack trace for this crash.
    will be saved in the format [instr addr, frame pointer, name]

    @type  trace: vtrace
    @param trace: Instance of vtrace

    @rtype:  list
    @return: list containing stack trace in (rva, instr addr, frame pointer) format
    '''
    stack_trace = []
      
    call_chain = trace.getStackTrace()
    
    for i in range(len(call_chain)):
      try:
        addr  = call_chain[i][0]
        frame = call_chain[i][1]
        name = self.addr_to_module(trace, addr) 
        stack_trace.append((addr,frame,name))
      except Exception as e:
        print(f"[{time.strftime('%I:%M.%S')}] [crash_binning] exception while unwinding stack:\n{e}")
        break
    return stack_trace

  ####################################################################################################################
  def seh_unwind(self, trace):
    '''
    walk and save the SEH chain for the current crash.
    will be saved in the format [reg record addr, handler, name]
    adapted from vdb/vdb/extensions/windows.py -> seh(vdb, line)

    @type  trace: vtrace
    @param trace: Instance of vtrace

    @rtype:  list
    @return: list containing seh chain in (reg record addr, handler, name) format
    '''
    seh_chain = []

    tid = trace.getMeta('ThreadId')
    tinfo = trace.getThreads().get(tid, None)
    if tinfo is None:
      return

    teb = trace.getStruct("ntdll.TEB", tinfo)
    addr = int(teb.NtTib.ExceptionList)

    while addr != 0xffffffff:
      try:
        er = trace.getStruct("ntdll.EXCEPTION_REGISTRATION_RECORD", addr)
        name = self.addr_to_module(trace, er.Handler)
        seh_chain.append((addr, er.Handler, name))
        addr = int(er.Next)
      except Exception as e:
        print(f"[{time.strftime('%I:%M.%S')}] [crash_binning] exception while unwinding SEH chain:\n{e}")
        break

    return seh_chain
  ###################################################################################################################
  def addr_to_module(self, trace, address):
      """
      Return a string representing the best known label/module for the given address
      shamelessly adapted from vivisect/vdb/__init__.py -> reprPointer()
      """
      
      if not address:
          return ""

      # Do we have a symbol?
      sym = trace.getSymByAddr(address, exact=False)
      if sym is not None:
          return "%s + %d" % (repr(sym),address-int(sym))

      # Check if it's a thread's stack
      for tid,tinfo in trace.getThreads().items():
          ctx = trace.getRegisterContext(tid)
          sp = ctx.getStackCounter()

          #smap = self.trace.getMemoryMap(sp)
          smap = trace.getMemoryMap(sp)
          if not smap:
              continue

          stack,size,perms,fname = smap
          if address >= stack and address < (stack+size):
              off = address - sp
              op = "+"
              if off < 0:
                  op = "-"
              off = abs(off)
              return "tid:%d sp%s%s (stack)" % (tid,op,off)

      map = trace.getMemoryMap(address)
      if map:
          return map[3]
    
      # Maybe its ASCII?
      try:
        hex_string = envi.bits.hex(address, 4)[2:]
        bytes_object = bytes.fromhex(hex_string)
        ascii_string = 'ASCII "' + bytes_object.decode("ASCII") + '"'
        return ascii_string
      # Maybe not...
      except Exception:
        return ""

  ####################################################################################################################
  def crash_synopsis (self, crash=None):
    '''
    For the supplied crash, generate and return a report containing the disassembly following the violating opcode,
    the ID of the offending thread, the call stack and the SEH chain. If no crash is specified, then return the 
    same information for the last recorded crash.

    @see: crash_synopsis()

    @type  crash: CrashBinStruct
    @param crash: (Optional, def=None) Crash object to generate report on

    @rtype:  str
    @return: Crash report
    '''

    if not crash:
      crash = self.last_crash

    synopsis =f'{crash.exception_module}: ' + \
              f'{envi.bits.hex(crash.exception_address, 4)} ' + \
              f'{crash.disasm} from thread {crash.violation_thread_id} '

    if not crash.signal:
      if crash.write_violation:
        direction = "write to"
      else:
        direction = "read from"
      synopsis += f'caused memory fault when attempting to ' + \
                  f'{direction} ' + \
                  f'{envi.bits.hex(crash.violation_address, 4)}'
    else:
      if crash.signal == 11:
        synopsis += 'caused a Segmentation Fault'
      else:
        synopsis += f'generated signal {crash.signal}'

    synopsis += "\nRegister context at time of memory fault:\n"
    synopsis += crash.context_dump

    if len(crash.disasm_around):
      synopsis += "\nDisassembly around point of failure:\n"
      for addr, op in crash.disasm_around:
        synopsis += f"\t{envi.bits.hex(addr, 4)} {str(op)}\n"
    
    if len(crash.stack_unwind):
      synopsis += "\nCall stack:\n"
      for addr, frame, name in crash.stack_unwind:
        synopsis += f"\tAddress: {envi.bits.hex(addr, 4)}\t Frame: {envi.bits.hex(frame, 4)}\t name: {name}\n"

    if len(crash.seh_unwind):
      synopsis += "\nSEH chain:\n"
      for (addr, handler, name) in crash.seh_unwind:
        synopsis +=  f"\tAddress: {envi.bits.hex(addr, 4)}\t Handler: {envi.bits.hex(handler, 4)}\t name:{name}\n"
    
    return synopsis + "\n"

  ####################################################################################################################
  def export_file (self, file_name):
    '''
    Dump the entire object structure to disk.

    @see: import_file()

    @type  file_name:   str
    @param file_name:   File name to export to

    @rtype:             CrashBinning
    @return:            self
    '''

    with open(file_name, "w") as crashbin_file:
      json.dump(self.bins, crashbin_file, default=lambda o: o.__dict__)
      crashbin_file.close()

    return self

  ####################################################################################################################
  def import_file (self, file_name):
    """
    Load the entire object structure from disk.

    @see: export_file()

    @type  file_name:   str
    @param file_name:   File name to import from

    @rtype:             CrashBinning
    @return:            self
    """

    self.bins = {}
    bin_dict = json.load(open(file_name, "rb"))
    for (crash_address, bin_list) in bin_dict.items():
        self.bins[crash_address] = []
        for single_bin in bin_list:
            tmp = CrashBinStruct()
            tmp.__dict__ = single_bin
            self.bins[crash_address].append(tmp)

    return self

  ####################################################################################################################
