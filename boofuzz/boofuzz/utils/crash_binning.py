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
               Patrick Cousineau (github/hippo-pat-amus)
@license:      GNU General Public License 2.0 or later
@contact:      cousineau.pat@gmail.com
'''

import os
import pickle
import sys
import struct
import time

import envi.bits as e_bits

class __crash_bin_struct__:
  exception_module    = None
  exception_address   = 0
  write_violation     = 0
  violation_address   = 0
  violation_thread_id = 0
  context             = None
  context_dump        = None
  disasm              = None
  disasm_around       = []
  stack_unwind        = []
  seh_unwind          = []
  extra               = None

def __getitem__(self, key): 
  return self.data[key]

class CrashBinning:
  bins       = {}
  last_crash = None
  trace      = None
  arch       = None
  target     = None
  
  ####################################################################################################################
  def __init__ (self):
    self.bins       = {}
    self.arch       = None
    self.last_crash = None
    self.trace      = None
    self.target     = None

  ####################################################################################################################
  def record_crash (self, trace, thread, extra=None):
    '''
    Given a vtrace instance that, at the current time, is assumed to have "crashed" (access violation for example),
    record various details such as the disassemly around the violating address, the ID of the offending thread, the
    call stack and the SEH unwind. Store the recorded data in an internal dictionary, binning them by the exception
    address.

    @type  trace: vtrace
    @param trace: Instance of vtrace
    @type  extra: Mixed
    @param extra: (Optional, Def=None) Whatever extra data you want to store with this bin
    '''

    self.trace = trace
    self.arch = trace.getMeta('Architecture')
    self.target = trace.getMeta('proc_name')
    crash = __crash_bin_struct__()
    crash.exception_address = trace.getMeta('Win32Event')['ExceptionAddress']

    '''
    Add module name to the exception address.
    '''
    exception_module = self.addr_to_name(trace, crash.exception_address)
    if not exception_module:
      exception_module = "[invalid address]"
      
    '''
    Populate crash synopsis datapoints
    '''
    crash.exception_module    = exception_module
    crash.write_violation     = trace.getMeta('Win32Event')['ExceptionInformation'][0]
    crash.violation_address   = trace.getMeta('Win32Event')['ExceptionInformation'][1]
    crash.violation_thread_id = thread
    crash.context             = trace.getRegisterContext(crash.violation_thread_id).getRegisters()
    crash.context_dump        = self.dump_register_context(trace, crash.context)
    crash.extra               = extra

    '''
    Populate crash synopsis datapoints which require memory reads. Depending on the nature of
    a fuzzed input, overflows can occur which corrupt memory and cause read errors. Hence,
    each datapoint to be populated is paired with exception handling to catch these instances.
    '''
    try:
      crash.disasm = trace.parseOpcode(crash.exception_address)
    except Exception as e:
      print(f"[{time.strftime('%I:%M.%S')}] [crash_binning] exception while gathering disam")
      crash.disasm  = "[invalid opcode]"
      
    try:
      crash.disasm_around = self.disasm_around(trace, crash.exception_address, 5)
    except Exception as e:
      print(f"[{time.strftime('%I:%M.%S')}] [crash_binning] exception while gathering disasm_around")
      crash.disasm_around = [(crash.exception_address,"[invalid opcode]")]
      
    try:
      crash.stack_unwind = self.stack_unwind(trace, thread=crash.violation_thread_id)
    except Exception as e:
      print(f"[{time.strftime('%I:%M.%S')}] [crash_binning] exception while reading call stack")
      crash.stack_unwind = []
      
    try:
      crash.seh_unwind  = self.seh_unwind(trace, thread=crash.violation_thread_id)
    except Exception as e:
      print(f"[{time.strftime('%I:%M.%S')}] [crash_binning] exception while unwinding SEH chain")
      crash.seh_unwind    = []  

    if crash.exception_address not in self.bins:
      self.bins[crash.exception_address] = []

    self.bins[crash.exception_address].append(crash)
    self.last_crash = crash
    return

  ####################################################################################################################
  def disasm_around(self, trace, starting_addr, num):
    '''
    returns the disassembly starting at addr for specified number of op codes.
    adapted from vtrace/__init__.py -> parseOpCodes() to include addresses.
    
    @type  trace: vtrace
    @param trace: instance of vtrace
    @type  starting_addr: int
    @param starting_addr: address of first instruction to disassemble
    @type  num: int
    @param num: number of instructions to disassemble
    '''
    disasm = []
    va = starting_addr
    for i in range(0, num):
      op = trace.parseOpcode(va)
      disasm.append((va, op))
      va += op.size
      
    return disasm

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
        best = self.addr_to_name(trace, addr)
        register_string += f'{i}: \t{e_bits.hex(regs[i], 4)} \t{best}\n'
    return register_string

  ####################################################################################################################
  def stack_unwind(self, trace, thread=None):
    '''
    walk and save the stack trace for the current (or specified) thread.
    will be saved in the format [instr addr, frame pointer, name]

    @type  trace: vtrace
    @param trace: Instance of vtrace
    @type  thread: integer
    @param thread: id of thread to process seh chain

    @rtype:  list
    @return: list containing stack trace in (rva, instr addr, frame pointer) format
    '''
    stack_trace = []
    
    if thread is not None:
      try:
        trace.selectThread(thread)
      except:
        # if we can't select the given thread, it has likely died and it's stack will be unavailable.
        stack_trace.append((0, 0, "Unable to retrieve stack trace for given thread"))
        return stack_trace
      
    call_chain = trace.getStackTrace()
    
    for i in range(len(call_chain)):
      addr  = call_chain[i][0]
      frame = call_chain[i][1]
      name = self.addr_to_name(trace, addr) 
      stack_trace.append((addr,frame,name))

    return stack_trace


  ####################################################################################################################
  def seh_unwind(self, trace, thread):
    '''
    walk and save the SEH chain for the current (or specified) thread.
    will be saved in the format [reg record addr, handler, name]
    adapted from vdb/vdb/extensions/windows.py -> seh(vdb, line)

    @type  trace: vtrace
    @param trace: Instance of vtrace
    @type  thread: integer
    @param thread: id of thread to process seh chain

    @rtype:  list
    @return: list containing seh chain in (reg record addr, handler, name) format
    '''
    seh_chain = []

    if thread == 0:
      tid = trace.getMeta('ThreadId')
    else:
      tid = int(thread)

    tinfo = trace.getThreads().get(tid, None)
    if tinfo is None:
      return

    teb = trace.getStruct("ntdll.TEB", tinfo)
    addr = int(teb.NtTib.ExceptionList)

    while addr != 0xffffffff:
      try:
        er = trace.getStruct("ntdll.EXCEPTION_REGISTRATION_RECORD", addr)
        '''
        class EXCEPTION_REGISTRATION_RECORD (vstruct/defs/windows/win_6_3_wow64/ntdll.py)
        self.Next (v_ptr32)
        self.Handler (v_ptr32)
        '''
        name = self.addr_to_name(trace, er.Handler)
        seh_chain.append((addr, er.Handler, name))
        addr = int(er.Next)
      except Exception as e:
        break

    return seh_chain
  ###################################################################################################################
  def addr_to_name(self, trace, address):
      """
      Return a string representing the best known name for the given address
      adapted from vivisect/vdb/__init__.py -> reprPointer()
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

      return ""

  ####################################################################################################################
  def crash_synopsis (self, crash=None):
    '''
    For the supplied crash, generate and return a report containing the disassembly following the violating opcode,
    the ID of the offending thread, the call stack and the SEH chain. If no crash is specified, then return the 
    same information for the last recorded crash.

    @see: crash_synopsis()

    @type  crash: __crash_bin_struct__
    @param crash: (Optional, def=None) Crash object to generate report on

    @rtype:  String
    @return: Crash report
    '''

    if not crash:
      crash = self.last_crash

    if crash.write_violation:
      direction = "write to"
    else:
      direction = "read from"

    synopsis =f'{crash.exception_module}: ' + \
              f'{e_bits.hex(crash.exception_address, 4)} ' + \
              f'{crash.disasm} from thread ' + \
              f'{crash.violation_thread_id} caused memory fault when attempting to ' + \
              f'{direction} ' + \
              f'{e_bits.hex(crash.violation_address, 4)}'
    
    synopsis += "\nRegister context at time of memory fault:\n"
    synopsis += crash.context_dump

    synopsis += "\nDisassembly around point of failure:\n"
    for addr, op in crash.disasm_around:
      synopsis += f"\t{e_bits.hex(addr, 4)} {str(op)}\n"
    
    if len(crash.stack_unwind):
      synopsis += "\nCall stack:\n"
      for addr, frame, name in crash.stack_unwind:
        synopsis += f"\tAddress: {e_bits.hex(addr, 4)}\t Frame: {e_bits.hex(frame, 4)}\t name: {name}\n"

    if len(crash.seh_unwind):
      synopsis += "\nSEH chain:\n"
      for (addr, handler, name) in crash.seh_unwind:
        synopsis +=  f"\tAddress: {e_bits.hex(addr, 4)}\t Handler: {e_bits.hex(handler, 4)}\t name:{name}\n"
    
    return synopsis + "\n"


  ####################################################################################################################
  def export_file (self, file_name):
    '''
    Dump the entire object structure to disk.

    @see: import_file()

    @type  file_name:   String
    @param file_name:   File name to export to

    @rtype:             CrashBinning
    @return:            self
    '''

    # null out what we don't serialize but save copies to restore after dumping to disk.
    last_crash = self.last_crash
    trace      = self.trace
    arch       = self.arch

    self.last_crash = self.trace = self.arch = None

    with open(file_name, "wb") as fh:
      pickle.dump(self, fh)
    fh.close()

    self.last_crash = last_crash
    self.trace      = trace
    self.arch       = arch

    return self


  ####################################################################################################################
  def import_file (self, file_name):
    '''
    Load the entire object structure from disk.

    @see: export_file()

    @type  file_name:   String
    @param file_name:   File name to import from

    @rtype:             CrashBinning
    @return:            self
    '''

    with open(file_name, "rb") as fh:
      tmp = pickle.load(fh)
    
    fh.close()
    return tmp


  ####################################################################################################################
