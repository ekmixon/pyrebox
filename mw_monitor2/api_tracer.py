# -------------------------------------------------------------------------
#
#   Copyright (C) 2018 Cisco Talos Security Intelligence and Research Group
#
#   PyREBox: Python scriptable Reverse Engineering Sandbox
#   Author: Xabier Ugarte-Pedrero
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License version 2 as
#   published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#   MA 02110-1301, USA.
#
# -------------------------------------------------------------------------

from __future__ import print_function
import os
import json
import functools
import fnmatch
import traceback
import pickle

# Determine TARGET_LONG_SIZE
from api import get_os_bits
TARGET_LONG_SIZE = get_os_bits() / 8

# Script requirements
requirements = ["mw_monitor2.interproc"]

# Global variables
# Callback manager
cm = None
# Printer
pyrebox_print = None

# Return breakpoint counter
bp_counter = 0

# Configuration values
APITRACER_BIN_LOG_PATH = "apitracer.bin" 
APITRACER_TEXT_LOG_PATH = "apitracer.log"
# Inclusion-exclusion lists, dict like:
#{
#  "policy": "accept|reject",
#  "rules": [{"action": "accept",
#             "mod": "kernel32.dll",
#             "fun": "*",
#             "from_mod": "ntdll.dll", 
#            {"action": "accept",
#             "mod": "*",
#             "fun": "ExitProc*"},
#            {"action": "reject"
#             "mod": "ntdll*",
#             "fun": "Zw*"}]
#}
APITRACER_RULES = {} 
APITRACER_LIGHT_MODE = True 
APITRACER_DATABASE32 = None
APITRACER_DATABASE64 = None

APITRACER_ANTI_STOLEN = False
APITRACER_ENABLE_JMP = False
APITRACER_ENABLE_RET = False

def serialize_calls():
    from interproc import interproc_data
    global pyrebox_print
    try:
        with open(APITRACER_BIN_LOG_PATH, "w") as f_out:
            pickle.dump(interproc_data.get_processes(), f_out)
    except Exception:
        traceback.print_exc()
        pyrebox_print(traceback.print_stack())

def log_calls():
    import api
    from interproc import interproc_data

    TARGET_LONG_SIZE = api.get_os_bits() / 8

    f_out = open(APITRACER_TEXT_LOG_PATH, "w")

    try:
        for proc in interproc_data.get_processes():

            f_out.write("Process (PID: %x) %s\n" %
                        (proc.get_pid(), proc.get_proc_name()))

            for vad in proc.get_vads():
                if len(vad.get_calls()) > 0:
                    if TARGET_LONG_SIZE == 4:
                        f_out.write("\n\nVAD [%08x - %08x] - %s\n\n" % (vad.get_start(), vad.get_size(), (vad.get_mapped_file() if vad.get_mapped_file() is not None else "Not file mapped")))
                    elif TARGET_LONG_SIZE == 8:
                        f_out.write("\n\nVAD [%016x - %016x] - %s\n\n" % (vad.get_start(), vad.get_size(), (vad.get_mapped_file() if vad.get_mapped_file() is not None else "Not file mapped")))
                    for data in vad.get_calls():
                        f_out.write(f"{data[2].__str__()}")

            if len(proc.get_other_calls()) > 0:
                f_out.write("\n\n OTHER CALLS...\n\n")
                for call in proc.get_other_calls():
                    f_out.write(f"{data[2].__str__()}")
        if f_out is not None:
            f_out.close()
    except Exception as e:
        pyrebox_print(str(e))
        pyrebox_print(traceback.print_exc())

    # Output ordered calls
    f_out = open(f"{APITRACER_TEXT_LOG_PATH}.ordered", "w")
    try:
        for proc in interproc_data.get_processes():
            f_out.write("Process (PID: %x) %s\n" %
                        (proc.get_pid(), proc.get_proc_name()))
            for data in proc.get_all_calls():
                f_out.write(f"{data[2].__str__()}")
        if f_out is not None:
            f_out.close()
    except Exception as e:
        pyrebox_print(str(e))
        pyrebox_print(traceback.print_exc())

class APICallData:

    def __init__(self):
        self.__in_args = []
        self.__out_args = []
        self.__ret = None
        self.__pc = None
        self.__mod = None
        self.__fun = None
        self.__ret_addr = None

    def get_in_args(self):
        return self.__in_args

    def set_in_args(self, args):
        self.__in_args = args

    def get_out_args(self):
        return self.__out_args

    def set_out_args(self, args):
        self.__out_args = args

    def get_ret(self):
        return self.__ret

    def set_ret(self, ret):
        self.__ret = ret

    def get_pc(self):
        return self.__pc

    def set_pc(self, pc):
        self.__pc = pc

    def get_mod(self, mod):
        self.__mod = mod

    def set_mod(self, mod):
        self.__mod = mod

    def get_fun(self, fun):
        return self.__fun

    def set_fun(self, fun):
        self.__fun = fun

    def get_ret_addr(self):
        return self.__ret_addr

    def set_ret_addr(self, ret_addr):
        self.__ret_addr = ret_addr

    def __str__(self):
        import api
        TARGET_LONG_SIZE = api.get_os_bits() / 8
        try:
            outstr = ""
            if TARGET_LONG_SIZE == 4:
                outstr += ("\n\n\n[0x%08x] --> [%s:%s] --> [0x%08x]\n" %
                           (self.__pc, self.__mod, self.__fun, self.__ret_addr))
            elif TARGET_LONG_SIZE == 8:
                outstr += ("\n\n\n[0x%016x] --> [%s:%s] --> [0x%016x]\n" %
                           (self.__pc, self.__mod, self.__fun, self.__ret_addr))
            args = sorted(self.__in_args + self.__out_args)
            for arg in args:
                if arg.is_output_arg():
                    try:
                        outstr += ("[OUT] %s: %s\n" %
                                   (arg.get_arg_name(), arg.__str__()))
                    except Exception as e:
                        outstr += (
                            "[OUT] %s: Unable to process: %s\n" % (arg.get_arg_name(), str(e)))
                else:
                    try:
                        outstr += ("[IN ] %s: %s\n" %
                                   (arg.get_arg_name(), arg.__str__()))
                    except Exception as e:
                        outstr += (
                            "[IN] %s: Unable to process : %s\n" % (arg.get_arg_name(), str(e)))
            if self.__ret is not None and self.__ret is not "":
                try:
                    outstr += ("[RET] %s: %s\n" %
                               (self.__ret.get_arg_name(), self.__ret.__str__()))
                except Exception as e:
                    outstr += ("[RET] %s: Unable to process: %s\n" %
                               (self.__ret.get_arg_name(), str(e)))
            return outstr
        except Exception as e:
            pyrebox_print(traceback.print_exc())
            pyrebox_print(str(e))


def opcodes_ret(addr_from, addr_to, data, callback_name, argument_parser, mod, fun, proc, params):
    import api
    global cm
    TARGET_LONG_SIZE = api.get_os_bits() / 8

    cpu_index = params["cpu_index"]
    cpu = params["cpu"]

    try:
        cm.rm_callback(callback_name)
        if TARGET_LONG_SIZE == 4:
            argument_parser.update_return(cpu.EAX)
        elif TARGET_LONG_SIZE == 8:
            argument_parser.update_return(cpu.RAX)
        data.set_out_args(list(argument_parser.get_out_args()))
        data.set_ret(argument_parser.get_ret())
    except Exception as e:
        pyrebox_print(f"Exception: {str(e)}")
    finally:
        return


def opcodes(params, cb_name, proc):
    from api import CallbackManager
    import api
    from deviare_db_parser import ArgumentParser
    import struct

    global bp_counter
    global APITRACER_DATABASE32
    global APITRACER_DATABASE64
    global APITRACER_RULES
    global APITRACER_ANTI_STOLEN

    TARGET_LONG_SIZE = api.get_os_bits() / 8

    cpu_index = params["cpu_index"]
    cpu = params["cpu"]
    pc = params["cur_pc"]
    next_pc = params["next_pc"]
    pgd = api.get_running_process(cpu_index)

    try:
        if APITRACER_ANTI_STOLEN:
            # Locate nearest lower symbol
            sym = proc.locate_nearest_symbol(next_pc)
        else:
            sym = proc.locate_nearest_symbol(next_pc, tolerate_offset = 0x0)

        if sym is None:
            return


        mod = sym.get_mod()
        mod_fullname = sym.get_mod_fullname()
        fun = sym.get_fun()
        real_api_addr = sym.get_addr()


        caller_module_name = proc.get_overlapping_module(pc)

        # Reduce FP's by checking that the origin EIP is not also within the
        # same module (code reuse inside the dll)

        if mod_fullname == caller_module_name:
            return

        matched = False
        # Check if the API is in the list (included or excluded)
        for rule in APITRACER_RULES["rules"]:
            if (
                rule["mod"] == ""
                or fnmatch.fnmatch(mod_fullname.lower(), rule["mod"].lower())
            ) and (
                rule["fun"] == ""
                or fnmatch.fnmatch(fun.lower(), rule["fun"].lower())
            ):
                if "from_mod" in rule and rule["from_mod"] != "":
                    if caller_module_name is not None and fnmatch.fnmatch(
                        caller_module_name, rule["from_mod"].lower()
                    ):
                        matched = True
                        if rule["action"] == "reject":
                            return
                        else:
                            break
                        break
                else:  
                    matched = True
                    if rule["action"] == "reject":
                        return
                    else:
                        break

        # Apply default policy if not matched: 
        if not matched and APITRACER_RULES["policy"] == "reject":
            return

        # Set callback on return address
        if TARGET_LONG_SIZE == 4:
            try:
                ret_addr_val = api.r_va(pgd, cpu.ESP, 4)
                ret_addr = struct.unpack("<I", ret_addr_val)[0]
            except Exception as e:
                ret_addr = 0
                pyrebox_print(f"Could not read return address on API tracer: {str(e)}")
        elif TARGET_LONG_SIZE == 8:
            try:
                ret_addr_val = api.r_va(pgd, cpu.RSP, 8)
                ret_addr = struct.unpack("<Q", ret_addr_val)[0]
            except Exception as e:
                ret_addr = 0
                pyrebox_print(f"Could not read return address on API tracer: {str(e)}")

        is_64_bit_dll = TARGET_LONG_SIZE != 4 and (
            TARGET_LONG_SIZE != 8
            or not proc.is_wow64()
            or "windows\\syswow64" not in mod_fullname.lower()
        )

        if APITRACER_LIGHT_MODE:
            bits = 64 if is_64_bit_dll else 32
            if real_api_addr == next_pc:
                if TARGET_LONG_SIZE == 4:
                    proc.add_call(pc, real_api_addr, "[PID: %x] (%d) %08x --> %s:%s(%08x) --> %08x\n" % (
                        proc.get_pid(), bits, pc, mod_fullname, fun, real_api_addr, ret_addr))
                elif TARGET_LONG_SIZE == 8:
                    proc.add_call(pc, real_api_addr, "[PID: %x] (%d) %016x --> %s:%s(%016x) --> %016x\n" % (
                        proc.get_pid(), bits, pc, mod_fullname, fun, real_api_addr, ret_addr))
            elif TARGET_LONG_SIZE == 4:
                proc.add_call(pc, real_api_addr, "[PID: %x] (%d) %08x --> %s:%s(+%x)(%08x) --> %08x\n" % (
                    proc.get_pid(), bits, pc, mod_fullname, fun, (next_pc - real_api_addr), next_pc, ret_addr))
            elif TARGET_LONG_SIZE == 8:
                proc.add_call(pc, real_api_addr, "[PID: %x] (%d) %016x --> %s:%s(+%x)(%016x) --> %016x\n" % (
                    proc.get_pid(), bits, pc, mod_fullname, fun, (next_pc - real_api_addr), next_pc, ret_addr))
            return

        data = APICallData()
        data.set_pc(pc)
        data.set_mod(mod)
        data.set_fun(fun)
        data.set_ret_addr(ret_addr)

        argument_parser = (
            ArgumentParser(cpu, cpu.RSP, mod, fun, 64)
            if is_64_bit_dll
            else ArgumentParser(cpu, cpu.ESP, mod, fun, 32)
        )

        if not argument_parser.in_db():
            #pyrebox_print("API function not present in db: %s - %s" % (mod, fun))
            return

        data.set_in_args(list(argument_parser.get_in_args()))

        # Add the call as soon as it is produced, and update
        # the output parameters on return
        proc.add_call(pc, real_api_addr, data)

        # If return address could not be read, we skip the callback
        if ret_addr != 0:
            callback_name = "ret_bp_%d" % bp_counter

            callback = functools.partial(opcodes_ret,
                                         pc,
                                         real_api_addr,
                                         data,
                                         callback_name,
                                         argument_parser,
                                         mod,
                                         fun,
                                         proc)

            cm.add_callback(CallbackManager.INSN_BEGIN_CB,
                                  callback,
                                  name=callback_name,
                                  addr=data.get_ret_addr(),
                                  pgd=pgd)

            bp_counter += 1

    except Exception as e:
        pyrebox_print(str(e))
        traceback.print_exc()
    finally:
        return


def module_load(params):
    global interproc_data

    pid = params["pid"]
    pgd = params["pgd"]
    base = params["base"]
    size = params["size"]
    name = params["name"]
    fullname = params["fullname"]

    if proc := interproc_data.get_process_by_pgd(pgd):
        proc.update_symbols()


def module_entry_point(params):
    '''
        Callback on the entry point of the main module being monitored
    '''
    global APITRACER_ANTI_STOLEN
    global APITRACER_ENABLE_JMP
    global APITRACER_ENABLE_RET

    global cm
    global pyrebox_print
    import os
    from api import CallbackManager
    import api
    from interproc import interproc_data

    # Get pameters
    cpu_index = params["cpu_index"]
    cpu = params["cpu"]

    # Get running process
    pgd = api.get_running_process(cpu_index)

    new_proc = interproc_data.get_process_by_pgd(pgd)

    pid = new_proc.get_pid()

    pyrebox_print("Initializing API tracer for process %x" % pgd)
    
    cb_func = functools.partial(opcodes, proc = new_proc)

    #E8 cw   CALL rel16  Call near, relative, displacement relative to next instruction
    #E8 cd   CALL rel32  Call near, relative, displacement relative to next instruction
    #FF /2   CALL r/m16  Call near, absolute indirect, address given in r/m16
    #FF /2   CALL r/m32  Call near, absolute indirect, address given in r/m32
    #9A cd   CALL ptr16:16   Call far, absolute, address given in operand
    #9A cp   CALL ptr16:32   Call far, absolute, address given in operand
    #FF /3   CALL m16:16 Call far, absolute indirect, address given in m16:16
    #FF /3   CALL m16:32 Call far, absolute indirect, address given in m16:32

    cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(cb_func, cb_name="call_e8_%x" % pid), name="call_e8_%x" % pid, start_opcode=0xE8, end_opcode=0xE8)
    cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(cb_func, cb_name="call_ff_%x" % pid), name="call_ff_%x" % pid, start_opcode=0xFF, end_opcode=0xFF)
    cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(cb_func, cb_name="call_9a_%x" % pid), name="call_9a_%x" % pid, start_opcode=0x9A, end_opcode=0x9A)

    cm.add_trigger("call_e8_%x" % pid, "mw_monitor2/trigger_jmp_call_ret_tracer.so")
    cm.set_trigger_var("call_e8_%x" % pid, "pgd", pgd)
    cm.set_trigger_var("call_e8_%x" % pid, "enable_ff_jmp", 1 if APITRACER_ENABLE_JMP else 0)

    cm.add_trigger("call_ff_%x" % pid, "mw_monitor2/trigger_jmp_call_ret_tracer.so")
    cm.set_trigger_var("call_ff_%x" % pid, "pgd", pgd)
    cm.set_trigger_var("call_ff_%x" % pid, "enable_ff_jmp", 1 if APITRACER_ENABLE_JMP else 0)

    cm.add_trigger("call_9a_%x" % pid, "mw_monitor2/trigger_jmp_call_ret_tracer.so")
    cm.set_trigger_var("call_9a_%x" % pid, "pgd", pgd)
    cm.set_trigger_var("call_9a_%x" % pid, "enable_ff_jmp", 1 if APITRACER_ENABLE_JMP else 0)

    #C3 RET NP Valid Valid Near return to calling procedure.
    #CB RET NP Valid Valid Far return to calling procedure.
    #C2 iw RET imm16 I Valid Valid Near return to calling procedure and pop imm16 bytes from stack.
    #CA iw RET imm16 I Valid Valid Far return to calling procedure and pop imm16 bytes from stack.

    if APITRACER_ENABLE_RET:
        cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(cb_func, cb_name="ret_c3_%x" % pid), name="ret_c3_%x" % pid, start_opcode=0xC3, end_opcode=0xC3)
        cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(cb_func, cb_name="ret_cb_%x" % pid), name="ret_cb_%x" % pid, start_opcode=0xCB, end_opcode=0xCB)
        cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(cb_func, cb_name="ret_c2_%x" % pid), name="ret_c2_%x" % pid, start_opcode=0xC2, end_opcode=0xC2)
        cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(cb_func, cb_name="ret_ca_%x" % pid), name="ret_ca_%x" % pid, start_opcode=0xCA, end_opcode=0xCA)

        cm.add_trigger("ret_c3_%x" % pid, "mw_monitor2/trigger_jmp_call_ret_tracer.so")
        cm.set_trigger_var("ret_c3_%x" % pid, "pgd", pgd)
        cm.set_trigger_var("ret_c3_%x" % pid, "enable_ff_jmp", 1 if APITRACER_ENABLE_JMP else 0)

        cm.add_trigger("ret_cb_%x" % pid, "mw_monitor2/trigger_jmp_call_ret_tracer.so")
        cm.set_trigger_var("ret_cb_%x" % pid, "pgd", pgd)
        cm.set_trigger_var("ret_cb_%x" % pid, "enable_ff_jmp", 1 if APITRACER_ENABLE_JMP else 0)

        cm.add_trigger("ret_c2_%x" % pid, "mw_monitor2/trigger_jmp_call_ret_tracer.so")
        cm.set_trigger_var("ret_c2_%x" % pid, "pgd", pgd)
        cm.set_trigger_var("ret_c2_%x" % pid, "enable_ff_jmp", 1 if APITRACER_ENABLE_JMP else 0)

        cm.add_trigger("ret_ca_%x" % pid, "mw_monitor2/trigger_jmp_call_ret_tracer.so")
        cm.set_trigger_var("ret_ca_%x" % pid, "pgd", pgd)
        cm.set_trigger_var("ret_ca_%x" % pid, "enable_ff_jmp", 1 if APITRACER_ENABLE_JMP else 0)


    #EB cb JMP rel8       Jump short, RIP = RIP + 8-bit displacement sign extended to 64-bits
    #E9 cw JMP rel16      Jump near, relative, displacement relative to next instruction. Not supported in 64-bit mode.
    #E9 cd JMP rel32      Jump near, relative, RIP = RIP + 32-bit displacement sign extended to 64-bits
    #FF /4 JMP r/m16      Jump near, absolute indirect, address = zeroextended r/m16. Not supported in 64-bit mode.
    #FF /4 JMP r/m32      Jump near, absolute indirect, address given in r/m32. Not supported in 64-bit mode.
    #FF /4 JMP r/m64      Jump near, absolute indirect, RIP = 64-Bit offset from register or memory
    #EA cd JMP ptr16:16   Jump far, absolute, address given in operand
    #EA cp JMP ptr16:32   Jump far, absolute, address given in operand
    #FF /5 JMP m16:16     Jump far, absolute indirect, address given in m16:16
    #FF /5 JMP m16:32     Jump far, absolute indirect, address given in m16:32.
    #FF /5 JMP m16:64     Jump far, absolute indirect, address given in m16:64

    if APITRACER_ENABLE_JMP:
        cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(cb_func, cb_name="jmp_e9_%x" % pid), name="jmp_e9_%x" % pid, start_opcode=0xE9, end_opcode=0xE9)
        cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(cb_func, cb_name="jmp_ea_%x" % pid), name="jmp_ea_%x" % pid, start_opcode=0xEA, end_opcode=0xEA)
        cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(cb_func, cb_name="jmp_eb_%x" % pid), name="jmp_eb_%x" % pid, start_opcode=0xEB, end_opcode=0xEB)

        cm.add_trigger("jmp_e9_%x" % pid, "mw_monitor2/trigger_jmp_call_ret_tracer.so")
        cm.set_trigger_var("jmp_e9_%x" % pid, "pgd", pgd)
        cm.set_trigger_var("jmp_e9_%x" % pid, "enable_ff_jmp", 1 if APITRACER_ENABLE_JMP else 0)

        cm.add_trigger("jmp_ea_%x" % pid, "mw_monitor2/trigger_jmp_call_ret_tracer.so")
        cm.set_trigger_var("jmp_ea_%x" % pid, "pgd", pgd)
        cm.set_trigger_var("jmp_ea_%x" % pid, "enable_ff_jmp", 1 if APITRACER_ENABLE_JMP else 0)

        cm.add_trigger("jmp_eb_%x" % pid, "mw_monitor2/trigger_jmp_call_ret_tracer.so")
        cm.set_trigger_var("jmp_eb_%x" % pid, "pgd", pgd)
        cm.set_trigger_var("jmp_eb_%x" % pid, "enable_ff_jmp", 1 if APITRACER_ENABLE_JMP else 0)

    # Start monitoring process
    api.start_monitoring_process(pgd)

def clean():
    '''
    Clean up everything. At least you need to place this
    clean() call to the callback manager, that will
    unregister all the registered callbacks.
    '''
    global cm
    global pyrebox_print
    global interproc_data

    pyrebox_print("[*]    Cleaning module")
    interproc_data.remove_entry_point_callback(module_entry_point)
    cm.clean()
    serialize_calls()
    log_calls()
    pyrebox_print("[*]    Cleaned module")


def initialize_callbacks(module_hdl, printer):
    '''
    Initialize callbacks for this module. This function
    will be triggered whenever import_module command
    is triggered.
    '''
    from api import CallbackManager
    from plugins.guest_agent import guest_agent
    from mw_monitor2.interproc import interproc_data
    from deviare_db_parser import set_db_path 

    global cm
    global pyrebox_print
    global APITRACER_BIN_LOG_PATH
    global APITRACER_TEXT_LOG_PATH
    global APITRACER_RULES
    global APITRACER_LIGHT_MODE
    global APITRACER_DATABASE32
    global APITRACER_DATABASE64
    global APITRACER_ANTI_STOLEN
    global APITRACER_ENABLE_JMP
    global APITRACER_ENABLE_RET

    global interproc_data

    pyrebox_print = printer

    # Set configuration values
    try:
        f = open(os.environ["MWMONITOR_APITRACER_CONF_PATH"], "r")
        conf_data = json.load(f)
        f.close()
        APITRACER_BIN_LOG_PATH = conf_data.get("bin_log_path", None)
        APITRACER_TEXT_LOG_PATH = conf_data.get("text_log_path", None)
        APITRACER_RULES = conf_data.get("rules", [])
        # Validate the rules
        if "policy" not in APITRACER_RULES:
            raise Exception("Invalid rules configuration: no policy specified")
        if APITRACER_RULES["policy"] != "accept" and APITRACER_RULES["policy"] != "reject":
            raise Exception("Invalid rules configuration: policy must be 'reject' or 'accept'")
        if "rules" not in APITRACER_RULES or not isinstance(APITRACER_RULES["rules"], list):
            raise Exception("Invalid rules configuration: no rules group")
        for ru in APITRACER_RULES["rules"]:
            if not isinstance(ru, dict):
                raise Exception("Invalid rules configuration: each rule must be a dictionary")
            if "action" not in ru or "mod" not in ru or "fun" not in ru:
                raise Exception("Invalid rules configuration: each rule must contain the keywords: action, mod, and fun")
            if not (isinstance(ru["action"], str) or isinstance(ru["action"], unicode)):
                raise Exception("Invalid rules configuration: action keyword must be str or unicode")
            if not (isinstance(ru["mod"], str) or isinstance(ru["mod"], unicode)):
                raise Exception("Invalid rules configuration: mod keyword must be str or unicode")
            if not (isinstance(ru["fun"], str) or isinstance(ru["fun"], unicode)):
                raise Exception("Invalid rules configuration: fun keyword must be str or unicode")
            for kw in ru:
                if kw not in ["action", "mod", "fun", "from_mod"]:
                    raise Exception("Invalid rules configuration: Invalid keyword: %s" % kw)
            if ru["action"] != "accept" and ru["action"] != "reject":
                raise Exception("Rule action must be either 'accept' or 'reject'")

        APITRACER_LIGHT_MODE = conf_data.get("light_mode", True)
        
        if not "database_path_32" in conf_data:
            raise Exception("Database path ('database_path_32') not properly specified")

        if not "database_path_64" in conf_data:
            raise Exception("Database path ('database_path_64') not properly specified")

        APITRACER_DATABASE32 = conf_data.get("database_path_32", None)
        set_db_path(APITRACER_DATABASE32, 32)
        APITRACER_DATABASE64 = conf_data.get("database_path_64", None)
        set_db_path(APITRACER_DATABASE64, 64)


        # Tracing engine configuration
        if "anti_stolen_bytes" in conf_data:
            APITRACER_ANTI_STOLEN = conf_data["anti_stolen_bytes"]
        else:
            APITRACER_ANTI_STOLEN = False

        if "enable_jmp_tracing" in conf_data:
            APITRACER_ENABLE_JMP = conf_data["enable_jmp_tracing"]
        else:
            APITRACER_ENABLE_JMP = False
        
        if "enable_ret_tracing" in conf_data:
            APITRACER_ENABLE_RET = conf_data["enable_ret_tracing"] 
        else:
            APITRACER_ENABLE_RET = False


        if APITRACER_BIN_LOG_PATH is None or APITRACER_TEXT_LOG_PATH is None:
            raise ValueError("The json configuration file is not well-formed: fields missing?")
    except Exception as e:
        pyrebox_print("Could not read or correctly process the configuration file: %s" % str(e))
        return
    
    try:
        # Initialize process creation callback
        pyrebox_print("[*]    Initializing callbacks")
        interproc_data.register_entry_point_callback(module_entry_point)
        interproc_data.register_load_module_callback(module_load)
        cm = CallbackManager(module_hdl, new_style = True)
        pyrebox_print("[*]    Initialized callbacks")
    except Exception as e:
        traceback.print_exc()

if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
