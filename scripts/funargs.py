from idapy import *
#from scripts import *
import re, string
import idapy


def fail(e):
    print "Unhandled case:", GetDisasm(e)
    ops = []
    for i in range(10):
        if GetOpType(e,i) <= 0: break
        ops.append((GetOpnd(e,i), GetOpType(e,i), GetOperandValue(e,i)))
    print ops


def RegReadsAndWrites(e, acc):
    mne = GetMnem(e)
    if mne in ["MOV", "MVN"]:
        t0 = GetOpType(e,0); v0 = GetOperandValue(e,0)
        t1 = GetOpType(e,1); v1 = GetOperandValue(e,1)
        
        if t1 in [o_reg, o_regshift]:
            if v1 <= 3: acc[v1] += "R"
        
        elif t1 == 8:
            for r in getRegs03(GetOpnd(e,1)):
                acc[r] += "R"

        elif t1 == o_imm: pass
        else: fail(e)

        if t0 in [o_reg, o_regshift]:
            if v0 <= 3: acc[v0] += "W"
            
        else: fail(e)

    elif mne in ["LDR", "STR"]:
        t0 = GetOpType(e,0); v0 = GetOperandValue(e,0)
        t1 = GetOpType(e,1); v1 = GetOperandValue(e,1)

        if t1 in [o_phrase, o_displ]:
            for r in getRegs03(GetOpnd(e,1)):
                acc[r] += "r"
        elif t1 in [o_mem, o_imm, o_far, o_near]: pass
        else: fail(e)
        
        if t0 in [o_reg, o_regshift]:
            if v0 <= 3: acc[v0] += ("W" if mne == "LDR" else "R")
        else: fail(e)

    elif mne in ["ADR"]:
        t0 = GetOpType(e,0); v0 = GetOperandValue(e,0)
        
        if t0 in [o_reg, o_regshift]:
            if v0 <= 3: acc[v0] += "W"
        else: fail(e)

    elif mne in ["ADD", "SUB", "MUL", "AND", "ORR", "EOR", "ADC", "SBC", "RSB", "RSC", ]:
        t0 = GetOpType(e,0); v0 = GetOperandValue(e,0)
        t1 = GetOpType(e,1); v1 = GetOperandValue(e,1)
        t2 = GetOpType(e,2); v2 = GetOperandValue(e,2)

        if t1 in [o_reg, o_regshift]:
            if v1 <= 3: acc[v1] += "R"
        elif t1 == o_imm: pass
        else: fail(e)

        if t2 in [o_reg, o_regshift]:
            if v2 <= 3: acc[v2] += "R"
        elif t2 == o_imm: pass
        else: fail(e)
        
        if t0 in [o_reg, o_regshift]:
            if v0 <= 3: acc[v0] += "W"
        elif t0 == o_imm: pass
        else: fail(e)

    elif mne in ["CMP", "CMN", "TST", "TEQ"]: # read-only operands
        t0 = GetOpType(e,0); v0 = GetOperandValue(e,0)
        t1 = GetOpType(e,1); v1 = GetOperandValue(e,1)

        if t0 in [o_reg, o_regshift]:
            if v0 <= 3: acc[v0] += "R"
        elif t0 == o_imm: pass
        else: fail(e)

        if t1 in [o_reg, o_regshift]:
            if v1 <= 3: acc[v1] += "R"
        elif t1 == o_imm: pass
        else: fail(e)

    elif mne == "PUSH":
        for v in getRegs03(GetOpnd(e,0)):
            acc[v] += "R"
    elif mne == "POP":
        for v in getRegs03(GetOpnd(e,0)):
            acc[v] += "W"
    elif mne == "STM":
        for v in getRegs03(GetOpnd(e,0)):
            acc[v] += "R"
        for v in getRegs03(GetOpnd(e,1)):
            acc[v] += "R"
    elif mne == "LDM":
        for v in getRegs03(GetOpnd(e,0)):
            acc[v] += "R"
        for v in getRegs03(GetOpnd(e,1)):
            acc[v] += "W"

        
    
    else:
        print "Unhandled instruction:", GetDisasm(e)
        regs = getRegs03(GetDisasm(e))
        if regs:
            print "Registers accessed (don't know if R or W):", regs
    return acc

def guessargs(ea, quick=True):

    acc = {0: "", 1: "", 2: "", 3: ""}

    funcname = GetFunctionName(ea)
    print "Guessing args for", funcname
    if quick:
        try: CP = [list(FuncItems(ea))]
        except: CP = [range(ea,ea+40,4)]
    else:
        CP = emusym.find_code_paths(ea)
        CP = sorted(CP, key=lambda x: -len(x))
        CP = [emusym.split_code_path_ea_cond(cp)[0] for cp in CP]
    for cp in CP:
        for e in cp:
            #~ print "%X"%e, GetDisasm(e)
            #~ ops = []
            #~ for i iguessan range(10):
                #~ if GetOpType(e,i) <= 0: break
                #~ ops.append((GetOpnd(e,i), GetOpType(e,i), GetOperandValue(e,i)))
            #print ops

            mne = GetMnem(e)
            
            if mne in ["BL", "BX"] and not GetCondSuffix(e):
                print "found function call, stopping here"
                print "%X"%e, GetDisasm(e)
                break

            elif mne == "B" and not GetCondSuffix(e):
                if quick:
                    print "jumps are not handled"
                    print "%X"%e, GetDisasm(e)
                    break

            else:
                #~ print "%X"%e, GetDisasm(e)
                RegReadsAndWrites(e, acc)
                #~ print RegReadsAndWrites(e, {0: "", 1: "", 2: "", 3: ""})

        #~ print acc

        for i in range(3,0,-1):
            if acc[i] and acc[i][0] in ["R", "r"] and acc[i-1] == "":
                acc[i-1] = acc[i][0]

        args = []
        for i in range(4):
            if len(acc[i]) == 0:
                break
                
            if acc[i][0] == "R":
                args.append("int R%d" % i)
            elif acc[i][0] == "r":
                args.append("void* R%d" % i)
            else:
                break

        #~ print    
        type = "int " + funcname + "(" + string.join(args, ", ") + ");"
        print type
        return args


void = "void"
ptr = "ptr"

class FSig:
    def __init__(self, *args, **kwargs):
        self.args = []
        self.ret = None
        for a in args:
            if type(a)==tuple:
                self.args.append(a)
            else:
                self.args.append((None,a))
        self.__dict__.update(kwargs)
    def arg(i):
        return self.args[i]

    numargs = property(lambda self: len(self.args))

FS = {}
FS["DebugMsg"] = FSig(int, int, ('msg',str), None, None, None, None, None, None, ret=void)
FS["prop_request_change"] = FSig(('property',hex), ('address',ptr), ('len',int), ret=void)
FS["prop_register_slave"] = FSig(('property_list',ptr), ('count',int), ('prop_handler',ptr), ('priv',ptr), ('token_handler',ptr), ret=void)
FS["FIO_CreateFile"] = FSig(('name',str), ret=int)
FS["FIO_WriteFile"] = FSig(('handle',int), ('start_addr',ptr), ('length',int), ret=int)
FS["FIO_CloseFile"] = FSig(('handle',int), ret=int)
FS["call"] = FSig(('name',str), None, None, ret=void)
FS["LoadCalendarFromRTC"] = FSig(ptr, ret=void)
FS["AllocateMemory"] = FSig(int, ret=ptr)
FS["register_interrupt"] = FSig(None, None, None, None, ret=void)
FS["register_func"] = FSig(None, None, None, None, ret=void)
FS["cmpString"] = FSig(None, None, ret=int)
FS["task_create"] = FSig(None, None, None, None, None, ret=void)
FS["dma_addr_to_user_addr"] = FSig(int, ret=int)
FS["SubscribeNotifyFromPartner"] = FSig(None, None, ret=void)
FS["SubscribeSwitchFromPartner"] = FSig(None, None, ret=void)
FS["SubscribeSpecificFromPartner"] = FSig(None, None, ret=void)
FS["SubscribeLCDFromPartner"] = FSig(None, None, ret=void)
FS["SubscribeLiveViewFromPartner"] = FSig(None, None, ret=void)
FS["SubscribeMachineCellFromPartner"] = FSig(None, None, ret=void)
FS["SubscribeFactoryFromPartner"] = FSig(None, None, ret=void)
FS["div_maybe"] = FSig(int, int, ret=int)
FS["delay_allocate_maybe"] = FSig(None, None, None, None, None, None, ret=None)
FS["calls_delay_allocate_maybe"] = FSig(None, None, None, None, None, None, ret=None)
FS["create_task_class_maybe"] = FSig(None, None, None, None, None, ret=None)
FS["CreateStateObject"] = FSig(("name", str), None, ("addr", hex), ("inputs", int), ("states", int), ret=None)
FS["gui_change_mode_post"] = FSig(None, ret=void)
FS["gui_timer_something"] = FSig(None, None, ret=void)
FS["gui_local_post"] = FSig(None, None, None, ret=void)
FS["gui_other_post"] = FSig(None, None, None, ret=void)
FS["if_A_eq_B_print_C_else_print_D"] = FSig(None, None, str, str, ret=void)

def getFuncSignature(ea):
    fn = GetName(ea)
    if fn in FS:
        return FS[fn]
        
    defa = FSig(None, None, None, None, ret=None)
    if ea < idapy._d.minaddr or ea > idapy._d.maxaddr:
        return defa
    try: args = cache.access((idapy._d.bin, ea), lambda x: guessargs(ea))
    except:
        print "could not guess args for", hex(ea)
        return defa
    if len(args) == 0:
        return FSig(ret=None)
    if len(args) == 1:
        return FSig(None, ret=None)
    if len(args) == 2:
        return FSig(None, None, ret=None)
    if len(args) == 3:
        return FSig(None, None, None, ret=None)
    return defa
