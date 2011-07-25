# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# Module bkt: (back)tracing ASM function calls and register values

import time
from copy import copy
import sys
import pydot, string

import inspect, os
from emusym import *
from pprint import pprint
from idapy import *
import deco

#~ resetLog()
#~ resetArm()

def go_back(cp):
    #~ print cp
    prev_addrs = list(CodeRefsTo(cp[0], 1))
    for p in sorted(prev_addrs, key=lambda x: abs(x - cp[0]) + (1000 if x > cp[0] else 0)):
        #~ print "%X"%p, GetDisasm(p)
        if p not in cp:
            cp = [p] + cp
            return cp

    raise Exception, "Loop detected"


def back_solve(ea, unknowns):
    resetArm()
    
    if type(unknowns) == list:
        regs = unknowns
    else:
        regs = [unknowns]

    cp = [ea]
    lucky = True
    while not isFuncStart(cp[0]) and len(cp) < 100:
        try:
            cp = go_back(cp)
            if lucky and regs == ['ARM.'+r for r in WrittenRegs(cp[0])]: # quick heuristic for a simple unknown
                #~ print cp
                sol = try_solve(cp,regs)
                if sol is not None: return sol
                #~ else: lucky = False
        except IndexError:
            print "WARNING: no code refs to %X" % cp[0]
            break
        except:
            pass
            break

    resetArm(func = isFuncStart(cp[0]))
    if len(set(cp)) != len(cp):
        print "code path contains loops => skipping"
        
    return try_solve(cp, regs, force=True)

def back_deco(ea):
    resetArm()
    
    cp = [ea]
    while not isFuncStart(cp[0]):
        try:
            cp = go_back(cp)
        except IndexError:
            print "WARNING: no code refs to %X" % cp[0]
            break
        except:
            pass
            break

    resetArm(True)
    #~ emusym.print_cp(cp)
    cp = emusym.strip_wrong_branches(cp)
    emusym.print_cp(cp)
    CP = emusym.add_branch_info(cp)
    print "emulating code path..."
    ct = emusym.emusym_code_path(CP,codetree=True)
    print "rebuilding..."
    ct = deco.rebuild_tree(ct)
    print emusym.P.doprint(ct)
    return ct

def try_solve(cp,regs,force=False):
    cp = emusym.strip_wrong_branches(cp)
    resetArm(func = isFuncStart(cp[0]))
    print cp
    emusym.print_cp(cp)
    emusym_code_path(cp[:-1])
    val = string.join([str(eval(r)) for r in regs], " ")
    #~ print "val=",val
    if ("unk_" not in val) or force or (len(val) > len(regs)*20):
        return [eval(r) for r in regs]


def back_solve_slow(ea, unknowns):
    resetArm()
    
    if type(unknowns) == list:
        regs = unknowns
    else:
        regs = [unknowns]

    cp = [ea]

    for i in range(200):
        sol = try_solve(cp,regs)
        if sol: return sol
        try:
            cp = go_back(cp)
        except IndexError:
            print "Giving up (no more code refs to current location)."
            return [eval(r) for r in regs]

    print "Giving up (too many iterations)"
    return try_solve(cp,regs) or []

def func_call_addr(ea):
    mne = GetMnem(ea)
    f = None
    if mne == "BX":
        f = subaddr_bx(ea)
    elif mne in ["BL", "B"]:
        f = subaddr_bl(ea)
    elif mne in ["MOV", "LDR", "MVN"]:
        f = subaddr_mov(ea)
    return f

def func_call_name(ea):
    f = func_call_addr(ea)
    if f: return GetFunctionName(f)

# find args of the function call made at "ea", assuming the function has "numargs" arguments
# returns: a string in a C-like pseudocode (with some notations inspired from python and octave)
def find_func_call(ea, numargs):
    allregs = ["ARM.R0", "ARM.R1", "ARM.R2", "ARM.R3"] + [ "MEM(ARM.SP+%d)"%k for k in range(0,13,4)]
    regs = back_solve(ea, allregs[:numargs])
    #~ Regs = [STR(r, pointsto=True) for r in regs]
    P = DecoPrinter()
    Regs = [P.doprint(r) for r in regs]
    #~ pprintpprint(ARM.MEMDIC)
    return func_call_addr(ea), func_call_name(ea), "(" + string.join(Regs, ", ") + ")", Regs


# Traces all the calls to a function
# returns: a dictionary [addr] => "malloc(0x1234)"
# also writes a wiki table in "table.txt"
# 
# possible_names: name of the function, or a list of possible names, e.g. ["TH_malloc", "AJ_malloc"]
# numargs: how many arguments you think the function has
# append: optional, append to the wiki table
def trace_calls_to(possible_names, numargs, append=False):
    if type(possible_names) != list:
        possible_names = [possible_names]
    tracedfunc = find_func(possible_names)
    if not tracedfunc:
        raise Exception, "function not found:" + str(possible_names)

    calls = {}
    for ref in list(CodeRefsTo(tracedfunc, 1)):
        #~ print "%x: called from %s" % (ref, GetFuncOffset(ref))
        f = func_call_addr(ref)
        if f:
            try:
                calls[ref] = find_func_call(ref, numargs)
            except:
                print "whoops..."
                pass
            #~ print calls[ref]

    tab = open("table.txt", ("a" if append else "w"))
    tabh = open("table.htm", ("a" if append else "w"))
    
    tab.write("Tracing function %s at 0x%X:\n" % (GetFunctionName(tracedfunc), tracedfunc))
    tabh.write("<p><b>Tracing function %s at 0x%X:</p></b>\n" % (GetFunctionName(tracedfunc), tracedfunc))
    
    tab.write("""{| border="1"
! scope="col"|Function call line
! scope="col"|Called from: func <addr>
""")

    tabh.write("<table border=1><th>Function call line</th><th>Called from: func &lt;addr&gt;</th>\n")

    for addr,call in sorted(calls.iteritems(), key=lambda x: str(x[1]).lower()):
        call = "%s%s" % call[1:3]
        calledfrom = "%s <0x%X>" % (GetFunctionName(addr), addr)
        tab.write("""|-\n|%s\n|%s\n""" % (call, calledfrom))
        calledfrom = "%s &lt;0x%X&gt;" % (GetFunctionName(addr), addr)
        tabh.write("""<tr><td>%s</td><td>%s</td></tr>\n""" % (call, calledfrom))
    
    tab.write("|}\n")
    tabh.write("</table>\n")

    tab.close()
    tabh.close()

    return calls

#~ ea = ScreenEA()
#~ print find_func_call(ea,4)
#~ print find_func_call(ea,4)


def subaddr_bl(a):
    v = GetOperandValue(a,0)
    return v

def subaddr_bx(a):
    """
    Get the address of the subroutine called from line A, with an instruction like this:
    BX blahblah
    
    It uses bkt.back_solve() to guess the value of ''blahblah''.
    
    !!! This function resets the ARM emulator !!!
    """
    v = GetOperandValue(a,0)
    t = GetOpType(a,0)
    if t == o_reg:
        if v < 13:
            R = "ARM.R%d" % v
            sub = None
            try: 
                sub = back_solve(a, R)[0]
                return int(sub & 0xFFFFFFFF)
            except:
                #~ print sub
                raise
        elif v==14:
            return
    print "Unhandled:" + GetDisasm(a)




def subaddr_mov(ea):
    """
    Get the address of the subroutine called from line A, with an instruction like this:
    MOV PC, blahblah
    LDR PC, blahblah
    MVN PC, blahblah

    It uses bkt.back_solve() to guess the value of ''blahblah''.

    !!! This function resets the ARM emulator !!!
    """
    mne = GetMnem(ea)
    #~ print mne
    if mne in ["MOV", "LDR", "MVN"]:
        if GetOpnd(ea,0) in ["R15","PC"]:
            resetArm()
            b,post = TranslateOperand(ea, 1)
            #~ print b
            if mne == "MVN": b = "-(%s)-1" % b
            try: return int(eval(b))
            except:
                sub = None
                try: 
                    sub = back_solve(ea, b)[0]
                    return int(sub & 0xFFFFFFFF)
                except:
                    print sub
                    raise
            pass
