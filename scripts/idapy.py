# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# IDAPython compatibility layer (incomplete, but useful for running 
# existing scripts with minimal modification)

from __future__ import division
import string,re
import disasm
import cache

# push and others allowed before it
# repr(list(set([GetMnef(a) for a in d.FUNCS]))), then manual cleanup
instructions_allowed_for_func_start = ['CMN', 'ORRS', 'SUB', 'STMIB', 'LDMIB', 'EOR', 'TST', 'MOVS', 'CMP', 'ASR', 'ASRS', 'LSL', 'BIC', 'LDM', 'LDR', 'LSR', 'PUSH', 'ANDS', 'STMIA', 'LDRSH', 'SUBS', 'STM', 'MRS', 'LDRB', 'ADD', 'STR', 'LDRH', 'MVN', 'AND', 'RSBS', 'ORR', 'MOV', 'RSB', 'STRB']

def GetFirstWord(s):
    """
    >>> GetFirstWord("abc def")
    'abc'
    """
    s = re.match("([a-zA-Z]*)", s).groups()[0]
    return s


_d = None
def select_dump(dump):
    global _d
    _d = dump

def GetDisasmQ(ea):
    """faster GetDisasm"""
    try: return string.join(_d.DISASM.get(ea).split("\t")[2:], "   ")
    except: return "undefined?"

def GetDisasm(ea):
    """
    >>> print GetDisasm(0xff000000) #doctest: +NORMALIZE_WHITESPACE
    mov   r1, #0    ; 0x0
    >>> print GetDisasm(0xff000004) #doctest: +NORMALIZE_WHITESPACE
    ldr   r2, [pc, #1]   ; 0xff00000d 
    """
    l = _d.DISASM.get(ea)
    l = disasm.friendly_disasm(_d,l).split("\t")
    #~ for i in range(min(4,len(l))):
        #~ l[i] = l[i].upper()
    return string.join(l[2:], "   ")

def GetMnef(ea):
    """
    >>> GetMnef(0xff000000)
    'MOV'
    """
    l = _d.DISASM.get(ea,"").upper()
    items = l.split("\t")
    if len(items) > 2:
        mnef = items[2]
        return mnef

_rmnem = re.compile("(ABS|ACS|ADC|ADD|ADF|ADRL|ADR|ALIGN|AND|ASL|ASN|ASR|ATN|BIC|BKPT|BLX|BLEQ|BLE|BLT|BLS|BL|BX|B|CDP|CLZ|CMF|CMN|CMP|CNF|COS|DVF|EOR|EXP|FABS|FADD|FCMP|FCPY|FCVTDS|FCVTSD|FDIV|FDV|FIX|FLD|FLT|FMAC|FMDHR|FMDLR|FML|FMRDH|FMRDL|FMRS|FMRX|FMSC|FMSR|FMSTAT|FMUL|FMXR|FNEG|FNMAC|FNMSC|FNMUL|FRD|FSITO|FSQRT|FST|FSUB|FTOSI|FTOUI|FUITO|LDC|LDF|LDM|LDR|LFM|LGN|LOG|LSL|LSR|MCRR|MCR|MLA|MNF|MOV|MRC|MRRC|MRS|MSR|MUF|MUL|MVF|MVN|NEG|NOP|NRM|OPT|ORR|PLD|POL|POP|POW|PUSH|QADD|QDADD|QDSUB|QSUB|RDF|RFC|RFS|RMF|RND|ROR|RPW|RRX|RSB|RSC|RSF|SBC|SFM|SIN|SMLAL|SMLAW|SMLA|SMULL|SMULW|SMUL|SQT|STC|STF|STM|STR|SUB|SUF|SWI|SWP|TAN|TEQ|TST|UMLAL|UMULL|URD|WFC|WFS)")
def GetMnem_w(ea):
    """
    >>> GetMnem(0xff000000)
    'MOV'
    """
    l = _d.DISASM.get(ea,"").upper()
    items = l.split("\t")
    if len(items) > 2:
        mnef = items[2]
        try: 
            mne = re.match(_rmnem,mnef).groups()[0]
            #~ print mne
            if mne in ["BLE", "BLT", "BLS"]: return "B"
            if mne in ["BLEQ"]: return "BL"
            return mne
        except AttributeError: return

# faster than GetMnem
def IsBL(ea):
    l = _d.DISASM.get(ea,"").upper()
    items = l.split("\t")
    if len(items) > 2:
        mnef = items[2]
        if mnef.startswith("BL"):
            if mnef in ["BLE", "BLT", "BLS"]: return 0
            if mnef.startswith("BLX"): return 0
            return 1
    return 0

def GetMnem(ea):
    return GetMnem_w(ea)
    return cache.access((_d,ea), lambda x: GetMnem_w(ea))

def _regnames(s):
    return s.replace("R15","PC").replace("R14","LR").replace("R13","SP")

def GetOpnd(ea,i):
    """
    >>> GetOpnd(0xff000000,0)
    'R1'
    >>> GetOpnd(0xff000000,1)
    '#0'
    >>> GetOpnd(0xff000004,1)
    '[PC,#1]'
    """
    l = _d.DISASM.get(ea,"").upper()
    items = l.split("\t")
    if len(items) > 3:
        args = _regnames(items[3].replace(" ",""))
        args = re.sub(",([ALR][SO][LR])", "`\\1", args) # trick to stick LSL to previous operand
        arglist = re.findall(r"(\([^\(\)]+\)|\[[^\[\]]+\]|\{[^\{\}]+\}|[^,]+)", args)
        try: return arglist[i].replace("`",",")
        except: return ""

def GetOpnds(ea):
    """
    >>> GetOpnds(0xff000000)
    'R1, #0'
    >>> GetOpnds(0xff000004)
    'R2, [PC, #1]'
    """
    l = _d.DISASM.get(ea,"").upper()
    items = l.split("\t")
    if len(items) > 3:
        args = _regnames(items[3])
        return args

def GetOpType(ea,i):
    """
    >>> GetOpType(0xff000000,0)
    1
    >>> GetOpType(0xff000000,1)
    5
    >>> GetOpType(0xff000004,1)
    3
    """
    opnd = GetOpnd(ea,i)
    if opnd.startswith("#"):
        return 5
    try: 
        v = int(opnd,16)
        return 5
    except: pass
    if opnd.startswith("["):
        return 3
    if re.match(".*,[ALR][SO][LR]", opnd): # LSL & friends
        return 8
    if re.match('[A-Z]',opnd):
        return 1
    return 0

def GetOperandValue(ea,i):
    """
    >>> GetOperandValue(0xff000000,0)
    1
    >>> GetOperandValue(0xff000000,1)
    0
    >>> GetOperandValue(0xff000004,1)
    15
    """
    opnd = GetOpnd(ea,i)
    if opnd.startswith("#"):
        return int(opnd[1:])
    try: return int(opnd,16)
    except: pass
    if opnd.startswith("R"):
        return int(opnd[1:].split(",")[0])
    if opnd == "PC":
        return 15
    if opnd == "LR":
        return 14
    if opnd == "SP":
        return 13
    if opnd.startswith("[R"):
        return int(opnd[2:].replace("]",",]").split(",")[0])
    if opnd.startswith("[PC"):
        return 15
    if opnd.startswith("["):
        return -1

    return -1
    
def GetString(ea,blah=0,blahh=0):
    return disasm.GuessString(_d,ea)

def FuncItems(ea):
    """
    >>> FuncItems(0xff000004)
    [4278190080L, 4278190084L, 4278190088L, 4278190092L]
    """
    f = disasm.which_func(_d,ea)
    end = _d.FUNCS[f]
    return range(f,end,4)

def OpSeg(*args):
    pass

def SegStart(ea):
    """
    >>> SegStart(0xff000004)
    4278190080L
    """
    return _d.minaddr
    
def SegEnd(ea):
    """
    >>> SegEnd(0xff000004)
    4278190096L
    """
    return _d.maxaddr

def GetFunctionName(ea):
    """
    >>> GetFunctionName(0xff000004)
    'main_prog'
    """
    try: ea = int(ea)
    except: return
    
    f = disasm.which_func(_d,ea)
    if f: return disasm.funcname(_d,f)
    return disasm.funcname(_d,ea)

def GetName(ea):
    """
    >>> GetName(0xff000000)
    'main_prog'
    """
    return _d.A2N.get(ea)

def GetFuncOffset(ea):
    """
    >>> GetFuncOffset(0xff000000)
    'main_prog'
    >>> GetFuncOffset(0xff000004)
    'main_prog+4'
    >>> GetFuncOffset(0xff000040)
    'ROMBASE+0x40'
    """
    ans = disasm.funcoff(_d,ea)
    if ans.endswith("+0"):
        return ans[:-2]
    return ans

def Byte(ea):
    return disasm.BYTE(_d,ea)

def Uint32(ea):
    return disasm.UINT32(_d,ea)
    
def getRegs03(op):
    """
    >>> getRegs03("R1, R2 and maybe R5")
    [1, 2]
    """
    R = []
    regs = re.split("(R[0-3])[^0-9]", str(op) + " ")
    for r in regs:
        if len(r) == 2 and r[0] == "R":
            R.append(int(r[1]))
    return R

def getRegsS(op):
    """
    >>> getRegsS("R1, R2 and maybe R5")
    ['R1', 'R2', 'R5']
    """
    R = []
    regs = re.split("(R[0-9]+)[^0-9]", str(op) + " ")
    for r in regs:
        if len(r) in [2,3] and r[0] == "R":
            R.append(r)
    return R

_rmode = re.compile("(IA|IB|DA|DB|FD|FA|ED|EA)")
_rcond = re.compile("(AL|NV|EQ|NE|VS|VC|MI|PL|CS|CC|HI|LS|GE|LT|GT|LE)")

def GetModeSuffix(ea):
    mne = GetMnem(ea)
    mnef = GetMnef(ea)
    if mnef is None or mne is None: return
    if mnef.startswith(mne):
        s = re.search(_rmode, mnef[len(mne):])
        if s:
            return s.groups()[0]
    else:
        raise "asm string does not start with mnemonics... wtf?!"

def GetCondSuffix(ea):
    mne = GetMnem(ea)
    mnef = GetMnef(ea)
    if mnef is None or mne is None: return
    if mnef.startswith(mne):
        s = re.search(_rcond, mnef[len(mne):])
        if s:
            return s.groups()[0]
    else:
        raise "asm string does not start with mnemonics... wtf?!"

# strip mode and cond
def GetExtraSuffixes(ea):
    asm = GetMnef(ea)
    mne = GetMnem(ea)
    if asm is None or mne is None: return
    if asm.startswith(mne):
        s = re.sub(_rmode, "", asm[len(mne):])
        s = re.sub(_rcond, "", s)
        return s
    else:
        raise "asm string does not start with mnemonics... wtf?!"

def GetFlagSuffix(ea):
    asm = GetMnef(ea)
    mne = GetMnem(ea)
    if asm is None or mne is None: return
    if asm.startswith(mne):
        s = re.sub(_rmode, "", asm[len(mne):])
        s = re.sub(_rcond, "", s)
        if s:
            return "S" if "S" in s else ""
    else:
        raise "asm string does not start with mnemonics... wtf?!"

def GetByteSuffix(ea):
    asm = GetMnef(ea)
    mne = GetMnem(ea)
    if asm is None or mne is None: return
    if asm.startswith(mne):
        s = re.sub(_rmode, "", asm[len(mne):])
        s = re.sub(_rcond, "", s)
        if s:
            return "B" if "B" in s else ""
    else:
        raise "asm string does not start with mnemonics... wtf?!"

def GetHalfwordSuffix(ea):
    asm = GetMnef(ea)
    mne = GetMnem(ea)
    if asm is None or mne is None: return
    if asm.startswith(mne):
        s = re.sub(_rmode, "", asm[len(mne):])
        s = re.sub(_rcond, "", s)
        if s:
            return "H" if "H" in s else ""
    else:
        raise "asm string does not start with mnemonics... wtf?!"

CondSuffixes = ["NE", "EQ", "AL", "NV", "VS", "VC", "MI", "PL", "CS", "CC", "HI", "LS", "GE", "LT", "GT", "LE"]

def ChangesFlags(ea):
    """
    >>> ChangesFlags(0xff000000)
    False
    """
    if GetMnem(ea) in ["CMP", "CMN", "TEQ", "TST"] or GetFlagSuffix(ea):
        return True
    if GetMnem(ea) == "MSR":
        print "unhandled: MSR (don't know if it changes flags or not)"
    return False

def ChangesPC(ea):
    """
    >>> ChangesPC(0xff000000)
    False
    """
    m = GetMnem(ea)
    if m in ["B", "BX"]:
        return True
    if m in ["ADD", "SUB", "MUL", "LDR", "MOV", "MVN"] and GetOpnd(ea,0) == "PC":
        return True
    if m in ["POP"] and "PC" in GetOpnd(ea,0):
        return True
    if m in ["LDM"] and "PC" in GetOpnd(ea,1):
        return True
    return False
def ReadRegs(ea):
    m = GetMnem(ea)
    if m in ["B", "BL", "BLX", "BX"]:
        return getRegsS(GetOpnd(ea,0))
    if m in ["ADD", "SUB", "RSB", "MUL", "AND", "ORR", "EOR", "BIC", "LSL", "LSR", "ASL", "ASR"]:
        return getRegsS(GetOpnd(ea,1)) + getRegsS(GetOpnd(ea,2))
    if m in ["CMP", "CMN", "TST", "TEQ"]:
        return getRegsS(GetOpnd(ea,0)) + getRegsS(GetOpnd(ea,1))
    return []

def WrittenRegs(ea):
    mne = GetMnem(ea)
    if mne in ["MOV", "LDR", "MRS", "MSR", "MVN", "ADD", "SUB", "RSB", "MUL", "AND", "ORR", "EOR", "BIC", "LSL", "LSR", "ASL", "ASR"]:
        return getRegsS(GetOpnd(ea,0))
    if mne == "LDM":
        return getRegsS(GetOpnd(ea,1))
    return []

def ChangesLR(ea):
    """
    >>> ChangesPC(0xff000000)
    False
    """
    if GetMnem(ea) in ["ADD", "SUB", "MUL", "LDR", "MOV", "MVN"] and GetOpnd(ea,0) == "LR":
        return True
    if GetMnem(ea) in ["POP"] and "LR" in GetOpnd(ea,0):
        return True
    if GetMnem(ea) in ["LDM"] and "LR" in GetOpnd(ea,1):
        return True
    return False

def OppositeSuffix(s):
    """
    >>> OppositeSuffix("EQ")
    'NE'
    >>> OppositeSuffix("pl")
    'MI'
    """
    try:
        i = CondSuffixes.index(str(s).strip().upper())
        return str(CondSuffixes[(i//2*2) + (1-(i%2))])
    except:
        return ""


o_void  =      0  # No Operand               
o_reg  =       1  # General Register (al,ax,es,ds...)    reg
o_mem  =       2  # Direct Memory Reference  (DATA)      addr
o_phrase  =    3  # Memory Ref [Base Reg + Index Reg]    phrase
o_displ  =     4  # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
o_imm  =       5  # Immediate Value                      value
o_far  =       6  # Immediate Far Address  (CODE)        addr
o_near  =      7  # Immediate Near Address (CODE)        addr
o_regshift =   8  # R1,LSL#5 or similar


# http://wiki.python.org/moin/BitManipulation

# testBit() returns a nonzero result, 2**offset, if the bit at 'offset' is one.

def testBit(int_type, offset):
    mask = 1 << offset
    return(int_type & mask)

# setBit() returns an integer with the bit at 'offset' set to 1.

def setBit(int_type, offset):
    mask = 1 << offset
    return(int_type | mask)

# clearBit() returns an integer with the bit at 'offset' cleared.

def clearBit(int_type, offset):
    mask = ~(1 << offset)
    return(int_type & mask)

# toggleBit() returns an integer with the bit at 'offset' inverted, 0 -> 1 and 1 -> 0.

def toggleBit(int_type, offset):
    mask = 1 << offset
    return(int_type ^ mask)

def setBit01(old, offset, value):
    if value: setBit(old, offset)
    else: clearBit(old, offset)


def hex(x):
    if x >= 0:
        return "%X" % x
    else:
        return "%X" % (0x100000000+x)

def isFuncStart(ea):
    """
    >>> isFuncStart(0xff000000)
    True
    >>> isFuncStart(0xff000004)
    False
    """
    return ea in _d.FUNCS

def maybePushFuncStart(ea):
    #~ if GetMnem(ea) == "PUSH":
    if GetMnef(ea) == "PUSH":
        #~ print GetOpnd(ea,0)
        if "LR" in GetOpnd(ea,0):
            return True
    return False

def maybeFuncStart(ea):
    #~ if GetCondSuffix(ea): return False
    for i in range(3):
        if maybePushFuncStart(ea + i*4): return True
        if GetMnef(ea + i*4) not in instructions_allowed_for_func_start: return False
        if ChangesPC(ea + i*4): return False
    return False

def filter_non_printable(str):
    f = ''.join([c for c in str if ord(c) <= ord('z')])
    return f

   
def CodeRefsTo(ea,ghost=0):
    CR = []
    mne = GetMnem(ea-4)
    if mne and not callsAbortFunc(ea-4) and (ea-4) not in _d.STRMASK:
        if (not ChangesPC(ea-4)) or (ChangesLR(ea-8)):
            CR.append(ea-4)
        else: # changes PC and it's not a call; if it's a conditional jump, skip it
            if GetCondSuffix(ea-4):
                CR.append(ea-4)      # or -8?
    if callsAbortFunc(ea-4) and GetCondSuffix(ea-4):
        c0 = GetCondSuffix(ea-4)
        adr = ea-4
        while GetCondSuffix(adr) == c0: adr -= 4
        CR.append(adr) # skip assert
        
    R = disasm.find_refs(_d, value=ea)
    for a,r in R:
        #~ if isFuncStart(r):
        CR.append(a)
    
    # try to go back through a jump table
    if GetMnem(ea) in ["B", "POP"]:
        while GetMnem(ea) in ["B", "POP"]:
            ea -= 4;
        if ChangesPC(ea):
            CR.append(ea)
    
    return list(set(CR))

def DataRefsTo(ea,ghost=0):
    DR = []
    R = disasm.find_refs(_d, value=ea)
    for a,r in R:
        DR.append(a)

    return list(set(DR))

def _refsFrom(ea):
    if isFuncStart(ea):
        return disasm.find_refs(_d, func=ea)
    
    return [(ea,r) for r in _d.A2REFS[ea]]
    
def CodeRefsFrom(ea,ghost=0):
    DR = []
    R = _refsFrom(ea)
    for a,r in R:
        if isFuncStart(r):
            DR.append(r)
    return DR
def DataRefsFrom(ea,ghost=0):
    DR = []
    R = _refsFrom(ea)
    for a,r in R:
        if not isFuncStart(r):
            DR.append(r)
    return DR


if __name__ == "__main__":
    import doctest
    disasm.prepare_test()
    D = disasm.load_dumps()
    print D
    select_dump(D[0])
    doctest.testmod()
    disasm.end_test()



# find a function addr in the code, starting from a list of possible names
def find_func(possible_names):
    print possible_names
    for ea,name in _d.A2N.iteritems():
        #~ print ea,name
        if name in possible_names:
            print "Function found at %x" % ea
            return ea

    for ea in _d.FUNCS:
        name = GetFunctionName(ea)
        if name in possible_names:
            print "Function found at %x" % ea
            return ea

    for ea in range(_d.minaddr, _d.maxaddr, 4):
        name = GetFunctionName(ea)
        if name in possible_names:
            print "Function found at %x" % ea
            return ea

import emusym
def callsAbortFunc(ea):
    if GetMnem(ea) in ["BL", "BLX"] and emusym.isAbortFunc(GetOperandValue(ea,0)):
        return True
    return False
