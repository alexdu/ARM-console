# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# Module guessfunc: try to guess where are the functions inside the firmware

from profilestats import profile
from scripts import *

def tryAddrList(d,A):
    A = list(set(A))
    progress("Guessing functions from %d candidate addresses..." % len(A))
    for i,a in enumerate(A):
        if a not in d.FUNCS:
            progress(float(i) / len(A))
            print
            show_disasm(d,a,a+12)
            tryMakeSub(d,a)

def analyze_push(d):
    select_dump(d)
    progress("Analyzing PUSH instructions...")
    A = []
    for a in range(d.minaddr, d.maxaddr, 4):
        if a in d.STRMASK: continue
        progress(float(a - d.minaddr) / (d.maxaddr - d.minaddr))
        if maybePushFuncStart(a):
            for xa in range(a, a - 3*4, -4):
                if not maybeFuncStart(xa-4):
                    break
                if d.REF2AS[xa]: # somebody calls this maybe
                    break
            A.append(xa)
    return A

def analyze_bl(d):
    select_dump(d)
    progress("Analyzing BL calls...")
    A = []
    for a in range(d.minaddr, d.maxaddr, 4):
        if a in d.STRMASK: continue
        progress(float(a - d.minaddr) / (d.maxaddr - d.minaddr))
        try: ins = d.DISASM.get(a,"").split("\t")[2]
        except: continue
        if idapy.IsBL(a):
            if GetMnef(a) not in ["BL", "BLNE", "BLEQ"]:
                continue
            sub = bkt.subaddr_bl(a)
            #~ print >> emusym.log, sub
            if sub in idapy.instructions_allowed_for_func_start:
                if sub not in d.STRMASK:
                    A.append(sub)
                #~ assert (a,sub) in d.REFLIST
    return A

def analyze_bx(d):
    select_dump(d)
    progress("Analyzing BX calls...")
    A = []
    for a in range(d.minaddr, d.maxaddr, 4):
        if a in d.STRMASK: continue
        progress(float(a - d.minaddr) / (d.maxaddr - d.minaddr))
        try: ins = d.DISASM.get(a,"").split("\t")[2]
        except: continue
        if ins.startswith("bx"):
            assert GetMnem(a) == "BX"
            print hex(a),GetDisasm(a)
            try: sub = bkt.subaddr_bx(a)
            except: sub = None
            if sub: 
                A.append(sub)
                if (a,sub) not in d.REFLIST:
                    d.AddRef(a, sub)
    return A

def analyze_b(d):
    select_dump(d)
    for a in range(d.minaddr, d.maxaddr, 4):
        if GetMnem(a) == "B":
            print hex(a),GetDisasm(a)

def analyze_names(d):
    select_dump(d)
    progress("Analyzing loaded names...")
    A = []
    for i,n in enumerate(d.N2A.keys()):
        progress(float(i) / len(d.N2A))
        a = d.N2A[n]
        if not GuessString(d, a):
            A.append(a)
    return A

#~ def init_funcs(d):
    #~ for a in range(598452, 598492, 20):
        #~ sub = d.ROM[a+4]
        #~ print sub
        #~ tryMakeSub(d,sub)
        
def getAddrList(d):
    select_dump(d)
    A = []
    A += analyze_push(d)
    A += analyze_names(d)
    #~ A += analyze_bx(d)
    A += analyze_bl(d)
    A = list(set(A))
    print "total candidates:", len(A)
    A = [a for a in A if a not in d.FUNCS]
    print "new candidates:", len(A)
    return A

def run(d):
    A = getAddrList(d)
    tryAddrList(d,A)
