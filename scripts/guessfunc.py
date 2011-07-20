# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# Module guessfunc: try to guess where are the functions inside the firmware

from profilestats import profile
from scripts import *

def analyze_push(d):
    select_dump(d)
    progress("Analyzing PUSH instructions...")
    for a in range(d.minaddr, d.maxaddr, 4):
        progress(float(a - d.minaddr) / (d.maxaddr - d.minaddr))
        if GetMnem(a) == "PUSH":
            print hex(a),GetDisasm(a)
            tryMakeSub(d,a)

def analyze_bl(d):
    select_dump(d)
    progress("Analyzing BL calls...")
    for a in range(d.minaddr, d.maxaddr, 4):
        progress(float(a - d.minaddr) / (d.maxaddr - d.minaddr))
        try: ins = d.DISASM.get(a,"").split("\t")[2]
        except: continue
        if ins.startswith("bl"):
            if GetMnem(a) == "BL":
                #~ print hex(a),GetDisasm(a)
                sub = bkt.subaddr_bl(a)
                if sub: 
                    tryMakeSub(d,sub)
                    assert (a,sub) in d.REFLIST


def analyze_bx(d):
    select_dump(d)
    progress("Analyzing BX calls...")
    for a in range(d.minaddr, d.maxaddr, 4):
        progress(float(a - d.minaddr) / (d.maxaddr - d.minaddr))
        try: ins = d.DISASM.get(a,"").split("\t")[2]
        except: continue
        if ins.startswith("bx"):
            assert GetMnem(a) == "BX"
            print hex(a),GetDisasm(a)
            try: sub = bkt.subaddr_bx(a)
            except: sub = None
            if sub: 
                tryMakeSub(d,sub)
                if (a,sub) not in d.REFLIST:
                    d.AddRef(a, sub)

def analyze_b(d):
    select_dump(d)
    for a in range(d.minaddr, d.maxaddr, 4):
        if GetMnem(a) == "B":
            print hex(a),GetDisasm(a)

def analyze_names(d):
    select_dump(d)
    progress("Analyzing loaded names...")
    for i,n in enumerate(d.N2A.keys()):
        progress(float(i) / len(d.N2A))
        a = d.N2A[n]
        if not GuessString(d, a):
            tryMakeSub(d,a)


#~ def init_funcs(d):
    #~ for a in range(598452, 598492, 20):
        #~ sub = d.ROM[a+4]
        #~ print sub
        #~ tryMakeSub(d,sub)
        
#~ @profile
def run(d):
    select_dump(d)
    analyze_names(d)
    analyze_bx(d)
    analyze_bl(d)
    #~ analyze_b(d)
    analyze_push(d)
