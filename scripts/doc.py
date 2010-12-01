# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# Module doc: generate wiki docs from IPython commands.
#
# irunner was buggy (buffer overflow? memory corruption?)
# => I rewrote it using plain IPython and hooks. Now the script is a big mess, 
# but at least I removed lots of workarounds which were needed with irunner.

from scripts.fileutil import *

import IPython
from pprint import PrettyPrinter
pformat = PrettyPrinter().pformat

_result = None
def intercept(self, *args):
    global _result
    _result = args[0]
    raise IPython.ipapi.TryNext()
    
def init():
    _ip = IPython.ipapi.get()
    _ip.set_hook('result_display', intercept)


def crun(line):
    global _result
    _result = ""
    print "RUN: %s" % line
    _ip = IPython.ipapi.get()
    stdout, stderr = sys.stdout, sys.stderr
    sys.stdout = c1 = cStringIO.StringIO()
    sys.stderr = c2 = cStringIO.StringIO()
    
    try:
        _ip.runlines(line)
    except:
        traceback.print_exc()

    sys.stdout = stdout
    sys.stderr = stderr
    if _result is not None: 
        try: out = str(eval(pformat(_result)))
        except: out = pformat(_result)
    if "\n" in out: out = "\n" + out
    if out.endswith("\n"): out = out[:-1]
    print "OUT[]:", repr(out)
    return (out, c1.getvalue(), c2.getvalue())

def nowiki(s):
    for c in s:
        if c in ["'*#<>[]|&"]:
            return "<nowiki>%s</nowiki>" % s
    return s
def mkcode(s):
    s = s.strip("\n")
    lines = s.split("\n")
    s = ""
    for l in lines:
        s += " %s\n" % nowiki(l)
    return s[:-1]

def pr(f,inp,res,out,err,ind=None):
    global k
    try:
        inp, com = inp.split("#")
    except:
        inp, com = inp, ""
    inp = inp.strip().strip("%")
    com = com.strip().strip("\n")
    if not inp: return
    if com:
        print >> f, " In [%d]: '''%s''' %s # %s" % (k, nowiki(inp), " " * (50-len(inp)), com)
    else:
        print >> f, " In [%d]: '''%s'''" % (k, nowiki(inp))
    
    O = ""
    if out.strip(): O += mkcode(out) + "\n"
    if err.strip(): O += mkcode(err) + "\n"
    if res.strip(): O += mkcode("Out[%d]: %s" % (k, res)) + "\n"
    O = O[:-1]
    print repr(O)
    if ind:
        lines = O.split("\n")
        for i in ind:
            if type(i) == int:
                try: l = lines[i]
                except: continue
                if len(l) > 100:
                    print >> f, l[:100] + " ..."
                else:
                    print >> f, l
            else:
                print >> f, mkcode(i)
    else:
        if O: 
            print >> f, O
    
    f.flush()
    k += 1
def run(fin):
    print fin
    init()
    fout = change_ext(fin, ".wiki")

    f = open(fin, "r")
    out = open(fout, "w")
    global k
    k = 1
    #~ print fin, f
    was_code = False
    for l in f.readlines():
        l = l.strip("\r\n")
        is_code = True
        if l.startswith("#"): continue
        if (len(l) > 4 and l.startswith("    ") and l[4] != " "):
            c = crun(l[4:])
            if was_code: print >> out, " "
            pr(out, l[4:], *c)
        
        elif l.startswith("   ["):
            p = l.index("]")+1
            ind = eval(l[:p])
            c = crun(l[p:])
            if was_code: print >> out, " "
            pr(out, l[p:], c[0], c[1], c[2], ind)

        elif l.startswith("   %") and l[4] != " ": # print input only
            c = crun(l[4:])
            if was_code: print >> out, " "
            pr(out, l[4:], c[0], "", "")

        elif l.startswith("   ~") and l[4] != " ": # print, but do not run
            if was_code: print >> out, " "
            pr(out, l[4:], "", "", "")

        elif l.startswith("   #") and l[4] != " ": # run, but do not print
            c = crun(l[4:])
            is_code = False
        else:
            is_code = False
            print >> out, l
        
        was_code = is_code
    out.close()
