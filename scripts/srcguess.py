from scripts import *
from progress import progress
import disasm

def funref(f):
    l = CodeRefsFrom(f)
    l += filter(lambda x: x > 1000, DataRefsFrom(f))
    return list(set(l))

def reflist(funs):
    rl = []
    for f in funs:
        rl += funref(f)
    return list(set(rl))

def refmatch(f,grp):
    rf = funref(f)
    rgrp = cache.access((idapy._d, tuple(grp)), lambda x: reflist(grp))
    tx = [k for k in rf if k in rgrp]
    return float(len(tx)) / len(rgrp)

def numrefs(f):
    return float(len(set(CodeRefsTo(f))))

def score(fs,g1,g2):
    Sa = [refmatch(f, g1) for f in fs]
    Sb = [refmatch(f, g2) for f in fs]
    Sax = [refmatch(f, g1) for f in g1+fs]
    Sbx = [refmatch(f, g2) for f in fs+g2]
    plot(Sax), plot(Sbx)
    print norm(Sa), norm(Sb), norm(Sax), norm(Sbx)
    Sa = Sa / norm(Sa)
    Sb = Sb / norm(Sb)
    S = [sum(Sa[:i]) + sum(Sb[i:]) for i in range(len(fs))]
    return S
    #~ return sum([refmatch(f,g1) / numrefs(f) for f in fs[:i+1]]) + sum([refmatch(f,g2) / numrefs(f) for f in fs[i+1:]])

def findgrp(srcfile):
    funs = []
    matches = []
    d = idapy._d
    for a,s in d.STRINGS.iteritems():
        if srcfile == s:
            matches.append(a)
        components = []
        for C in s.split(" "):
            for c in C.split(":"):
                if c: components.append(c)
        if srcfile in components:
            matches.append(a)
    #~ print matches
    for m in matches:
        for a,r in disasm.find_refs(d, m):
            f = which_func(d, a)
            if f: funs.append(f)
    #~ print funs
    try: 
        return funcs(min(funs), max(funs))
    except:
        print srcfile

def funcs(minaddr,maxaddr):
    d = idapy._d
    fs = sorted(filter(lambda x: x >= minaddr and x <= maxaddr, list(d.FUNCS)))
    return fs


def extrapolate(d):
    idapy.select_dump(d)
    srcfiles = []
    d.SRCFILES = {}
    
    progress("finding source file names...")
    for k,f in enumerate(sorted(d.FUNCS)):
        progress(float(k) / len(d.FUNCS))
        s = sourcefile(d, f, partial=False)
        if s:
            srcfiles.append(s)
    progress("finding source file groups...")
    srcfiles = list(set(srcfiles))
    for k,s in enumerate(srcfiles):
        progress(float(k) / len(srcfiles))
        g = findgrp(s)
        if g is None:
            print "WARNING: source file not found:", s
            continue
        for a in g:
            if a in d.SRCFILES:
                print "ERROR:", d.SRCFILES[a], s
            d.SRCFILES[a] = s
    print "Found source files for %d subs; %d subs reference file name directly" % (len(d.SRCFILES), len(srcfiles))
def sourcefile(dump, addr, partial=False):
    try: return dump.SRCFILES[addr]
    except: pass
    refs = disasm.find_refs(dump, func=addr)
    for a,v in refs:
        s = disasm.GuessString(dump, v)
        if s:
            if s.endswith(".c") or s.endswith(".cfg"):
                return s
            if partial and ".c " in s or ".c:" in s:
                r = re.search(r"([^ ]*\.c):? ", s)
                return r.groups()[0]



