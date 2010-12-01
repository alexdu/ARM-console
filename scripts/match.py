# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# Module match (aka match.py): function/address matching between two camera firmwares

from __future__ import division
import disasm, fileutil, math
from collections import defaultdict
import difflib, sys, os, re, string
from bunch import Bunch
#~ import subprocess, shlex

diff_header = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
          "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html>

<head>
    <meta http-equiv="Content-Type"
          content="text/html; charset=ISO-8859-1" />
    <title></title>
    <style type="text/css">
        table.diff {font-family:Courier; border:medium;}
        .diff_header {background-color:#e0e0e0}
        td.diff_header {text-align:right}
        .diff_next {background-color:#c0c0c0}
        .diff_add {background-color:#aaffaa}
        .diff_chg {background-color:#ffff77}
        .diff_sub {background-color:#ffaaaa}
    </style>
</head>

<body>
"""

diff_footer = """
</body>
</html>
"""

restub = r"\s*NSTUB\s*\((.*),([^\)]*)\)"
redef = r"\s*DEF\s*\((.*),([^\)]*)\)"

def parse_stub(file):
    A2N = {}
    N2A = {}
    f = open(file)
    for l in f.readlines():
        m = re.match(restub, l)
        if m:
            a = m.groups()[0].strip()
            if a == "ROMBASEADDR": continue
            addr = int(a, 16)
            name = m.groups()[1].strip()
            A2N[addr] = name
            N2A[name] = addr
        m = re.match(redef, l)
        if m:
            a = m.groups()[1].strip()
            if a == "ROMBASEADDR": continue
            addr = int(a, 16)
            name = m.groups()[0].strip()
            A2N[addr] = name
            N2A[name] = addr
            
    print "Found %d stubs in %s." % (len(A2N), file)
    return A2N, N2A

def FindBestMatch(dump_and_addr_list, newdump, M, DM):
    confirmed = defaultdict(dict)
    matches = []
    funpairs = []
    for d,a in dump_and_addr_list:
        #~ print "look in ", d.bin, hex(a)
        key = (d,newdump) if d.bin < newdump.bin else (newdump,d)
        pair = (a,None)   if d.bin < newdump.bin else (None,a)
        for a1,a2 in M.get(key,[]):
            if a1==a: 
                matches.append(a2)
                score = Score(key,(a1,a2))
                funpairs.append((d,newdump,a1,a2,score))
                confirmed[a2][d] = confirmed[a2].get(d,0) + score
                #~ print d.bin, a1
            if a2==a: 
                matches.append(a1)
                score = Score(key,(a1,a2))
                funpairs.append((d,newdump,a2,a1,score))
                confirmed[a1][d] = confirmed[a1].get(d,0) + score
                #~ print d.bin,a2
        for a1,a2 in DM.get(key,{}).keys():
            if a1==a: 
                matches.append(a2)
                score = Score_refmatch(key, (a1,a2), DM[key][a1,a2], False)
                funpairs.append((d,newdump,a1,a2,score))
                confirmed[a2][d] = confirmed[a2].get(d,0) + score
                #~ print d.bin,a1
            if a2==a: 
                matches.append(a1)
                score = Score_refmatch(key, (a1,a2), DM[key][a1,a2], False)
                funpairs.append((d,newdump,a2,a1,score))
                confirmed[a1][d] = confirmed[a1].get(d,0) + score
                #~ print d.bin,a2
    
    #~ for a,ds in confirmed.iteritems():
        #~ print hex(a), len(ds)
    if len(confirmed) == 1:
        val = confirmed.keys()[0]
        scores = confirmed[val].values()
        if len(scores)==1:
            return val, combined_score(scores), "might be good (dumps=%d, score=%.2g)" % (len(scores), combined_score(scores)), list(set(funpairs))
        else:
            return val, combined_score(scores), "OK (dumps=%d, score=%.2g)" % (len(scores), combined_score(scores)), list(set(funpairs))
    elif len(confirmed) == 0:
        return 0, 0, "no match", []
        
    else:
        msg = "Ambiguous match. Found matches: "
        vals = sorted(confirmed.keys(), key=lambda val: -combined_score(confirmed[val].values()))
        #~ print vals
        S = []
        for val in vals:
            scores = confirmed[val].values()
            msg += "%x/%.2g, " % (val, combined_score(scores))
            S.append(combined_score(scores))
        msg = msg[:-2]
        if S[0] > S[1]*5: # clearly better
            msg = msg.replace("Ambiguous match", "Good")
        return vals[0], combined_score(confirmed[vals[0]].values()), msg, list(set(funpairs))

def find_dump(bin, D):
    for d in D:
        if d.bin == bin:
            return d

# this does ugly tricks to place new dump always on the right side
def MakeStubs(newdump, D, M=None, DM=None, SRC=None, mlpath="."):
    print type(DM)
    bins = [d.bin for d in D]
    F = lambda f: f.endswith(".S")
    stubs = fileutil.matchInputFilesToBins(bins, filter(F, os.listdir(mlpath)))
    
    S = defaultdict(Bunch)
    names = []
    for bin, stub in stubs.iteritems():
        print "%30s  <=====>  %s" % (bin, stub)
        S[bin].A2N, S[bin].N2A = parse_stub(os.path.join(mlpath, stub))
        for n in S[bin].N2A:
            names.append(n)
    names = list(set(names))
    #~ print names, len(names)

    dif = open("MakeSubs-diff.htm","w")
    print >> dif, diff_header
    for n in sorted(names):
        da = []
        for b,s in stubs.iteritems():
            if n in S[b].N2A:
                da.append((find_dump(b,D), S[b].N2A[n]))
        m,s,c,fp = FindBestMatch(da, newdump, M, DM)
        print "NSTUB(%10s, %s)%s // %s" % ("0x%X"%m,n," " * (30-len(n)),c)
        for do,dn,fo,fn,score in fp:
            sources = SRC[do,dn][fo,fn] if (do,dn) in SRC else [((b,a),s) for (a,b),s in SRC[dn,do][fn,fo]]
            print >> dif, diff_side((do,dn),(fo,fn),score,sources), "<hr>"
            
    print >> dif, diff_footer
    dif.close()

def create_codesig(dump, start, end):
    """ code signature from instruction mnemonics (including flags)
    >>> d = load_dumps()["test-0xff000000.bin"]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> create_codesig(d,0xff000000,0xff00000f)
    'mov ldr mov add '
    """
    MNEF = dump.MNEF
    sig = ""
    for ea in range(start, end, 4):
        if ea in MNEF:
            sig += MNEF[ea].replace(" ","_") + " "
        else:
            sig += "X "
    return sig

def create_codesigs(dump):
    """ Create code signatures for all functions listed in the "func" field
    Returns addr => sig and sig => list of addresses
    
    >>> d = load_dumps()["test-0xff000000.bin"]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> create_codesigs(d)
    Creating codesigs for test-0xff000000.bin...
    ({4278190080L: 'mov ldr mov add '}, {'mov ldr mov add ': [4278190080L]})
    """
    print "Creating codesigs for %s..." % dump.bin
    addr2sigs = {}
    sigs2addr = {}
    for a,end in dump.FUNCS.iteritems():
        sig = create_codesig(dump, a, end)
        addr2sigs[a] = sig
        if sig in sigs2addr: sigs2addr[sig].append(a)
        else: sigs2addr[sig] = [a] 
    return addr2sigs, sigs2addr



def funcpair(dumpair,addrpair):
    d1,d2 = dumpair
    a1,a2 = addrpair
    return "%60s <-------> %s" % (("0x%x:"%a1) + disasm.funcname(d1,a1), ("0x%x:"%a2) + disasm.funcname(d2,a2))

def funcpair_score(dumpair,addrpair):
    d1,d2 = dumpair
    a1,a2 = addrpair
    score = data_match_funcpair(dumpair,addrpair,log=False)[0]
    return "%60s <--[%s]--> %s" % (("0x%x:"%a1) + disasm.funcname(d1,a1), '{0:^+6.2g}'.format(score), ("0x%x:"%a2) + disasm.funcname(d2,a2))

def Score(dumpair, addrpair):
    score = data_match_funcpair(dumpair, addrpair,log=False)[0]
    return score

def combined_score(srcscores):
    return sum(srcscores)/len(srcscores) * math.sqrt(len(srcscores)-0.95)
    
def Score_refmatch(dumpair, addrpair, srcscores, log=True):
    if type(log) == file:
        matchlog = log
    else:
        matchlog = sys.stdout
    verbose = bool(log)

    d1,d2 = dumpair
    a1,a2 = addrpair

    ref1 = len(d1.REF2AS[a1]) # how many times it was referenced
    ref2 = len(d2.REF2AS[a2])
    refm = (ref1 + ref2) / 2
    reftomismatch = abs(ref1 - ref2) / refm if refm else 0
    if verbose: print >> matchlog, "refto mismatch: %.2g (%.2g vs %d)" % (reftomismatch, ref1, ref2)
    srcscore = combined_score(srcscores)
    if verbose: print >> matchlog, "srcscore: %.2g %s" % (srcscore, srcscores)
    score = srcscore - reftomismatch
    return score

# match data refs between two functions
def data_match_funcpair(dumpair, addrpair, log=True):
    if type(log) == file:
        matchlog = log
    else:
        matchlog = sys.stdout
    verbose = bool(log)

    d1,d2 = dumpair
    a1,a2 = addrpair
    e1 = d1.FUNCS[a1]
    e2 = d2.FUNCS[a2]
    #~ print e1-a1, e2-a2
    #~ print d1.addr2sigs[a1]
    #~ print d2.addr2sigs[a2]

    ref1 = len(d1.REF2AS[a1]) # how many times it was referenced
    ref2 = len(d2.REF2AS[a2])
    refm = (ref1 + ref2) / 2.0
    reftomismatch = abs(ref1 - ref2) / refm if refm else 0
    if verbose: print >> matchlog, "refto mismatch: %.2g (%.2g vs %d)" % (reftomismatch, ref1, ref2)
    ref1 = len(disasm.find_refs(d1, func=a1))
    ref2 = len(disasm.find_refs(d2, func=a2))
    refm = (ref1 + ref2) / 2.0
    reffrommismatch = abs(ref1 - ref2) / refm if refm else 0
    if verbose: print >> matchlog, "reffrom mismatch: %.2g (%.2g vs %d)" % (reffrommismatch, ref1, ref2)
    

    assert e1-a1 == e2-a2
    
    smallmatch_ok = 0
    smallmatch_total = 0
    smallmatch = 0

    bigmatch_ok = 0
    bigmatch_total = 0
    bigmatch = 0

    datamatches = []

    stringmatch_ok = 0
    stringmatch_total = 0
    stringmatch = 0
    if verbose: print >> matchlog, funcpair((d1,d2),(a1,a2))
    
    # refs from this function, matched line-by-line
    refpairs = []
    for off in range(0, e1-a1, 4):
        for i in range(2): # max 2 refs at a single address; first is raw value, second is pointer
            try:
                c1,c2 = None,None
                c1 = d1.A2REFS[a1+off][i]
                c2 = d2.A2REFS[a2+off][i]
                refpairs.append((c1,c2))
            except: 
                pass

    # if there is a single ref (call) to this function, consider it also
    # (i.e. the function which calls this should also match)
    c1 = d1.REF2AS[a1]
    c2 = d2.REF2AS[a2]
    if len(c1)==1 and len(c2)==1:
        c1,c2 = disasm.which_func(d1,c1[0]), disasm.which_func(d2,c2[0])
        refpairs.append((c1, c2))
        if verbose:
            print >> matchlog, "unique ref: %s called from %s <---> %s called from %s" \
                                                         % (disasm.guess_data(d1,a1),
                                                            disasm.guess_data(d1,c1),
                                                            disasm.guess_data(d2,a2),
                                                            disasm.guess_data(d2,c2))

    for c1,c2 in refpairs:
        if c1 is not None or c2 is not None:
                
            #~ if verbose: print >> matchlog, "%f:%s --- %f:%s" % (a1+off,c1,a2+off,c2)
            
            if c1 < 0x1000 and c2 < 0x1000:
                smallmatch_total += 1
                if c1 == c2: smallmatch_ok += 1
            else:
                s1 = disasm.GuessString(d1, c1)
                s2 = disasm.GuessString(d2, c2)

                if s1 or s2:
                    stringmatch_total += 1
                    ds = 0
                    if s1 is None or s2 is None:
                        ds = -1 # penalty if one has string and other doesn't
                    else:
                        ratio = difflib.SequenceMatcher(None, s1, s2).ratio()
                        if ratio > 0.7: ds = ratio
                        if len(s1) <= 5: ds /= 2       # penalty for small strings
                    stringmatch_ok += ds
                    if verbose:
                        print >> matchlog, "string pair [match=%.2g]: %s <---> %s" % (ds, repr(s1), repr(s2))
                else:
                    bigmatch_total += 1
                    if c1==c2:
                        bigmatch_ok += 1
                    elif c1 is not None and c2 is not None:
                        cm = ((c1+c2)/2)
                        if abs(c1 - c2) / cm < 1: 
                            bigmatch_ok += 0.5 # same order of magnitude
                            datamatches.append((c1,c2))

    if smallmatch_total:
        smallmatch = smallmatch_ok / smallmatch_total
        if verbose: print >> matchlog, "small numbers match: %.2g (%d / %d)" % (smallmatch, smallmatch_ok, smallmatch_total)

    if bigmatch_total:
        bigmatch = bigmatch_ok / bigmatch_total
        if verbose: print >> matchlog, "big numbers match: %.2g (%d / %d)" % (bigmatch, bigmatch_ok, bigmatch_total)

    if stringmatch_total:
        stringmatch = stringmatch_ok / stringmatch_total
        if verbose: print >> matchlog, "STRING MATCH: %.2g (%.2g / %d)" % (stringmatch, stringmatch_ok, stringmatch_total)
    
    score = (smallmatch-0.5) * math.sqrt(smallmatch_total) + \
            (bigmatch-0.5) * math.sqrt(bigmatch_total) + \
            20 * (stringmatch-0.5) * math.sqrt(stringmatch_total) - \
            reftomismatch * 2 - \
            reffrommismatch * 2
            
    if verbose: print >> matchlog, "score: %.3g\n" % score
    return score, datamatches


# first, search only those binaries which have IDCs
def find_code_matches_idcs(D):
    M = defaultdict(list)
    
    # dumps for which we have info about funcs (from IDC maybe)
    Di = []
    for d in D:
        if d.FUNCS:
            Di.append(d)

    for d in Di:
        for a in d.FUNCS:
            sig = d.addr2sigs[a]
            for otherd in Di:
                if otherd != d:
                    key = (d,otherd) if d.bin < otherd.bin else (otherd,d)
                    if sig in otherd.sigs2addr:
                        candidates = otherd.sigs2addr[sig]
                        if len(candidates) < 20:
                            for c in candidates:
                                pair = (a,c) if d.bin < otherd.bin else (c, a)
                                M[key].append(pair)
    for key in M:
        M[key] = list(set(M[key]))

    for key in M:
        print "Found %d raw code matches between %s and %s." % (len(M[key]), key[0].bin, key[1].bin)

    return M

def CodeMatch(D):
    M1 = CodeMatch_dbfuncs(D)
    M2 = CodeMatch_corasick(D)
    M = {}
    for pair in list(set(M1.keys() + M2.keys())):
        M[pair] = list(set(M1.get(pair,[]) + M2.get(pair,[])))
    M = remove_duplicate_matches(M)
    return M
def CodeMatch_corasick(D):
    import ahocorasick

    for d in D:
        d.addr2sigs, d.sigs2addr = create_codesigs(d)
    for d in D:
        print "creating big codesig for %s..." % d.bin
        print min(d.ROM), max(d.ROM)
        d.bigsig = create_codesig(d, min(d.ROM), max(d.ROM))

    M = defaultdict(list)
    tree = ahocorasick.KeywordTree()

    print "gathering sigs..."
    for d in D:
        for a in d.FUNCS:
            sig = d.addr2sigs[a]
            if string.count(sig, " ") > 3:
                tree.add(sig)
    print "growing tree..."
    tree.make()

    for d in D:
        print "searching in %s..." % d.bin
        bigsig = d.bigsig
        found = 0
        pairs = 0
        for start,end in tree.findall_long(bigsig):
            #~ print start,end
            foundsig = bigsig[start:end]
            found += 1
            #~ print foundsig
            ast = d.loadaddr + string.count(bigsig[:start+1], " ") * 4
            aen = ast + string.count(foundsig, " ") * 4
            
            #~ print foundsig
            #~ print start,end
            #~ print hex(ast),hex(aen)
            
            #~ from IPython.Shell import IPShellEmbed
            #~ IPShellEmbed()()

            if ast in d.FUNCS:
                if d.FUNCS[ast] != aen:
                    print "mismatch: %x -> %x, found %x" % (ast, d.FUNCS[ast], aen)
                    continue
                    #~ print foundsig
                #~ else:
                    #~ print "match ok: %x -> %x" % (ast, D[b].FUNCS[ast])
            else:
                #~ print "new func: %x -> %x" % (ast, aen)
                d.MakeFunction(ast,aen)
            a = ast
            for dx in D:
                if dx != d:
                    #~ print "dx=",dx.bin
                    if hasattr(dx, 'sigs2addr') and foundsig in dx.sigs2addr:
                        if len(dx.sigs2addr[foundsig]) < 10:
                            for ax in dx.sigs2addr[foundsig]:
                                key = (d,dx) if d.bin < dx.bin else (dx,d)
                                pair = (a,ax) if d.bin < dx.bin else (ax,a)
                                #~ print key,pair
                                
                                M[key].append(pair)
                                #~ print key,pair
                                assert pair[0] in key[0].FUNCS
                                assert pair[1] in key[1].FUNCS
                                pairs += 1
        #~ print found, pairs
    save_raw_match_log(M, "raw-match-log-corasick.txt")
    M = remove_duplicate_matches(M)
    write_code_matches(M, "code-matches-corasick.txt")

    #~ for d in D:
        #~ del d.codesigs
        #~ del d.bigsig
    return M
            #~ print foundsig

def remove_duplicate_matches(M):
    print "Removing duplicates..."
    newM = {}
    for (d1,d2),m in M.iteritems():
        
        m.sort(key=lambda x: Score((d1,d2),x), reverse=True)
        
        newm = []
        handled = {}
        
        for a1,a2 in m:
            if handled.get(a1): continue
            if handled.get(a2): continue
            newm.append((a1,a2))
            handled[a1] = True
            handled[a2] = True
        
        newM[(d1,d2)] = newm
    for key in newM:
        print "Remaining %d code matches between %s and %s." % (len(newM[key]), key[0].bin, key[1].bin)
    return newM

rawlog = False
def save_raw_match_log(M, filename):
    if rawlog:
        print "Saving raw match log... (set match.rawlog=False to disable)"
        matchlog = open(filename, "w")
        for dumpair,m in M.iteritems():
            for addrpair in m:
                data_match_funcpair(dumpair,addrpair,log=matchlog)
        matchlog.close()
    else:
        print "Skipping raw match log... (set match.rawlog=True to enable)"

def write_code_matches(M, filename):
    out = open(filename, "w")
    for (d1,d2),m in M.iteritems():
        print >> out, ""
        print >> out, "Code matches between %s and %s:" % (d1.bin, d2.bin)
        print >> out, "=================================================="
        print >> out, ""
        for a1,a2 in m:
            print >> out, funcpair_score((d1,d2),(a1,a2))
    out.close()

from pylab import mean,std
def DataMatch(M):
    out = open("data-matches.txt", "w")
    outf = open("possible-code-matches.txt", "w")
    DM = {}
    SRC = {}
    for (d1,d2),m in M.iteritems():
        Dm = defaultdict(list)
        Src = defaultdict(list)
        
        kdm = 0
        kpc = 0
        print >> out, "Data matches between %s and %s:" % (d1.bin, d2.bin)
        print >> out, "=================================================="
        print >> outf, "Possible (inexact,unverified) code matches between %s and %s:" % (d1.bin, d2.bin)
        print >> outf, "=================================================="
        for a1,a2 in m:
            score, dm = data_match_funcpair((d1,d2),(a1,a2),log=False)
            for pair in dm:
                Dm[pair].append(score)
                Src[pair].append(((a1,a2),score))
        
        for (v1,v2) in sorted(Dm.keys(), key=lambda x: mean(Dm[x]), reverse=True):
            if v1 > d1.loadaddr and v2 > d2.loadaddr:
                o = outf
                kpc += 1
            else:
                o = out
                kdm += 1
            
            scores = Dm[(v1,v2)]
            print >> o, "%s === %s (mean=%.2g, stdev=%.2g, num=%d)" % (disasm.dataname(d1,v1),disasm.dataname(d2,v2),mean(scores),std(scores), len(scores))


        print "Found %d possible code matches between %s and %s." % (kpc,d1.bin,d2.bin)
        print "Found %d data matches between %s and %s." % (kdm,d1.bin,d2.bin)
        DM[d1,d2] = Dm
        SRC[d1,d2] = Src
    out.close()
    outf.close()

    return DM, SRC


def CodeMatch_dbfuncs(D):
    for d in D:
        d.addr2sigs, d.sigs2addr = create_codesigs(d)
    M = find_code_matches_idcs(D)
    save_raw_match_log(M, "raw-match-log-dbfuncs.txt")
    M = remove_duplicate_matches(M)
    write_code_matches(M, "code-matches-dbfuncs.txt")
    return M
    
def diff_side(dumpair, addrpair, score, sources, level=3):
    d1,d2 = dumpair
    a1,a2 = addrpair
    try:
        f1 = d1.Fun(a1)
        f2 = d2.Fun(a2)
    except:
        sc = "&larr;(%s)&rarr;" % ('{0:^+.2g}'.format(score))
        head = "<h%d>%s in %s %s %s in %s</h%d>" % (level, disasm.guess_data(d1,a1), d1.bin, sc, disasm.guess_data(d2,a2), d2.bin, level)
        srch = "<small>"
        for srcpair,sco in sources:
            srch += diff_side(dumpair, srcpair, sco, [], level=level+1)            
        srch += "</small>"
        return head + srch

    A = fileutil.capture(f1.disasm)[1].split("\n")
    B = fileutil.capture(f2.disasm)[1].split("\n")
    #~ a = [l.split("\t")[0] + " " + string.join(l.split("\t")[2:], "\t")[:60] for l in a]
    #~ b = [l.split("\t")[0] + " " + string.join(l.split("\t")[2:], "\t")[:60] for l in b]
    a = [string.join(l.split("\t")[2:], "\t")[:60] for l in A]
    b = [string.join(l.split("\t")[2:], "\t")[:60] for l in B]
    h = difflib.HtmlDiff()
    sc = "&larr;[%s]&rarr;" % ('{0:^+.2g}'.format(score))
    head = "<h%d>%s in %s %s %s in %s</h%d>" % (level, f1.name, f1.dump.bin, sc, f2.name, f2.dump.bin, level)
    htm = head + h.make_table(a, b, f1.dump.bin, f2.dump.bin)
    for i,l in enumerate(A):
        try: addr = int(l.split("\t")[0][:-1],16)
        except: continue
        r = r'<td class="diff_header" id="from([0-9_]+)%d">%d</td>' % (i+1,i+1)
        new = r'<td class="diff_header" id="from\\1%d">%x:</td>' % (i+1,addr)
        htm = re.sub(r,new,htm)

    for i,l in enumerate(B):
        try: addr = int(l.split("\t")[0][:-1],16)
        except: continue
        r = r'<td class="diff_header" id="to([0-9_]+)%d">%d</td>' % (i+1,i+1)
        new = r'<td class="diff_header" id="to\\1%d">%x:</td>' % (i+1,addr)
        htm = re.sub(r,new,htm)
    return htm

if __name__ == "__main__":
    import doctest
    prepare_test()
    doctest.testmod()
    end_test()
