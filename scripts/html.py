# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# Module html: generate a browseable disasm dump, along with some firmware analysis results


import scripts.emusym as es
import sys
from scripts import *
from Cheetah.Template import Template as _Template
from scripts.fileutil import capture
import shutil
import cgi
import cPickle
from profilestats import profile
import traceback
import idapy

def Template(*args,**kwargs):
    here = os.getcwd()
    os.chdir("scripts/html/")
    try:
        t = _Template(*args,**kwargs)
    finally:
        os.chdir(here)
    return t

granul = 0x2000

def addrfile(x):
    """
    >>> addrfile(0x12345678)
    '12344000.htm'
    """
    return '%08x.htm'% ((x//granul)*granul)

def funcfile(fun):
    """
    >>> funcfile(Fun(D[0],0X8017F4))
    'sub_008017f4.htm'
    """
    return 'sub_%08x.htm' % fun.addr

def funcsigfile(fun):
    """
    >>> funcsigfile(Fun(D[0],0X8017F4))
    'sub_008017f4.sig'
    """
    return 'sub_%08x.sig' % fun.addr
def link2addr(x):
    """
    >>> link2addr(0x123456)
    '<a href="00122000.htm#A123456">123456</a>'
    """
    return '<a href="%s#_%X">%X</a>' % (addrfile(x), x, x)

def link2func(fun):
    """
    >>> link2func(Fun(D[0],0X8017F4))
    '<a href="sub_008017f4.htm">sub_8017F4</a>'
    """
    return '<a href="%s">%s</a>' % (funcfile(fun), fun.name)

def xlink2func(fun):
    return '<a xlink:href="%s" style="fill: blue" xlink:show="new" target="_top">%s</a>' % (funcfile(fun), fun.name)

def link2funcoff(dump, addr):
    """
    >>> link2funcoff(D[0], 0X8017F8)
    '<a href="sub_008017f4.htm#A8017F8">sub_8017F4+4</a>'
    >>> link2funcoff(D[0], 0X123456)
    '<a href="00122000.htm#A123456">ROMBASE+0x99456</a>'
    """
    try: return '<a href="%s#_%X">%s</a>' % (funcfile(dump.Fun(which_func(dump,addr))), addr, funcoff(dump, addr))
    except: return '<a href="%s#_%X">%s</a>' % (addrfile(addr), addr, funcoff(dump, addr))

def openf(bin,name,mode="w"):
    dir = change_ext(bin,"")
    if not os.path.isdir(dir):
        os.mkdir(dir)
    outf = os.path.join(dir, name)
    out = open(outf,mode)
    return out

def refs_html(dump,value=None, func=None, context=0, f=sys.stdout):
    R = []
    refs = find_refs(dump, value, func)
    for a,v in refs:
        #~ print "out",a,v
        if v > 0x1000 and v == dump.A2REFS[a][0]:
            R.append({'address': link2funcoff(dump,a), 'value': guess_data(dump, v) })
            #~ print >> f, "%s:" % link2funcoff(dump,a),
            #~ show_disasm_html(dump, a-4*context, a+4*context+4, f)
            #~ print >> f, guess_data(dump, v)
    return R

def refsig(F):
    R = ""
    dump = F.dump
    refs = find_refs(dump, None, F.addr)
    for a,v in refs:
        if v > 0x1000 and v == dump.A2REFS[a][0]:
            R += "%x %s\n" % (a, guess_data(dump, v))
    return R
    
def calls_html(dump, F):
    print "calls..."
    C = []
    for a in range(F.addr, F.end, 4):
        try: 
            calledfun = bkt.func_call_addr(a)
            if GetFunctionName(calledfun) == F.name:
                assert isFuncStart(calledfun)    # if assert OK => recursive call, else, just a jump inside the function
        except: continue
        if calledfun:
            try: call = bkt.find_func_call(a, len(funargs.getFuncSignature(calledfun).args))
            except: continue
            c = {'address': link2funcoff(dump, a)}
            funaddr, funname, args = bkt.find_func_call(a, len(funargs.getFuncSignature(calledfun).args))
            try: fun = dump.Fun(funaddr)
            except: fun = None
            c['func'] = link2func(fun) if fun else funname
            c['args'] = args
            print funname + args
            C.append(c)
    return C

def callers_html(dump,value=None, func=None, context=0, f=sys.stdout):
    print "callers..."
    C = []
    refs = find_refs(dump, value, func)
    for a,v in sorted(refs):
        #~ print hex(a)
        #~ print >> f, "%s:" % link2funcoff(dump,a),
        try: 
            calledfun = bkt.func_call_addr(a)
            print calledfun
            assert calledfun == value
        except:
            #~ disasm_html(dump, a-4*context, a+4*context+4, f)
            c = {'address': link2funcoff(dump, a), 'disasm': disasm_html(dump, a-4*context, a+4*context+4, f)}
            C.append(c)
            continue
    
        try:
            #~ print a, calledfun, value
            c = {'address': link2funcoff(dump, a)}
            funaddr, funname, args = bkt.find_func_call(a, len(funargs.getFuncSignature(calledfun).args))
            try: fun = dump.Fun(funaddr)
            except: fun = None
            c['func'] = funname
            c['args'] = args
            C.append(c)
            print funname + args
        except:
            pass
            c = {'address': link2funcoff(dump, a), 'disasm': disasm_html(dump, a-4*context, a+4*context+4, f)}
            C.append(c)
            
    return C


def calls_html_quick(dump, F):
    C = []
    refs = list(set(find_refs(dump, func=F.addr)))
    for a,v in refs:
        if isFuncStart(v) or GetMnem(a) in ["BL","BLX"]:
            c = {'address': link2funcoff(dump, a), 'disasm': disasm_html(dump, a, a+4)}
            C.append(c)
    return C

def callers_html_quick(dump,value=None, func=None, context=0, f=sys.stdout):
    C = []
    refs = find_refs(dump, value, func)
    for a,v in sorted(refs):
            c = {'address': link2funcoff(dump, a), 'disasm': disasm_html(dump, a-4*context, a+4*context+4, f)}
            C.append(c)
    return C


def disasm_html(dump, start, end, f=None):
    if end is None: end = start+4
    LINES = []
    for a in range(start, end, 4):
        l = dump.DISASM.get(a)
        L = {}
        L['anchor'] = "_%X" % a
        crefs = CodeRefsTo(a)
        L['refs'] = string.join([link2addr(r) for r in crefs[:5]]).replace(">%X<" % (a-4), ">&#x2B01;<")
        if len(crefs) > 5: L['refs'] += "... (total %d refs)" % len(crefs)
        if not l: 
            #~ print >> f, "%s: <empty>" % link2addr(a)
            continue
        if len(l) > 8 and l[8] == ":":
            items = l.split("\t")
            addr = int(items[0][:-1], 16)
            assert addr==a
            raw = int(items[1], 16)
            #~ items[0] = link2addr(addr) + ":"

            if addr in dump.FUNCS:
                L['funcstart'] = link2func(dump.Fun(addr))

            if addr in dump.A2N:
                #~ print ""
                L['name'] = dump.A2N[addr]

            if 1:
                data = 0
                arg3 = False
                try:
                    mnef = items[2]
                    assert mnef.startswith("add")
                    args = items[3].split(",")
                    b = args[1].strip()
                    c = args[2].strip()
                    assert b in ["r15", "pc"]
                    assert c[0] == "#"
                    off = int(c[1:])
                    data = addr + off + 8
                    items[3] = items[3].replace("r15","pc")
                except:
                    try:
                        data = int(items[4].split(" ")[1], 16)
                    except:
                        try:
                            data = int(items[3].split(" ")[0], 16)
                            arg3 = True
                        except:
                            pass
                if data:
                    while len(items) < 5: items.append("")
                    index = 3 if arg3 else 4
                    prefix = "" if arg3 else "; "
                    if GuessString(dump, data): 
                        items[index] = "%s*%s" % (prefix, repr(GuessString(dump, data)))
                    elif data in dump.ROM and GuessString(dump, dump.ROM[data]): 
                        items[index] = "%s**%s" % (prefix, repr(GuessString(dump, dump.ROM[data])))
                    elif data in dump.FUNCS:
                        items[index] = "%s%s" % (prefix, link2func(dump.Fun(data)))
                    elif data in dump.ROM and dump.ROM[data] in dump.FUNCS: 
                        items[index] = "%spointer to %s" % (prefix, link2func(dump.Fun(dump.ROM[data])))
                    elif data in dump.ROM and GetMnem(a) == "B":
                        items[index] = "%s%s" % (prefix, link2addr(data))
                        if data in dump.A2N:
                            items[index] += "(%s)" % dataname(dump,data)
                    elif data in dump.A2N:
                        items[index] = "%s=%s" % (prefix, dataname(dump,data))
                    else:
                        items[index] = "%s%s" % (prefix, guess_data(dump, data))
                items[0] = "%12s" % items[0]

                while len(items) < 5: items.append("")
                items[3] = items[3].replace("r15","pc").replace("r14", "lr").replace("r13", "sp")
                L['address'] = link2addr(addr)
                L['data'] = items[1]
                L['inst'] = items[2]
                mne = GetMnem(addr)
                L['mnem'] = mne.lower() if mne else items[2]
                L['flags'] = items[2][len(str(L['mnem'])):] if mne else ""
                if not mne: L['undefined'] = True
                L['params'] = items[3]
                L['comment'] = items[4]

            if addr+4 in dump.FUNCENDS:
                st = dump.FUNCENDS[addr+4]
                L['funcend'] = funcname(dump, which_func(dump,addr))
                            
            for i in range(4):
                if GuessString(dump, addr+i) and not GuessString(dump, addr+i-1):
                    s = GuessString(dump, addr+i)
                    L['string'] = cgi.escape(repr(s))
        LINES.append(L)
    return LINES


def sourcefile(dump, addr):
    refs = find_refs(dump, func=addr)
    for a,v in refs:
        s = GuessString(dump, v)
        if s:
            if s.endswith(".c") or s.endswith(".cfg"):
                return s
    return "~"

def table(dump, template, dinosaur):
    for lis,fn,fi,var in dinosaur:
        items = []
        for F in lis:
            item = {}
            for lis2,fn2,fi2,var2 in dinosaur:
                item[var2] = fi2(F)
            items.append(item)
        f = openf(dump.bin, fn)
        ns = {'dumpname': dump.bin, "rows": items}
        print >> f, Template(file=template, searchList=[ns])
        f.close()

def name_index(dump):
    print "Creating name index..."
    names = []
    for name,addr in sorted(dump.N2A.iteritems()):
        if isFuncStart(addr): continue
        if addr < 100: continue
        if name[0] == 'a'and name[1] <= 'Z' and GetString(addr): continue
        if name[0] == '$': continue
        refs = find_refs(dump,addr)
        reflist = [link2addr(a) for a,v in refs]
        s = {'address': addr, 'name': cgi.escape(name), 'refs': string.join(reflist, ", "), 'numrefs': len(reflist)}
        names.append(s)
    Nn = sorted(names, key=lambda x: x["name"].lower())
    Na = sorted(names, key=lambda x: x["address"])
    Nr = sorted(names, key=lambda x: -x["numrefs"])
    #~ print Nr
    dinosaur = [(Na, "names-by-addr.htm", lambda n: link2addr(n['address']), 'address'),
                (Nn, "names-by-name.htm", lambda n: n['name'], "name"),
                (Nr, "names-by-ref.htm", lambda n: n['refs'], "refs")]

    table(dump, "Names.tmpl", dinosaur)

def func_index(dump):
    print "Creating function index..."
    Fn  = [dump.Fun(a) for a in sorted(dump.FUNCS.keys(), key=lambda x: dump.Fun(x).name.lower())]
    Fa  = [dump.Fun(a) for a in sorted(dump.FUNCS.keys())]
    Fs  = [dump.Fun(a) for a in sorted(dump.FUNCS.keys(), key=lambda x: -dump.Fun(x).size)]
    Fcf = [dump.Fun(a) for a in sorted(dump.FUNCS.keys(), key=lambda x: -len(filter(lambda av: av[1] in dump.FUNCS, find_refs(dump, None, x))))]
    Fct = [dump.Fun(a) for a in sorted(dump.FUNCS.keys(), key=lambda x: -len(find_refs(dump, x)))]
    Fsf = [dump.Fun(a) for a in sorted(dump.FUNCS.keys(), key=lambda x: sourcefile(dump, x))]

    dinosaur = [(Fn, "functions-by-name.htm", lambda f: link2func(f), 'name'),
                (Fa, "functions-by-addr.htm", lambda f: link2addr(f.addr), "address"),
                (Fs, "functions-by-size.htm", lambda f: f.size, "size"),
                (Fcf, "functions-by-callsfrom.htm", lambda f: len(filter(lambda av: av[1] in dump.FUNCS, find_refs(dump, None, f.addr))), "callsfrom"),
                (Fct, "functions-by-callsto.htm", lambda f: len(find_refs(dump, f.addr)), "callsto"),
                (Fsf, "functions-by-source.htm", lambda f: sourcefile(dump, f.addr), "source")]

    table(dump, "FuncIndex.tmpl", dinosaur)

def strings_index(dump):
    print "Creating strings index..."

    f = openf(dump.bin, "strings.htm")
    ns = {}
    strings = []
    for addr,s in sorted(dump.STRINGS.iteritems()):
        refs = find_refs(dump,addr)
        reflist = [link2addr(a) for a,v in refs]
        s = {'address': addr, 'msg': cgi.escape(repr(s)), 'refs': string.join(reflist, ", ")}
        strings.append(s)
    ns["strings"] = strings
    ns['dumpname'] = dump.bin
    print >> f, Template(file="Strings.tmpl", searchList=[ns])
    f.close()

def func_quick(F):
    dump = F.dump
    select_dump(dump)
    es.resetLog()
    msg = str(F)
    ns = {}
    ns['funcname'] = F.name
    ns['funcaddr'] = hex(F.addr)
    ns['dumpname'] = dump.bin
    ns['codeflow'] = ""
    ns['decompiled'] = "in progress..."

    ns['lines'] = disasm_html(dump, F.addr, F.end)
    ns['calls'] = calls_html_quick(dump, F)
    ns['callers'] = callers_html_quick(dump, F.addr, context=0)
    ns['references'] = refs_html(dump, func=F.addr, context=-1)
    
    f = openf(dump.bin, funcfile(F))
    print >> f, Template(file="Func.tmpl", searchList=[ns])
    f.close()        

    f = openf(dump.bin, funcsigfile(F))
    cPickle.dump(refsig(F), f)
    f.close()

def func_full(F):
    print F
    dump = F.dump
    select_dump(dump)
    es.resetLog()
    msg = str(F)
    ns = {}
    ns['funcname'] = F.name
    ns['funcaddr'] = hex(F.addr)
    ns['dumpname'] = dump.bin
    ns['codeflow'] = ""
    ns['decompiled'] = "too complex?"

    try:
        #~ es.resetLog()
        print "code paths..."
        CP = es.find_code_paths(F.addr, timeout=10)

        if len(CP) < 50:
            try:
                print "decompiling..."
                ns['decompiled'] = str(deco.decompile(F.addr, CP))
            except:
                ns['decompiled'] = "whoops..."
        else:
            ns['decompiled'] = "too many code paths (%d, limit=50)" % len(CP)
            
        svg = change_ext(funcfile(F), ".svg")
        svgf = os.path.join(change_ext(dump.bin,""), svg)
        es.create_graph(CP, svgf)
        sv = open(svgf)
        svgdata = sv.read()
        sv.close()
        #svgdata = re.sub("@([a-zA-Z0-9_]+)", '<a xlink:href="\\1.htm" style="fill: blue" xlink:show="new" target="_top">\\1</a>', svgdata)
        for m in re.findall("@([a-zA-Z0-9_]+)", svgdata):
            try:
                fun = dump.Fun(m)
            except:
                continue
            
            svgdata = svgdata.replace("@" + str(fun.name), xlink2func(fun))
        wid = int(re.search('<svg width="([0-9]+)pt"', svgdata).groups()[0])
        sv = open(svgf,"w")
        sv.write(svgdata)
        sv.close()
        es.log.flush()
        #~ align = "align='right'" if wid < 600 else ""
        #~ print >> f, "<embed src='%s' %s >" % (svg,align)
        ns['codeflow'] = svg
        ns['codeflow_width'] = "%spt" % wid
    except:
        traceback.print_exc()
        pass

    ns['lines'] = disasm_html(dump, F.addr, F.end)
    ns['calls'] = calls_html(dump, F)
    ns['callers'] = callers_html(dump, F.addr, context=0)
    ns['references'] = refs_html(dump, func=F.addr, context=-1)
    
    f = openf(dump.bin, funcfile(F))
    print >> f, Template(file="Func.tmpl", searchList=[ns])
    f.close()
    


def func_update(F,quick=True):
    try:
        f = openf(dump.bin, funcsigfile(F), 'r')
        s = cPickle.load(f)
        f.close()
    except:
        print "Signature not found for %s => updating" % F.name
        func_quick(F)
        if not quick: func_full(F)
    if s != refsig(F):
        print "Signature has changed for %s => updating" % F.name
        func_quick(F)
        if not quick: func_full(F)

def full(D,q=True):
    if type(D) != list: D = [D]
    if q: quick(D)
    for dump in D:
        print "=" * (len(dump.bin) + 33)
        print "Running symbolic analysis for %s..." % dump.bin
        print "=" * (len(dump.bin) + 33)
        progress("Function analysis...")
        for i,a in enumerate(sorted(dump.FUNCS, key=lambda x: funcname(dump, x))):
            #~ continue
            progress(float(i) / len(dump.FUNCS))
            F = dump.Fun(a)
            func_full(F)


def update(D, quick=True):
    if type(D) != list: D = [D]
    for dump in D:
        for i,a in enumerate(dump.FUNCS):
            F = dump.Fun(a)
            func_update(f, quick)

def quick(D):
    if type(D) != list: D = [D]
    for dump in D:
        print "=" * (len(dump.bin) + 17)
        print "Disassembling %s..." % dump.bin
        print "=" * (len(dump.bin) + 17)
        select_dump(dump)
        name_index(dump)
        func_index(dump)
        strings_index(dump)
        shutil.copyfile("scripts/html/disasm.css", os.path.join(change_ext(dump.bin, ""), "disasm.css"))

        
        progress("Function disassembly...")
        for i,a in enumerate(dump.FUNCS):
            #~ continue
            progress(float(i) / len(dump.FUNCS))
            F = dump.Fun(a)
            func_quick(F)


        progress("Raw disassembly...")
        maxaddr = max(dump.ROM)
        for a in range(dump.loadaddr, maxaddr, granul):
            progress(float(a - dump.loadaddr) / (maxaddr - dump.loadaddr))
            f = openf(dump.bin, addrfile(a))
            ns = {}
            ns['start'] = "0x" + hex(a)
            ns['end'] = "0x" + hex(a+granul-1)
            ns['dumpname'] = dump.bin
            ns['lines'] = disasm_html(dump, a, a+granul, f)
            print >> f, Template(file="RawDisasm.tmpl", searchList=[ns])
            f.close()


if __name__ == "__main__":
    import doctest
    doctest.testmod()
