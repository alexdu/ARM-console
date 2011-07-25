# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# Module disasm: disassembly and code browsing routines

from __future__ import division
import os, sys, re, time, subprocess, shlex, marshal, difflib, math, copy, string
from easygui import *
from collections import defaultdict
import cache
from bunch import Bunch
from pprint import pprint
from fileutil import *
import idapy
import idc
import console, IPython
import match
import emusym
import deco
import shutil
import bkt
import srcguess

gui_enabled = False
armelf = "arm-elf-"
objcopy = armelf + "objcopy"
objdump = armelf + "objdump"


class Dump(Bunch):
    """Contains all the info about a dump: ROM contents, disassembly, references, function names..."""
    def __str__(self):
        return "Dump of %s\nFields: %s" % (self.bin, string.join(self.__dict__.keys(), ", "))

    def __repr__(self):
        return "Dump of %s" % self.bin

    def refs(self, value=None, func=None, context=0, gui=gui_enabled):
        if gui:
            s = "References to %s from %s in %s" % (dataname(self, value) if value else "any value",
                                                    Fun(self,func).name if func else "any function",
                                                    self.bin)
            codebox(msg=s, title=s, text=capture(self.refs, value, func, context, False)[1:])
            return
        
        show_refs(self, value, func, context)

    def funcs(self,pattern,ratio=1,num=10):
        find_funcs(self,pattern,ratio,num)

    def _get_strings_work(self):
        print "finding strings..."
        STRMASK = {}
        STRINGS = {}
        ROM = self.ROM
        for addr in sorted(ROM.keys()):
            for i in range(4):
                if addr+i not in STRMASK:
                    s = GuessString(self, addr+i)
                    if s:
                        STRINGS[addr+i] = s
                        for k in range(len(s)+1): STRMASK[addr+i+k] = True
        self.STRMASK = STRMASK
        return STRINGS
    def _get_strings(self): 
        #return self._get_strings_work()
        return cache.access(self.bin, lambda x: self._get_strings_work())
    STRINGS = property(_get_strings)
    def strings(self, pattern="", gui=gui_enabled):
        if gui:
            s = "Strings in %s" % (self.bin)
            codebox(msg=s, title=s, text=capture(self.strings, pattern, False)[1:])
            return

        for a,s in self.STRINGS.iteritems():
            if re.search(pattern, s, re.IGNORECASE):
                print "%x: %s" % (a, repr(s))

    def strrefs(self, pattern, context=0):
        matches = []
        for a,s in self.STRINGS.iteritems():
            if re.search(pattern, s, re.IGNORECASE):
                matches.append(a)
        for a in matches:
            print "\nString references to %x %s:" % (a,repr(self.STRINGS[a]))
            self.refs(a, gui=False)

    def disasm(self, start, end=None):
        show_disasm(self, start, end)
    
    def save_disasm(self, file):
        print "Saving disassembly to %s..." % file
        out = capture(show_disasm, self, self.loadaddr, max(self.ROM))[1]
        f = open(file,"w")
        f.write(out)
        f.close()

    def Fun(self, name_or_addr):
        return Fun(self, name_or_addr)

    def load_names(dump, file, guessfunc=False):
        if file.endswith(".S"):
            a2n,n2a = match.parse_stub(file)
            fe = {}
            if guessfunc:
                for a in a2n:
                    if a > dump.loadaddr and a < dump.maxaddr:
                        tryMakeSub(dump,a)
        elif file.lower().endswith(".idc"):
            a2n,n2a,fe = idc.parse(file)
        else:
            raise Exception, "Unrecognized extension: " + file
        
        for n,a in n2a.iteritems(): 
            dump.MakeName(a,n)
        for f,e in fe.iteritems():
            dump.MakeFunction(f,e)

        if not hasattr(dump, "_loadednames"):
            dump._loadednames = {}
        dump._loadednames.update(n2a)

    def save_names(dump, file):
        if os.path.isfile(file):
            shutil.copyfile(file, file + '~')
        if is_idc(file):
            save_names_idc(dump, file)
        else:
            save_names_subs(dump, file)


    def save_new_names(dump, file, oldnames=None):
        na = []
        if oldnames is None:
            oldnames = dump._loadednames
        for n,a in sorted(dump.N2A.iteritems()):
            if n in oldnames and oldnames[n] == a: continue
            na.append((n,a))
        if is_idc(file):
            save_names_idc(dump, file, na)
        else:
            save_names_subs(dump, file, na)

    def check_integrity(dump):
        for a,n in dump.A2N.iteritems():
            if dump.N2A[n] != a:
                print "mismatch:",a,n,dump.N2A[n]
        for n,a in dump.N2A.iteritems():
            if dump.A2N[a] != n:
                print "mismatch:",n,a,dump.A2N[a]
    
    def MakeName(dump,addr,name):
        if not name:
            try: name = dump.A2N[addr]
            except KeyError: 
                print "No name is associated with %x." % addr
                return
            print "Deleting name %x -> %s" % (addr, name)
            del dump.A2N[dump.N2A[name]]
            del dump.N2A[name]
            return
        if name in dump.N2A or addr in dump.A2N:
            if name not in dump.N2A: oldname = dump.A2N[addr]
            else: oldname = name
            oldaddr = dump.N2A[oldname]
            print "Overwriting %x -> %s with %x -> %s" % (oldaddr, oldname, addr, name)
            if oldaddr != addr and addr in dump.A2N:
                name_at_new_addr = dump.A2N[addr]
                print "Warning: deleting %x -> %s" % (addr, name_at_new_addr)
                del dump.A2N[addr]
                del dump.N2A[name_at_new_addr]
            del dump.A2N[oldaddr]
            del dump.N2A[oldname]
        dump.A2N[addr] = name
        dump.N2A[name] = addr
        assert len(dump.A2N) == len(dump.N2A)

    def MakeFunction(dump,start,end=None,name=None):
        """
        >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
        Input files:
        ...
        >>> d.MakeFunction(1, 10, "myfun")
        >>> d.MakeFunction(1, 10, "myfun")
        Overwriting name myfun
        """
        if end is None:
            idapy.select_dump(dump)
            end = cache.access(start, emusym.GuessFunction)
            if end is None:
                print "Could not guess end address for function %x => skipping" % start
                return 
            end += 4
        f,e = start,end
        n = funcname(dump,f)
        dump.FUNCS[f] = e
        dump.FUNCENDS[e] = f
        for a in range(f,e-3):
            dump.WHICHFUNC[a] = f
        if name:
            dump.MakeName(f,name)

    def AddRef(dump, addr, value):
        if (addr,value) in dump.REFLIST:
            print "Reference to %x from %x already exists." % (value, addr)
            assert value in dump.A2REFS[addr]
            assert addr in dump.REF2AS[value]
            return
        print "Adding reference to %x from %x" % (value, addr)
        dump.REFLIST.append((addr,value))
        dump.A2REFS[addr].append(value)
        dump.REF2AS[value].append(addr)

    # print information about new functions named
    def named_percentage(d):
        k = 0
        A = []
        named, unnamed = 0, 0
        for f in d.FUNCS:
            try: F = d.Fun(f)
            except: continue
            if F.name.startswith("sub_"):
                unnamed += 1
            else:
                named += 1

        print "# Total Functions Named:", named, "\n# Total Functions:", named + unnamed, "\n# Percentage Named:", 100 * named / (named + unnamed), "%"
        print "################################################################"

    def update_func_indexes(dump):
        print "updating function indexes (FUNCENDS and WHICHFUNC)...",
        dump.FUNCENDS.clear()
        dump.WHICHFUNC.clear()
        for f,e in dump.FUNCS.iteritems():
            n = funcname(dump,f)
            for a in range(f,e-3):
                dump.WHICHFUNC[a] = f
        for f,e in dump.FUNCS.iteritems():
            dump.FUNCENDS[e] = f
        print "ok."

class Fun():
    """
    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> f = Fun(d, "main_porg")
    Unknown function: main_porg. Using closest match: main_prog.
    >>> print f
    ASM function: main_prog at 0xff000000 in test-0xff000000.bin
    """
    def __init__(self, dump, addr_or_name):
        addr = get_func(dump, addr_or_name)
        if not addr: raise "Invalid function: " + str(addr_or_name)
        self.dump = dump
        self.addr = addr

    def __str__(self):
        return "ASM function: %s at 0x%x in %s" % (self.name, self.addr, self.dump.bin)

    def __repr__(self):
        return "ASM function: %s at 0x%x in %s" % (self.name, self.addr, self.dump.bin)
    
    def disasm(self, gui=gui_enabled):
        if gui:
            s = "Disassembly of %s at 0x%x in %s" % (self.name, self.addr, self.dump.bin)
            codebox(msg=s, title=s, text=capture(self.disasm, False)[1:])
            return
        
        show_disasm_func(self.dump, self.addr)
    #~ disasm = property(_get_disasm)
    
    def _get_end(self):
        return self.dump.FUNCS[self.addr]
    end = property(_get_end)

    def _get_size(self):
        return int(self.end - self.addr)
    size = property(_get_size)

    def _get_sig(self):
        return match.create_codesig(self.dump, self.addr, self.end)
    sig = property(_get_sig)

    def called_by(self, context=-1):
        refs = find_refs(self.dump, self.addr)
        for a,v in refs:
            print "%x: %s" % (a, funcoff(self.dump, a))
            if context >= 0: 
                show_disasm(self.dump, a-4*context, a+4*context+4)
                print

    def calls(self, context=0):
        refs = find_refs(self.dump, None, self.addr)
        for a,v in refs:
            if v in self.dump.FUNCS:
                show_disasm(self.dump, a-4*context, a+4*context+4)
                if context: print

    def refs(self, context=0, gui=gui_enabled):
        if gui:
            s = "Addresses referenced by %s at 0x%x in %s" % (self.name, self.addr, self.dump.bin)
            codebox(msg=s, title=s, text=capture(self.refs, context, False)[1:])
            return
        
        refs = find_refs(self.dump, None, self.addr)
        for a,v in refs:
            print ""
            print "%s:" % funcoff(self.dump, a)
            show_disasm(self.dump, a-4*context, a+4*context+4)
            print guess_data(self.dump,v)

    def strings(self, gui=gui_enabled):
        refs = find_refs(self.dump, None, self.addr)
        for a,v in refs:
            if GuessString(self.dump, v):
                print GuessString(self.dump, v)

    def _get_name(self):
        return funcname(self.dump, self.addr)
    name = property(_get_name)
    
def show_disasm_func(dump, f):
    """Displays disassembly of a function, given by name or address.
    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...

    >>> show_disasm_func(d, "main_prog")      #doctest: +NORMALIZE_WHITESPACE
    // Start of function: main_prog
    NSTUB(main_prog, ff000000):
    ff000000:	e3a01000 	mov	r1, #0	; 0x0
    ff000004:	e59f2001 	ldr	r2, [pc, #1]	; 0xff00000d
    ff000008:	e3a02004 	mov	r2, #4	; 0x4
    ff00000c:	e0810002 	add	r0, r1, r2
    """
    f = get_func(dump,f)
    show_disasm(dump, f, dump.FUNCS[f])


def check_elf():
    for bin in [objcopy, objdump]:
        try:
            p = subprocess.Popen(shlex.split(bin + " -V"), stdout=subprocess.PIPE)
            p.communicate()
        except:
            print
            print "Could not run %s." % bin
            print "Make sure you have the arm-elf utilities in your PATH."
            print "For details, see http://magiclantern.wikia.com/wiki/Build_instructions/550D"
            print
            print sys.exc_info()[1]
            print
            raise SystemExit
        
    
def disasm_work(bin, addr):
    check_elf()
    print "Disassembling %s <%x>..." % (bin, addr),  ; sys.stdout.flush()
    tmp = change_ext(bin, ".elf")
    subprocess.check_call(shlex.split("%s --change-addresses=0x%x -I binary -O elf32-littlearm -B arm \"%s\" \"%s\"" % (objcopy, addr, bin, tmp)))
    subprocess.check_call(shlex.split("%s --set-section-flags .data=code \"%s\"" % (objcopy, tmp)))
    p = subprocess.Popen(shlex.split("%s -d \"%s\" -M reg-names-raw" % (objdump, tmp)), stdout=subprocess.PIPE)
    dasm = p.communicate()[0]
    os.remove(tmp)
    print "ok"
    return dasm

def disasm_dump(bin, addr):
    """ Disassemble a file using arm-elf-objdump; return the output as plain text
    >>> print disasm_dump("test-0xff000000.bin", 0xff000000)  #doctest: +NORMALIZE_WHITESPACE
    Disassembling test-0xff000000.bin <ff000000>... ok
    <BLANKLINE>
    tmp.elf:     file format elf32-littlearm
    <BLANKLINE>
    <BLANKLINE>
    Disassembly of section .data:
    <BLANKLINE>
    ff000000 <_binary_test_0xff000000_bin_start>:
    ff000000:	e3a01000 	mov	r1, #0	; 0x0
    ff000004:	e59f2001 	ldr	r2, [pc, #1]	; ff00000d <_binary_test_0xff000000_bin_start+0xd>
    ff000008:	e3a02004 	mov	r2, #4	; 0x4
    ff00000c:	e0810002 	add	r0, r1, r2
    ff000010:	eafffffa 	b	ff000000 <_binary_test_0xff000000_bin_start>
    <BLANKLINE>
    """
    return cache.access((bin,addr), lambda x: disasm_work(*x))


def parse_disasm(dump):
    """
    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> pprint(parse_disasm(d)[1])        #doctest: +NORMALIZE_WHITESPACE
    Parsing disassembly of test-0xff000000.bin...
       found 13 lines
    {4278190080L: 'mov',
     4278190084L: 'ldr',
     4278190088L: 'mov',
     4278190092L: 'add',
     4278190096L: 'b'}
    """
    print "Parsing disassembly of %s..." % dump.bin, 
    lines = dump.RAWASM.split("\n")
    print " found %d lines" % len(lines)
    
    ROM = {}
    MNEF = {}
    ARGS = {}
    REFS = {}
    DISASM = {}
    for l in lines:
        l = re.sub("<_binary.*>", "", l)
        if len(l) > 8 and l[8] == ":":
            items = l.split("\t")
            addr = int(items[0][:-1], 16)
            try: 
                raw = int(items[1], 16)
                ROM[addr] = raw
                DISASM[addr] = l
            except: pass
            
            try:
                mnef = items[2]
                MNEF[addr] = mnef
            except IndexError: continue
            
            # stupid objdump misses this PC-relative addressing: add rx, r15, offset
            try:
                assert mnef.startswith("add") or mnef.startswith("sub")
                args = items[3].split(",")
                b = args[1].strip()
                c = args[2].strip()
                assert b in ["r15", "pc"]
                #~ print l
                assert c[0] == "#"
                off = int(c[1:])
                data = addr + off + 8 if mnef.startswith("add") else addr - off + 8
                #~ print data
                REFS[addr] = data
            except:
                try:
                    comt = int(items[4].split(" ")[1], 16)
                    REFS[addr] = comt
                except:
                    try:
                        data = int(items[3].split(" ")[0], 16)
                        REFS[addr] = data
                    except:
                        pass
    return ROM, MNEF, ARGS, REFS, DISASM

def UINT32(dump,addr):
    """ Get an uint32 from ROM, from a 4-byte aligned address

    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> UINT32(d, 0xff000000)
    3818917888L
    """
    return dump.ROM[addr]

def BYTE(dump,a):
    """ Get a byte from ROM

    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> BYTE(d, 0xff000000)
    0
    >>> BYTE(d, 0xff000001)
    16
    """
    return int((dump.ROM[4 * (a // 4)] >> (8 * (a%4))) & 0xFF)

def GuessString(dump, a, minlen=3):
    s = ""
    while len(s) < 100:
        try:
            c = BYTE(dump,a)
        except:
            return
        if c == 0: 
            if len(s) >= minlen: return s
            return
        elif (c > 31 and c < 127) or (c in [7, 8, 9, 10, 13]):
            s += chr(c)
            a += 1
        else: 
            return

def funcoff(dump, a):
    """
    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> funcoff(d, 0xff000000)
    'main_prog+0'
    >>> funcoff(d, 0xff000005)
    'main_prog+5'
    >>> funcoff(d, 0xff000123)
    'ROMBASE+0x123'
    """
    
    try:
        f = which_func(dump, a)
        return "%s+%d" % (funcname(dump,f),a-f)
    except:
        return "ROMBASE+%s" % hex(int(a - dump.loadaddr))
    #~ if a in dump.WHICHFUNC:
        #~ f = dump.WHICHFUNC[a]


def funcname(dump, addr):
    """
    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> funcname(d, 0xff000000)
    'main_prog'
    >>> funcname(d, 0xff000004)
    'sub_FF000004'
    """
    if addr: return dump.A2N.get(addr, "sub_%X" % addr)

def dataname(dump, addr):
    """
    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> dataname(d, 0x1234)
    '0x1234 (some_device)'
    >>> dataname(d, 0xff000004)
    '0xFF000004'
    """
    try:
        addr = int(addr)
    except:
        return str(addr)
    name = dump.A2N.get(addr, None)
    if name:
        return "0x%X (%s)" % (addr, name)
    else:
        return "0x%X" % (addr)

def get_func_approx(dump,func):
    funcs = []
    for f in dump.FUNCS:
        name = funcname(dump,f)
        funcs.append(name)
    matches = difflib.get_close_matches(guess_data(dump,func), funcs, 1, 0.7)
    if matches:
        print "Unknown function: %s. Using closest match: %s." % (func, matches[0])

        func = matches[0]
        func = dump.N2A.get(func, func)
        return func

    raise Exception, "Function not found: %s" % func

def get_func(dump,func):
    """
    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> get_func(d, "main_prog")
    4278190080L
    >>> get_func(d, "main_porg")
    Unknown function: main_porg. Using closest match: main_prog.
    4278190080L
    >>> get_func(d, 0xff000000)
    4278190080L
    >>> get_func(d, 0xff001234)
    Traceback (most recent call last):
      File "/usr/lib/python2.6/doctest.py", line 1248, in __run
        compileflags, 1) in test.globs
      File "<doctest __main__.get_func[4]>", line 1, in <module>
        get_func(d, 0xff001234)
      File "disasm.py", line 322, in get_func
        raise Exception, "Function outside dump: %s" % func
    Exception: Function outside dump: 4278194740
    """
    if func is None: return
    try: return func.addr
    except: pass
    
    funcn = func
    if str(func).startswith("sub_"): func = int(func[4:],16)
    func = dump.N2A.get(func, func)
    
    try: func = int(func)
    except: return get_func_approx(dump,funcn)

    if func in dump.FUNCS:
        return func

    if func < dump.minaddr or func > dump.maxaddr: 
        raise Exception, "Function outside dump: %s" % func

    raise Exception, "There's no function starting at %s" % func


def get_name(dump,name):
    """
    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> hex(get_name(d, "some_device"))
    '0x1234'
    >>> get_name(d, "some_deice")
    Unknown name: some_deice. Using closest match: some_device.
    4660
    >>> get_name(d, 0xff000000)
    4278190080L
    """
    if type(name) != str:
        return name
    
    if name.startswith("sub_"):
        try: return int(name[4:], 16)
        except: pass
    
    if name in dump.N2A:
        return dump.N2A[name]
    
    for n,a in sorted(dump.N2A.iteritems(), key = lambda x: x[1]):
        if n.startswith(name + "."):
            print "struct maybe: %s -> %s" % (n, name)
            return a
    
    matches = difflib.get_close_matches(name, dump.N2A.keys(), 1, 0.7)
    if matches:
        print "Unknown name: %s. Using closest match: %s." % (guess_data(dump,name), matches[0])
        name = matches[0]
        name = dump.N2A.get(name, name)
        return name

    raise Exception, "unknown name: %s" % guess_data(dump,name)


def index_refs(refs, ROM):
    print "Indexing references...",  ; sys.stdout.flush()
    A2REFS = defaultdict(list)
    REF2AS = defaultdict(list)
    for a,r in refs.iteritems():
        A2REFS[a].append(r)
        REF2AS[r].append(a)
        try: 
            p = ROM[r]
            A2REFS[a].append(p)
            REF2AS[p].append(a)
            try:
                p = ROM[p]
                A2REFS[a].append(p)
                REF2AS[p].append(a)
            except: pass
        except KeyError:
            pass
    print "ok"
    return A2REFS, REF2AS

def load_dumps(regex=""):
    """
    >>> D = load_dumps()         #doctest: +ELLIPSIS
    Input files:
    ...
    >>> D
    [Dump of test-0xff000000.bin]
    """
    bins, loadaddrs, idcs = GetInputFiles(regex)
    D = {}
    for b,a in loadaddrs.iteritems():
        D[b] = Dump(bin=b, RAWASM = disasm_dump(b,a))
        D[b].loadaddr = a

    for b in bins:
        D[b].FUNCS = {}
        D[b].FUNCENDS = {}
        D[b].WHICHFUNC = {}
        D[b].A2N = {}
        D[b].N2A = {}

    for b,i in idcs.iteritems(): # this needs cleanup
        D[b].A2N, D[b].N2A, D[b].FUNCS = cache.access(i, idc.parse)
        D[b].update_func_indexes()


    for b,a in loadaddrs.iteritems():
        D[b]._loadednames = {}
        D[b]._loadednames.update(D[b].N2A)
        D[b].ROM, D[b].MNEF, D[b].ARGS, refs, D[b].DISASM = cache.access(b, lambda b: parse_disasm(D[b]))
        D[b].minaddr = min(D[b].ROM)
        D[b].maxaddr = max(D[b].ROM)
        D[b].REFLIST = list(refs.iteritems())
        D[b].A2REFS, D[b].REF2AS = cache.access(b, lambda b: index_refs(refs, D[b].ROM))
        
    for b,a in loadaddrs.iteritems():
        D[b].STRINGS # compute them
        remove_autogen_string_names(D[b])

    cache.save()
    
    if len(D) == 1:
        print "Auto-selecting dump %s" % D[bins[0]].bin
        idapy.select_dump(D[bins[0]])

    return sorted(D.values(), key=lambda x: x.bin)

def guess_data(dump,value,allow_pointer=True):
    """
    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> guess_data(d, 0xff000000)
    '@main_prog'
    """
    if value is None: return "None"
    if type(value) == str:
        return value
    s = GuessString(dump, value)
    if s: return repr(s)
    
    if value in dump.FUNCS:
        return "@" + funcname(dump,value)

    if value in dump.A2N:
        return dataname(dump, value)
    
    if allow_pointer and value in dump.ROM:
        p = guess_data(dump, dump.ROM[value], allow_pointer=False)
        if p: return "0x%x: pointer to %s" % (value,p)
    
    return "0x%x" % value


def which_func(dump, a):
    """
    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> which_func(d, 0xff000008)
    4278190080L
    """

    if not dump.FUNCS:
        print "which_func: no functions defined; load an IDC or try with guessfunc.run(dump)"
        return

    return dump.WHICHFUNC.get(a)

    #~ try: return max(filter(lambda x: x <= a, dump.FUNCS.keys()))
    #~ except: return

def friendly_disasm(dump,l):
    if l is None: return ""
    items = l.split("\t")
    addr = int(items[0][:-1], 16)
    raw = int(items[1], 16)
    data = 0
    arg3 = False
    try:
        mnef = items[2].lower()
        assert mnef.startswith("add") or mnef.startswith("sub")
        args = items[3].split(",")
        b = args[1].strip().lower()
        c = args[2].strip().lower()
        assert b in ["r15", "pc"]
        assert c[0] == "#"
        off = int(c[1:])
        data = addr + off + 8 if mnef.startswith("add") else addr - off + 8
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
            items[index] = "%s@%s" % (prefix, funcname(dump,data))
        elif data in dump.A2N:
            items[index] = "%s=%s" % (prefix, dataname(dump,data))
        elif data in dump.ROM and dump.ROM[data] in dump.FUNCS: 
            items[index] = "%spointer to %s" % (prefix, funcname(dump, dump.ROM[data]))
        elif data in dump.A2N:
            items[index] = "%s=%s" % (prefix, dataname(dump,data))
        else:
            items[index] = "%s%s" % (prefix, guess_data(dump, data))


    try: items[3] = items[3].replace("r15","pc").replace("r14", "lr").replace("r13", "sp")
    except: pass
    
    l = string.join(items, "\t")
    return l

# code adapted from disasm.py
def show_disasm(dump, start, end=None):
    """
    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> show_disasm(d, 0xff000004)    #doctest: +NORMALIZE_WHITESPACE
    ff000004:	e59f2001 	ldr	r2, [pc, #1]	; 0xff00000d
    >>> show_disasm(d, 0xff000000, 0xff00000f)    #doctest: +NORMALIZE_WHITESPACE
    // Start of function: main_prog
    NSTUB(main_prog, ff000000):
    ff000000:	e3a01000 	mov	r1, #0	; 0x0
    ff000004:	e59f2001 	ldr	r2, [pc, #1]	; 0xff00000d
    ff000008:	e3a02004 	mov	r2, #4	; 0x4
    ff00000c:	e0810002 	add	r0, r1, r2
    """
    if end is None: end = start+4

    for a in range(start, end, 4):
        l = dump.DISASM.get(a)

        if a in dump.FUNCS:
            print "// Start of function: %s" % funcname(dump, a)

        if a in dump.A2N:
            print "NSTUB(0x%x, %s):" % (a, dump.A2N[a])

        if not l: 
            print "%x: <empty>" % a
            continue
        if len(l) > 8 and l[8] == ":":
            items = l.split("\t")
            addr = int(items[0][:-1], 16)
            raw = int(items[1], 16)
            
            assert addr == a

            l = friendly_disasm(dump,l)
            print l
            
            if addr+4 in dump.FUNCENDS:
                st = dump.FUNCENDS[addr+4]
                print "// End of function: %s" % funcname(dump, which_func(dump,addr))
                #~ print 
                            
            for i in range(4):
                if GuessString(dump, addr+i) and not GuessString(dump, addr+i-1):
                    s = GuessString(dump, addr+i)
                    print "%x:\tSTRING:  \t %s" % (addr, repr(s))

def addr_from_magic_string(s, rounded_32bit = True):
    s = s.strip()
    s = s.strip(":")
    _ip = IPython.ipapi.get()

    try:
        a = int(s)
    except:
        try:
            a = int(s,16)
        except:
            try:
                a = eval(s, _ip.user_ns)
            except:
                try:
                    #~ a = eval(s.replace("FF", "0xFF").replace("ff", "0xff")) # fixme: a smarter regex
                    a = eval("0x" + s, _ip.user_ns)
                except:
                    a = get_name(idapy._d, s)
    if rounded_32bit:
        a = (a//4)*4
    return a

def _magic_g(self, s):
    """Go to a ROM address or function name.
    
    Examples: 
    g ff340d40
    g bzero32
    """
    s = s.strip()
    if idapy._d is None:
        print "Please select a dump first. Example:"
        print "sel t2i"
        return
    a = addr_from_magic_string(s)
    show_disasm(idapy._d, a, a+80)

def _magic_f(self, s):
    """Go to the function containing some ROM address or name.
    
    Examples: 
    g ff340d40
    g bzero32
    """
    s = s.strip()
    if idapy._d is None:
        print "Please select a dump first. Example:"
        print "sel t2i"
        return
    a = addr_from_magic_string(s)
    while not idapy.isFuncStart(a) and not idapy.maybeFuncStart(a):
        a -= 4
    show_disasm(idapy._d, a, a+80)

def _magic_s(self, s):
    """Search for strings in the selected dump, using a regex.
    
    Examples:
    s canon
    s japan
    """
    if idapy._d is None:
        print "Please select a dump first. Example:"
        print "sel t2i"
        return
    idapy._d.strings(s)

def _magic_S(self, s):
    """Search for string references in the selected dump, using a regex.
    
    Examples:
    S canon
    S japan
    """
    if idapy._d is None:
        print "Please select a dump first. Example:"
        print "sel t2i"
        return
    idapy._d.strrefs(s)

def _magic_sel(self, s):
    """Select a dump. It will be used in IDAPython compatibility layer and in magic commands which operate on the selected dump.
    
    Usage:    
    sel t2i
    sel mk2
    """
    
    IPython.ipapi.get().runlines("idapy.select_dump(%s)" % s)

def _magic_r(self, s):
    """Search for references in the selected dump.
    
    Examples:
    r additional_version
    r 0x15094
    """
    if idapy._d is None:
        print "Please select a dump first. Example:"
        print "sel t2i"
        return
    a = addr_from_magic_string(s)
    idapy._d.refs(a)

def _magic_d(self, s):
    """Decompile
    
    Examples: 
    d FF066908
    d gui_main_task
    """
    if idapy._d is None:
        print "Please select a dump first. Example:"
        print "sel t2i"
        return
    a = addr_from_magic_string(s)
    print deco.P.doprint(deco.decompile(a, force=1))

def _magic_bd(self, s):
    """Backwards decompilation
    
    Examples: 
    d FF0669F4
    """
    if idapy._d is None:
        print "Please select a dump first. Example:"
        print "sel t2i"
        return
    a = addr_from_magic_string(s)
    bkt.back_deco(a)

def _magic_n(self, args):
    """Name an address in the firmware
    
    Examples: 
    n FF066908 gui_main_task
    n 0x2AA0 + 4 foobar
    """
    if idapy._d is None:
        print "Please select a dump first. Example:"
        print "sel t2i"
        return
    args = args.split(" ")
    s,n = string.join(args[:-1], " "), args[-1]
    
    a = addr_from_magic_string(s, rounded_32bit = False)
    print "NSTUB( 0x%X, %s )" % (a, n)
    idapy._d.MakeName(a, n)

IPython.ipapi.get().expose_magic("g", _magic_g)
IPython.ipapi.get().expose_magic("go", _magic_g)
IPython.ipapi.get().expose_magic("f", _magic_f)
IPython.ipapi.get().expose_magic("fun", _magic_f)
IPython.ipapi.get().expose_magic("s", _magic_s)
IPython.ipapi.get().expose_magic("S", _magic_S)
IPython.ipapi.get().expose_magic("rs", _magic_S)
IPython.ipapi.get().expose_magic("r", _magic_r)
IPython.ipapi.get().expose_magic("sel", _magic_sel)
IPython.ipapi.get().expose_magic("d", _magic_d)
IPython.ipapi.get().expose_magic("dec", _magic_d)
IPython.ipapi.get().expose_magic("bd", _magic_bd)
IPython.ipapi.get().expose_magic("n", _magic_n)
IPython.ipapi.get().expose_magic("name", _magic_n)

def find_refs(dump,value=None, func=None):
    """
    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> find_refs(d, 0xff00000d)
    [(4278190084L, 4278190093L)]
    """

    refs = []
    if value: 
        try:
            value = int(value)
        except:
            try:
                value = dump.N2A[value]
            except KeyError:
                raise Exception, "Unknown name: %s" % value
        #~ print "index by value"

        if func: func = get_func(dump,func)

        for a in dump.REF2AS[value]:
            if (not func) or (which_func(dump,a)==func):
                refs.append((a,value))

    elif func: # any value
        #~ print "index by func"
        func = get_func(dump,func)
        minaddr = func
        maxaddr = dump.FUNCS[func]
        for a in range(minaddr, maxaddr, 4):
            for r in dump.A2REFS[a]:
                refs.append((a,r))
    else:
        return dump.REFLIST
    
    return refs

# interactive functions
def show_refs(dump,value=None, func=None, context=0):
    """
    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> show_refs(d, 0xff00000d)       #doctest: +NORMALIZE_WHITESPACE
    <BLANKLINE>
    main_prog+4:
    ff000004:	e59f2001 	ldr	r2, [pc, #1]	; 0xff00000d
    0xff00000d
    """
    refs = find_refs(dump, value, func)
    for a,v in refs:
        print ""
        print "%s:" % funcoff(dump, a)
        show_disasm(dump, a-4*context, a+4*context+4)
        print guess_data(dump, v)

def find_funcs(dump,pattern,ratio=1,num=10):
    """ Find functions using either a regex search, or fuzzy string match
    
    >>> d = load_dumps()[0]   #doctest: +ELLIPSIS
    Input files:
    ...
    >>> find_funcs(d, "main")
    ff000000: main_prog
    >>> find_funcs(d, "main_porg", 0.5)
    ff000000: main_prog
    """
    if ratio != 1:
        funcs = []
        for f in dump.FUNCS:
            name = funcname(dump,f)
            funcs.append(name)
        matches = difflib.get_close_matches(pattern, funcs, num, ratio)
        for m in matches:
            print "%x: %s" % (dump.N2A[m], m)
        if len(matches) == num:
            print "stopping here (num=%d)" % num
    else:
        k = 0
        for f in dump.FUNCS:
            name = funcname(dump,f)
            m = re.search(pattern, name, re.IGNORECASE)
            if m:
                print "%x: %s" % (f, name)
                k += 1
                if k >= num: 
                    print "stopping here (num=%d)" % num
                    return

def tryMakeSub(d,v):
    if v % 4 != 0:
        print "Address %x not aligned, ignoring" % v
        return
    if v in d.FUNCS:
        print "Function 0x%x: already defined." % v
    #~ elif which_func(d,v):
        #~ print "Address 0x%x belongs to function %s." % (v, funcname(d,which_func(d,v)))
    elif v:
        if v < d.minaddr or v > d.maxaddr:
            print "Function 0x%x is outside ROM => skipping" % v
            return
        print "Creating function at %x" % v
        d.MakeFunction(v)




def save_names_idc(dump, file, na=None):
    file = open(file, "w")
    print >> file, """
// Generated with ARM disassembly console from %s
// http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#include <idc.idc>

static main() {    
    """ % dump.bin
    
    if na is None:
        na = sorted(dump.N2A.iteritems())
    for n,a in na:
        print >> file, '    MakeName(%10s, "%s");' % ("0x%X"%a,n)

    dele = 0
    #~ for n,a in dump._loadednames.iteritems():
        #~ if n not in dump.N2A:
            #~ dele += 1
            #~ print >> file, '    MakeName(%10s, ""); // old name: %s' % ("0x%X"%a, n)

    for a,e in dump.FUNCS.iteritems():
            print >> file, '    MakeFunction(0x%X, 0x%x);' % (a,e)
    
    print >> file, "}"
    file.close()

    if na is None:
        print "Saved %d names." % len(dump.N2A)
    else:
        print "Saved %d names out of %d." % (len(na), len(dump.N2A))
    
    if dele:
        print "Deleted %d names." % dele
        
def save_names_subs(dump, file, na=None):
    file = open(file, "w")
    if na is None:
        na = sorted(dump.N2A.iteritems())
    for n,a in na:
        print >> file, "NSTUB(%10s, %s)" % ("0x%X"%a,n)
    file.close()
    
    if na is None:
        print "Saved %d names." % len(dump.N2A)
    else:
        print "Saved %d names out of %d." % (len(na), len(dump.N2A))
    

def is_idc(file):
    if file.endswith(".S"):
        return False
    elif file.lower().endswith(".idc"):
        return True
    else:
        raise Exception, "Unrecognized extension: " + file

def guess_struct(d, x, refmin=2, maxsize=1000):
    candidates = {}
    for a,v in d.ROM.iteritems():
        if v <= x and v >= x-maxsize:
            nrefs = len(find_refs(d, v))
            if nrefs > refmin:
                candidates[v] = nrefs
    for c,n in sorted(candidates.iteritems(), key=lambda x: -x[1]):
        print hex(c),"refs=%d" % n, "dif=%d" % (x-c)

def reduce_aj_verbosity(d):
    aj_0x1234_usefulname = r"a?AJ_0x[0-9a-fA-F]+_(.*)"
    aj_0x1234_structname_0x12_to_0x34 = r"a?AJ_0x[0-9a-fA-F]+_(.*)_0x[0-9a-fA-F]+_to_0x[0-9a-fA-F]+$"
    rep = []
    for x,v in d.N2A.iteritems():
        x = x.replace("__","_")
        m = re.match(aj_0x1234_structname_0x12_to_0x34, x)
        if m:
            name = m.groups()[0]
            if not name.endswith("_struct"):
                name += "_struct"
            rep.append((v,x,name))
        else:
            m = re.match(aj_0x1234_usefulname, x)
            if m:
                name = m.groups()[0]
                rep.append((v,x,name))
    pprint(rep)
    for addr, oldname, newname in rep:
        if newname == "related": newname = ""
        d.MakeName(addr, newname)


def remove_decompiled_names(d):
    rep = []
    for x,v in d.N2A.iteritems():
        if ("*" in x) or ("(" in x):
            rep.append((v,x,""))
    pprint(rep)
    for addr, oldname, newname in rep:
        d.MakeName(addr, newname)

def remove_names_starting_with(d, prefix):
    rep = []
    for x,v in d.N2A.iteritems():
        if x.startswith(prefix):
            rep.append((v,x,""))
    pprint(rep)
    for addr, oldname, newname in rep:
        d.MakeName(addr, newname)

def remove_autogen_string_names(d):
    dele = 0
    for name, addr in list(d.N2A.iteritems()):
        if len(name) >=2 and name[0] == 'a' and addr in d.STRMASK:
            del d.N2A[name]
            del d.A2N[addr]
            dele += 1
    if dele: print "%s: deleted %d auto-generated string names." % (d.bin, dele)


def trim_names(d, maxlen):
    rep = []
    for x,v in d.N2A.iteritems():
        if len(x) > maxlen:
            rep.append((v,x,x[:maxlen]))
    pprint(rep)
    #~ for addr, oldname, newname in rep:
        #~ d.MakeName(addr, newname)

def prepare_test():
    asm = """
x:
mov r1, #0
ldr r2, [pc,#1]
mov r2, #4
add r0,r1,r2
b x
    """
    print "Test program:"
    print asm

    f = open("test.asm", "w")
    f.write(asm)
    f.close()

    idcf = """
    MakeName(0xff000000, "main_prog")
    MakeName(0x1234, "some_device")
    MakeFunction(0xff000000, 0xff00000f)
    """
    print "Test IDC:"
    print idcf

    f = open("test.idc", "w")
    f.write(idcf)
    f.close()

    os.system("arm-elf-as test.asm -o test.elf")
    os.system("arm-elf-objcopy -O binary test.elf test-0xff000000.bin")
    
    import cache
    cache.cache_enabled = False

def end_test():
    os.remove("test-0xff000000.bin")
    os.remove("test.elf")
    os.remove("test.asm")
    os.remove("test.idc")

    print "Tests complete."

if __name__ == "__main__":
    import doctest
    prepare_test()
    doctest.testmod()
    end_test()
