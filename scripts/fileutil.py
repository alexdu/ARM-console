# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# Module fileutil: misc file-related utilities

import os, sys, re, string, difflib
import cStringIO, traceback
from copy import copy
import time

def change_ext(file, newext):
    """ Changes extension of a file name.
    >>> change_ext("foo.py", "c")
    'foo.c'
    >>> change_ext("foo.py", ".jpg")
    'foo.jpg'
    >>> change_ext("foo.py", "")
    'foo'
    >>> change_ext("stubs-550d.108.S", "")
    'stubs-550d.108'
    """
    if newext and (not newext.startswith(".")):
        newext = "." + newext
    return os.path.splitext(file)[0] + newext


def GetLoadAddr(bin):
    """Guess the load address from bin's name
    >>> GetLoadAddr("bin_0x12345678_abc")
    305419896
    >>> GetLoadAddr("0x12345678_bin")
    305419896
    >>> GetLoadAddr("12345678_bin")
    Don't know load address for 12345678_bin. Ignoring this file.
    """
    m = re.search("0x([a-f0-9]+)", bin.lower())
    if m:
        return int(m.groups()[0], 16)
    else:
        print "Don't know load address for %s. Ignoring this file." % bin

def stripaddr(f):
    """
    >>> stripaddr("bin_0x12345678_abc")
    'bin__abc'
    >>> stripaddr("045678_bin")
    '045678_bin'
    """
    return re.sub("0x([a-f0-9]+)", "", f)

def matchInputFilesToBins(bins, inputs):
    """
    >>> matchInputFilesToBins(["5d2_0x12345678.bin"], ["5D2 AJ.idc"])
    {'5d2_0x12345678.bin': '5D2 AJ.idc'}
    >>> matchInputFilesToBins(["5d2_0x12345678.bin"], ["5D2 AJ.idc", "5D2_AI.idc"])  # second has better match due to underscore
    {'5d2_0x12345678.bin': '5D2_AI.idc'}
    >>> matchInputFilesToBins(["5d2_0x12345678.bin"], ["5D2_AJ.idc", "5D2 AI.idc"])
    {'5d2_0x12345678.bin': '5D2_AJ.idc'}
    >>> matchInputFilesToBins(["5d2_0x12345678.bin", "7d_0x12345678.bin", "550d_106_0x12345678.bin", "550d_108_0x12345678.bin"],["5D2_AJ.idc", "7d AI.idc"])
    {'7d_0x12345678.bin': '7d AI.idc', '5d2_0x12345678.bin': '5D2_AJ.idc'}
    >>> matchInputFilesToBins(["5d2_0x12345678.bin", "7d_0x12345678.bin", "550d_106_0x12345678.bin", "550d_108_0x12345678.bin"],["5D2_AJ.idc", "nikon d3s.idc", "7d AI.idc", "550d-108.idc", "550d-106-0x1234.idc"])
    Did not find the matching bin for nikon d3s.idc. Ignoring this file.
    {'7d_0x12345678.bin': '7d AI.idc', '550d_106_0x12345678.bin': '550d-106-0x1234.idc', '5d2_0x12345678.bin': '5D2_AJ.idc', '550d_108_0x12345678.bin': '550d-108.idc'}
    >>> matchInputFilesToBins(["550d.109.0xff010000.bin","550d.108.0xff010000.bin"], ["stubs-550d.108.S"])
    {'550d.108.0xff010000.bin': 'stubs-550d.108.S'}
    """
    bins_without_addr = []
    for b in bins:
        bins_without_addr.append(stripaddr(b.lower()))

    idcs = {}
    idcscore = {}
    for f in inputs:
        #~ print f
        try:
            fs = stripaddr(change_ext(f.lower(),""))
            #~ print bins_without_addr, fs
            #~ print difflib.get_close_matches(fs, bins_without_addr, 1, 0.3)
            binwa = difflib.get_close_matches(fs, bins_without_addr, 1, 0.3)[0]
            bin = bins[bins_without_addr.index(binwa)]
            score = difflib.SequenceMatcher(None, fs, binwa).ratio()
            #~ print score
            if score > idcscore.get(bin,0):
                idcs[bin] = f
                idcscore[bin] = score
        except IndexError:
            print "Did not find the matching bin for %s. Ignoring this file." % f
    return idcs

def GetInputFiles(regex=""):
    """ Guess input files, based on a regex
    >>> f = open("5d2_0x12345678.bin", "w"); f = open("5Dmk2 AJ.idc", "w")
    >>> GetInputFiles()  #doctest: +NORMALIZE_WHITESPACE
    Input files:    
    ===============================================================================
               Binary dump (*.bin)     LoadAddr     IDC database (*.idc)    
    ===============================================================================
                5d2_0x12345678.bin     12345678     5Dmk2 AJ.idc
    ===============================================================================
    (['5d2_0x12345678.bin'], {'5d2_0x12345678.bin': 305419896}, {'5d2_0x12345678.bin': '5Dmk2 AJ.idc'})
    >>> os.remove("5d2_0x12345678.bin"); os.remove("5Dmk2 AJ.idc")
    """
    bins = []
    loadaddrs = {}
    for f in sorted(os.listdir(".")):
        if f.lower().endswith(".bin"):
            addr = GetLoadAddr(f)
            if addr is not None:
                bins.append(f)
                loadaddrs[f] = addr
    
    F = lambda f: f.lower().endswith(".idc")
    idcs = matchInputFilesToBins(bins, filter(F, os.listdir(".")))

    for b in copy(bins):
        if not re.search(regex, b, re.IGNORECASE):
            bins.remove(b)
            del loadaddrs[b]
            if b in idcs: del idcs[b]
    
    print "Input files:"
    print "==============================================================================="
    print "           Binary dump (*.bin)     LoadAddr     IDC database (*.idc)    "
    print "==============================================================================="
    for b,a in loadaddrs.iteritems():
        idc = idcs.get(b, "n/a")
        print "%30s     %8X     %s" % (b, a, idc)
        
    print "==============================================================================="
    #~ if len(idcs) != len(bins):
        #~ print "sorry, you need to have an IDC for each BIN, since my dumb matching algorithm is really dumb... "
        #~ raise SystemExit

    return sorted(bins), loadaddrs, idcs

cap_en = True
# http://northernplanets.blogspot.com/2006/07/capturing-output-of-print-in-python.html
# Modified to disallow (indirect) recursive calls 
def capture(func, *args, **kwargs):
    """Capture the output of func when called with the given arguments.

    The function output includes any exception raised. capture returns
    a tuple of (function result, standard output, standard error).
    """
    global cap_en
    if not cap_en:
        return func(*args, **kwargs)
    stdout, stderr = sys.stdout, sys.stderr
    sys.stdout = c1 = cStringIO.StringIO()
    sys.stderr = c2 = cStringIO.StringIO()
    result = None
    cap_en = False
    try:
        result = func(*args, **kwargs)
    except:
        traceback.print_exc()
    cap_en = True
    sys.stdout = stdout
    sys.stderr = stderr
    return (result, c1.getvalue(), c2.getvalue())


if __name__ == "__main__":
    import doctest
    doctest.testmod()
