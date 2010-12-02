# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# Module idc: IDC parser

from __future__ import division
import sys, re, string
from pprint import pprint

def parse(idc):
    """ Get data from an IDC file 
    Returns 3 dictionaries: address => name, name => address, funcstart => funcend

    >>> pprint(parse("test.idc"))
    Parsing test.idc... found 2 MakeName's and 1 MakeFunction's
    ({4660: 'some_device', 4278190080L: 'main_prog'},
     {'main_prog': 4278190080L, 'some_device': 4660},
     {4278190080L: 4278190095L})
    """
    print "Parsing %s..." % idc,   ; sys.stdout.flush()
    f = open(idc)
    lines = f.readlines()

    addr2name = {}
    name2addr = {}
    for l in lines:
        m = re.match(r'\s*MakeName\s*\((.*),\s*"(.*)"\)', l)
        if m:
            addr = int(m.groups()[0], 16)
            name = m.groups()[1]
            if name.startswith("$"): continue
            addr2name[addr] = name
            name2addr[name] = addr

    # MakeFunction(start, end)
    funcs = {}
    for l in lines:
        m = re.match(r'\s*MakeFunction\s*\((.*),\s*(.*)\)', l)
        if m:
            start = int(m.groups()[0], 16)
            end = int(m.groups()[1], 16)
            funcs[start] = end


    print "found %d MakeName's and %d MakeFunction's" % (len(addr2name), len(funcs))
    
    return addr2name, name2addr, funcs


if __name__ == "__main__":
    import doctest
    from disasm import prepare_test
    prepare_test()
    doctest.testmod()
