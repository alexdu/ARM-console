# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# Module stats: simple call stats

from disasm import *
from idapy import *
from collections import defaultdict

def calls_to(dump, gui=gui_enabled):
    select_dump(dump)
    if gui:
        s = "Functions sorted by number of calls to them, in %s" % dump.bin
        codebox(msg=s, title=s, text=capture(calls_to, dump, False)[1:])
        return

    calls = []
    for f in dump.FUNCS:
        name = GetFunctionName(f)
        refs = CodeRefsTo(f)
        calls.append((f, name, len(refs)))    
    
    calls.sort(key=lambda x: x[2])

    for ea,name,num in calls:
        print "%5d: %s" % (num, name)

def calls_from(dump, gui=gui_enabled):
    select_dump(dump)
    if gui:
        s = "Functions sorted by number of calls made by them, in %s" % dump.bin
        codebox(msg=s, title=s, text=capture(calls_from, dump, False)[1:])
        return

    calls = []
    for f in dump.FUNCS:
        name = GetFunctionName(f)
        refs = list(set(CodeRefsFrom(f)))
        refnames = list([str(GetFunctionName(r)) for r in refs])
        calls.append((f, name, refnames))
    calls.sort(key=lambda x: len(x[2]))
    for ea,name,refs in calls:
        num = len(refs)
        print "%5s: %50s         %s" % (num, name, string.join(refs, ","))

