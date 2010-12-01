# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL


import os
os.environ['SYMPY_USE_CACHE']="no"

from pylab import *
from easygui import *
from scripts.disasm import *
from scripts.match import *
from scripts.idapy import *
from fileutil import *
from progress import progress
import bunch, cache, disasm, fileutil, idapy, idc, match, stats, emusym, deco, bkt, sympy, guessfunc, html, doc


print """
http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
You might want to do this:
    D = load_dumps("autoexec")"""
