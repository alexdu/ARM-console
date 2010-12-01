# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# Module cache: cache stuff which takes a loooooooong time to compute

# import with: import cache

# ! Don't use: from cache import *

import sys, marshal, os
DISASM_CACHE = {}

cache_enabled = True
cache_disk = False

def enable_disk():
    global cache_disk
    cache_disk = True
def disable_disk():
    global cache_disk
    cache_disk = False

def enable():
    global cache_enabled
    cache_enabled = True

def disable():
    global cache_enabled
    cache_enabled = False

def clear():
    global DISASM_CACHE
    DISASM_CACHE = {}

def load():
    global DISASM_CACHE
    if cache_enabled and cache_disk and os.path.isfile("disasm.cache"):
        try:
            print "Loading cache...", ; sys.stdout.flush()
            DISASM_CACHE = marshal.load(open("disasm.cache","rb"))
            DISASM_CACHE["dirty"] = False
            print "ok"
        except:
            print "failed"
            print sys.exc_info()[0]
def save():
    if cache_enabled and cache_disk and DISASM_CACHE["dirty"]:
        print "saving cache...", ; sys.stdout.flush()
        _quickdump(DISASM_CACHE, "disasm.cache")
        print "ok"

def access(key,func):
    if cache_enabled:
        assert key
        f = hash(func.func_code)
        if (key,f) in DISASM_CACHE:
            return DISASM_CACHE[(key,f)]
    
    value = func(key)

    if cache_enabled:
        DISASM_CACHE[(key,f)] = value
        DISASM_CACHE["dirty"] = True

    return value

def _quickdump(obj, filename):
    f = open(filename,"wb")
    marshal.dump(obj, f)
    f.close()



