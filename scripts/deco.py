# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# Module deco: experimental decompiler for ARM


import time
from copy import copy, deepcopy
import sys
import pydot, string
import inspect, os
import emusym
from emusym import *
from sympy.core.cache import * 

def inde(k):
    print " " * k,
    
def merge_trees(a,b,k=0):
    #~ print "merge:", a, b
    #~ print type(a), type(b)
    assert type(a) == type(b)
    if type(a) == SEQ:
        elems = []
        #~ print "ELEM A:",a
        #~ print "ELEM B:",b
        assert len(a.args)==len(b.args)
        for i in range(len(a.args)):
            elema, elemb = a.args[i], b.args[i]
            elems.append(merge_trees(elema, elemb, k+1))
        return SEQ(evaluate=False, *(elems))
    elif type(a) == IFB:
        assert a.args[0] == b.args[0]
        return IFB(a.args[0], merge_trees(a.args[1], b.args[1], k+1), evaluate=False)
    elif type(a) == IF:
        assert a.args[0] == b.args[0] # should be the same IF condition
        ba = a.args[1:]
        bb = b.args[1:]
        newB = []
        for ifba in ba:     # merge each IFB branch with an identical one from the other side
            assert type(ifba) == IFB
            #~ inde(k); print "trying to merge",str(ifba.args[0]),a.args[0]
            found = False
            for ifbb in bb:
                assert type(ifbb) == IFB
                if str(ifba.args[0]) == str(ifbb.args[0]):
                    ifba = merge_trees(ifba, ifbb,k+1)
                    newB.append(ifba)
                    found = True
                    break
            #~ inde(k); print found
            if not found: newB.append(ifba)
        for ifbb in bb:   # also consider what's in b but not in a...
            #~ inde(k); print "trying to merge b ",str(ifbb.args[0]),a.args[0]
            found = False
            for ifba in ba:
                assert type(ifba) == IFB
                if str(ifba.args[0]) == str(ifbb.args[0]):
                    found = True
                    break
            #~ inde(k); print found
            if not found: newB.append(ifbb)
        #~ inde(k); print "newB:", len(newB), newB
        newB.sort(key=lambda x: str(x.args[0]) != "TRUE")
        args = [a.args[0]] + newB
        #~ if len(newB) == 2: print IF(*args)
        return IF(evaluate=False, *(args))
        #print args
        #return a
    else:
        assert str(a) == str(b)
        return a

def rebuild_tree(t):
    if t and t.args:
        A = []
        for a in t.args:
            A.append(rebuild_tree(a))
        return eval(type(t).__name__)(*A)
    else:
        return t

def find_some_kind_of_operation(t, optype=CALL):
    if type(t) == optype:
        return [t]
    elif hasattr(t,'args') and t.args:
        A = []
        for a in t.args:
            A += find_some_kind_of_operation(a, optype)
        return A
    return []

def decompile(ea, CP=None):
    #~ print "finding code paths..."
    if CP is None: CP = emusym.find_code_paths(ea)
    CP = sorted(CP, key=lambda x: -len(x))
    print "found %d code paths" % len(CP)

    emusym.resetArm(func=True)
    has_loops = False
    for i,cpf in enumerate(CP):
        cp,cf = emusym.split_code_path_ea_cond(cpf)
        if len(cp) != len(set(cp)):
            has_loops = True

    if has_loops:
        raise Exception, "code has loops => not implemented yet"
        #~ time.sleep(1)
        

        
    CT = []
    for i,cpf in enumerate(CP):
        print "emulating code path %d of %d" % (i+1, len(CP))

        emusym.resetArm(func=True)
        CT.append(emusym.emusym_code_path(cpf, codetree=True))

        #~ print CT[-1]
    #~ print "first"
    #~ print(CT[0])
    #~ print "second"
    #~ print(CT[1])
    #~ print len(CT)


    print "\nmerging"
    mt = CT[0]
    for ct in CT[1:]:
        mt = merge_trees(mt, ct)
    #~ print "merged"

    #~ return mt

    print "rebuilding"
    T = []
    for flags in [(False,False), (True,False), (True,True)]:
        emusym.setSimpFlags(*flags)
        T.append(rebuild_tree(mt))
    T2 = []
    for flags in [(False,False), (True,False), (True,True)]:
        for t in T:
            emusym.setSimpFlags(*flags)
            T2.append(rebuild_tree(t))
    T2.sort(key=lambda x: len(str(x)))
    mt = T2[0]
    #~ print "rebuilt", len(str(mt))
    #~ print mt

    #~ print
    #~ print "SUMMARY"
    #~ print "======="
    #~ print "* only unique items are displayed"
    #~ calls = find_some_kind_of_operation(mt, CALL)
    #~ calls = sorted(list(set(calls)), key=lambda x: str(x))
    #~ if calls:
        #~ print "CALLS:", len(calls)
        #~ for c in calls:
            #~ print " --> ", c
#~ 
#~ 
    #~ memr = find_some_kind_of_operation(mt, MEM)
    #~ memr = sorted(list(set(memr)), key=lambda x: str(x))
    #~ if memr:
        #~ print "MEMORY READS:", len(memr)
        #~ for m in memr:
            #~ print " --> ", m
#~ 
    #~ memw = find_some_kind_of_operation(mt, MEMWRITE)
    #~ memw = sorted(list(set(memw)), key=lambda x: str(x))
    #~ if memw:
        #~ print "MEMORY WRITES:", len(memw)
        #~ for m in memw:
            #~ print " --> ", m
#~ 
    #~ regw = find_some_kind_of_operation(mt, REGWRITE)
    #~ regw = sorted(list(set(regw)), key=lambda x: str(x))
    #~ if regw:
        #~ print "SPECIAL REGISTRY WRITES:", len(regw)
        #~ for m in regw:
            #~ print " --> ", m
    return mt
    #~ create_graph(CP)

