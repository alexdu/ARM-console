#!/usr/bin/env python




##################################################
## DEPENDENCIES
import sys
import os
import os.path
try:
    import builtins as builtin
except ImportError:
    import __builtin__ as builtin
from os.path import getmtime, exists
import time
import types
from Cheetah.Version import MinCompatibleVersion as RequiredCheetahVersion
from Cheetah.Version import MinCompatibleVersionTuple as RequiredCheetahVersionTuple
from Cheetah.Template import Template
from Cheetah.DummyTransaction import *
from Cheetah.NameMapper import NotFound, valueForName, valueFromSearchList, valueFromFrameOrSearchList
from Cheetah.CacheRegion import CacheRegion
import Cheetah.Filters as Filters
import Cheetah.ErrorCatchers as ErrorCatchers

##################################################
## MODULE CONSTANTS
VFFSL=valueFromFrameOrSearchList
VFSL=valueFromSearchList
VFN=valueForName
currentTime=time.time
__CHEETAH_version__ = '2.4.3'
__CHEETAH_versionTuple__ = (2, 4, 3, 'development', 0)
__CHEETAH_genTime__ = 1291208784.035285
__CHEETAH_genTimestamp__ = 'Wed Dec  1 15:06:24 2010'
__CHEETAH_src__ = 'AsmBase.tmpl'
__CHEETAH_srcLastModified__ = 'Wed Dec  1 15:06:08 2010'
__CHEETAH_docstring__ = 'Autogenerated by Cheetah: The Python-Powered Template Engine'

if __CHEETAH_versionTuple__ < RequiredCheetahVersionTuple:
    raise AssertionError(
      'This template was compiled with Cheetah version'
      ' %s. Templates compiled before version %s must be recompiled.'%(
         __CHEETAH_version__, RequiredCheetahVersion))

##################################################
## CLASSES

class AsmBase(Template):

    ##################################################
    ## CHEETAH GENERATED METHODS


    def __init__(self, *args, **KWs):

        super(AsmBase, self).__init__(*args, **KWs)
        if not self._CHEETAH__instanceInitialized:
            cheetahKWArgs = {}
            allowedKWs = 'searchList namespaces filter filtersLib errorCatcher'.split()
            for k,v in KWs.items():
                if k in allowedKWs: cheetahKWArgs[k] = v
            self._initCheetahInstance(**cheetahKWArgs)
        

    def respond(self, trans=None):



        ## CHEETAH: main method generated for this template
        if (not trans and not self._CHEETAH__isBuffering and not callable(self.transaction)):
            trans = self.transaction # is None unless self.awake() was called
        if not trans:
            trans = DummyTransaction()
            _dummyTrans = True
        else: _dummyTrans = False
        write = trans.response().write
        SL = self._CHEETAH__searchList
        _filter = self._CHEETAH__currentFilter
        
        ########################################
        ## START - generated method body
        
        write(u'''<html> 
<head><title>''')
        _v = VFFSL(SL,"title",True) # u'$title' on line 2, col 14
        if _v is not None: write(_filter(_v, rawExpr=u'$title')) # from line 2, col 14.
        write(u'''</title>
<link rel="stylesheet" href="disasm.css" type="text/css" />
</head> 
<body> 
<div id=\'toolbar\'>
<ul>
<li><a href="functions-by-addr.htm">Functions</a></li>
<li><a href="names-by-addr.htm">Names</a></li>
<li><a href="strings.htm">Strings</a></li>
<li><a href="tasks.htm">Tasks</a></li>
<li><a href="semaphores.htm">Semaphores</a></li>
<li><a href="msgqueues.htm">MsgQueues</a></li>
<li><a href="properties.htm">Properties</a></li>
<li><a href="eventprocs.htm">Eventprocs</a></li>
<li><a href="statemachines.htm">FSMs</a></li>
</ul>
</div>
<div id=\'main\'>
<h1>''')
        _v = VFFSL(SL,"title",True) # u'$title' on line 20, col 5
        if _v is not None: write(_filter(_v, rawExpr=u'$title')) # from line 20, col 5.
        write(u'''</h1>
''')
        _v = VFFSL(SL,"content",True) # u'$content' on line 21, col 1
        if _v is not None: write(_filter(_v, rawExpr=u'$content')) # from line 21, col 1.
        write(u'''
</div>
</body> 
</html> 
''')
        
        ########################################
        ## END - generated method body
        
        return _dummyTrans and trans.response().getvalue() or ""
        
    ##################################################
    ## CHEETAH GENERATED ATTRIBUTES


    _CHEETAH__instanceInitialized = False

    _CHEETAH_version = __CHEETAH_version__

    _CHEETAH_versionTuple = __CHEETAH_versionTuple__

    _CHEETAH_genTime = __CHEETAH_genTime__

    _CHEETAH_genTimestamp = __CHEETAH_genTimestamp__

    _CHEETAH_src = __CHEETAH_src__

    _CHEETAH_srcLastModified = __CHEETAH_srcLastModified__

    _mainCheetahMethod_for_AsmBase= 'respond'

## END CLASS DEFINITION

if not hasattr(AsmBase, '_initCheetahAttributes'):
    templateAPIClass = getattr(AsmBase, '_CHEETAH_templateClass', Template)
    templateAPIClass._addCheetahPlumbingCodeToClass(AsmBase)


# CHEETAH was developed by Tavis Rudd and Mike Orr
# with code, advice and input from many other volunteers.
# For more information visit http://www.CheetahTemplate.org/

##################################################
## if run from command line:
if __name__ == '__main__':
    from Cheetah.TemplateCmdLineIface import CmdLineIface
    CmdLineIface(templateObj=AsmBase()).run()

