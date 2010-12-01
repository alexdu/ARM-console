# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# Module bunch: a simple structure in Python

# from http://stackoverflow.com/questions/35988/c-like-structures-in-python
class Bunch:
    def __init__(self, **kwds):
        self.__dict__.update(kwds)
