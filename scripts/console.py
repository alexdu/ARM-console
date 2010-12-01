# ARM firmware analysis console for Magic Lantern
# http://magiclantern.wikia.com/wiki/GPL_Tools/ARM_console
#
# (C) 2010 Alex Dumitrache <broscutamaker@gmail.com>
# License: GPL
#
# Start the IPython console

import IPython

_args = ['-colors', 'LightBG', '-xmode', 'Plain', '-autocall', '1', "-pylab"]
ipshell = IPython.Shell.IPShellEmbed(_args, banner="\nARM firmware analysis console ready.")

