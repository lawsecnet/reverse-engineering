#
# Volatility framework plugin structure based on sample plugin
# presented in 'Art of Memory Forensics'
#

import volatility.utils as utils
import volatility.commands as commands
import volatility.win32.tasks as tasks

class SamplePlugin(commands.Command):

    def calculate(self):
    # main part of the plugin

        addr_space = utils.load_as(slef._config)
        for proc in tasks.pslist(addr_space):
            yield proc

    def render_text(self, outfd, data):
    # output formatting

        for proc in data:
            outfd.write("Process: {0}\n".format(proc.ImageFileName))
