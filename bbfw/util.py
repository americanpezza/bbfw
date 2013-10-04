# This project is maintained at http://github.com/americanpezza/bbfw/
#
# Copyright (c) 2013 Mario Beccia
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.




import traceback, subprocess
from elements import Rule
from renderers import FileRenderer

def loadRuleset(ruleset):
    fileRenderer = FileRenderer(ruleset)    
    string = fileRenderer.render()
    iptp = subprocess.Popen(['iptables-restore'],stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    (outmsg, errmsg) = iptp.communicate(string)

    if iptp.returncode != 0:
        oldLines = string.split("\n")
        errlines = errmsg.split("\n")
        errline = -1
        configErrLine = "<can't determine line>"
        configChain = "<can't determine chain>"
        configTable = "<can't determine table>"
        try:
            for line in errlines:
                if line.find("Error occurred at line") == 0:
                    parts = line.split()
                    errline = int(parts[len(parts) - 1])

                    lines = fileRenderer.renderLines()
                    if len(oldLines) > errline:
                        configErrLine = oldLines[errline - 1]
                        rule = Rule(configErrLine)
                        chain = ruleset.getChainFromRule(rule)
                        configTable = chain.getRoot()
                        configChain = chain.getName()

                    break
        except Exception,e:
            traceback.print_exc()

        print "\nCould not load config.\nError occurred while loading the following rule (config line# %s, chain %s in %s):\n-->  %s\nError is: %s" % (errline, configChain, configTable, configErrLine, errlines[0])
    else:
        print "\nConfig rules loaded succesfully"

