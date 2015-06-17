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
from elements import Rule, TABLE_CHAINS
from renderers import FileRenderer
from parsers import IPTSaveFileParser
from logger import log

def purgeTable(table, chain, recursive=True, reset=True):
    ruleset = getCurrentRuleset()
    tables = ruleset.getTables()
    
    tablesToPurge = tables.keys()
    if table is not None:
        if table in tablesToPurge:
            tablesToPurge = [table]
        else:
            raise Exception("Unknown table %s" % table)

    for tableToPurge in tablesToPurge:
        tableObject = ruleset.getTable(tableToPurge)
        chainsToDelete = tableObject.getBuiltinChains()
        if chain is not None:
            chainsToDelete = [chain]

        for chainToDelete in chainsToDelete:
            chainObject = tableObject.getChain(chainToDelete)
            if chainObject is None:
                raise Exception("Chain %s not present in table %s" % (chainToDelete, tableToPurge))

            purgeChain(chainObject, recursive, reset)

def purgeChain(chainObject, recursive, reset):
    children = chainObject.getChildren()

    if recursive:
        # Remove children
        for chain in children:
            purgeChain(chain, recursive, reset)

    # now remove the chain itself
    tableToPurge = chainObject.getRoot().name
    chainToDelete = chainObject.name

    result = _purgeChain(tableToPurge, chainToDelete)
    if not result:
        raise Exception("Cannot remove chain %s from table %s" % (chainToDelete, tableToPurge))

    table = chainObject.getRoot()
    builtins = TABLE_CHAINS[table.name]

    if reset and (chain.name in builtins):
        result = _setPolicy(tableToPurge, "ACCEPT")
        if not result:
            log(20, "Could not reset policy of table %s" % tableToPurge)

def _setPolicy(table, policy):
    iptp = subprocess.Popen(['iptables', '-P', table, policy],stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    (outmsg, errmsg) = iptp.communicate()

    result = True
    if iptp.returncode != 0:
        result = False

    return result

def _purgeChain(table, chain):
    iptp = subprocess.Popen(['iptables', '-F', chain, '-t', table],stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    (outmsg, errmsg) = iptp.communicate()

    result = True
    if iptp.returncode != 0:
        result = False

    return result

def getCurrentRuleset():
    iptp = subprocess.Popen(['iptables-save'],stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    
    (out, err) = iptp.communicate()
    lines = out.split("\n")
    parser = IPTSaveFileParser(lines)
    config = parser.parse()
    config.name = "Currently loaded ruleset"

    return config

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

