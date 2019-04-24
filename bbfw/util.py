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

def purgeTableOLD(table, chain, recursive=True):
    deletions = 0
    ruleset = getCurrentRuleset()
    tables = ruleset.getTables()

    tablesToPurge = tables.keys()

    # If a table has been specified, only purge that one
    if table is not None:
        if table in tablesToPurge:
            tablesToPurge = [table]
        else:
            raise Exception("Unknown table %s" % table)

    for tableToPurge in tablesToPurge:
        log(50, "Now purging table %s" % tableToPurge)

        tableObject = ruleset.getTable(tableToPurge)
        chainsToDelete = tableObject.getChains()

        # If a chain has been specified, only remove that one
        if chain is not None:
            chainObj = tableObject.getChain(chain)
            if chainObj is None:
                raise Exception("Unknown chain %s in table %s specified for deletion, aborting" % (chain, tableObject.getName()))

            chainsToDelete = [chainObj]

        chainNames = [n.getName() for n in chainsToDelete]
        for chainToDelete in chainNames:
            log(21, "Now deleting chain %s" % chainToDelete)
            deletions = deletions + purgeChain(tableObject, chainToDelete )
            log(70, "Chain %s removed from table %s" % (chainToDelete, tableToPurge))

    if deletions > 0:
        # Apply changes
        loadRuleset(ruleset, True, True)
        print "Removed %s chains, done." % deletions
    else:
        print "No chains were deleted, configuration unchanged."

def purgeTable(table, chain, recursive=True):
    deletions = 0
    ruleset = getCurrentRuleset()
    tables = ruleset.getTables()

    tablesToPurge = tables.keys()

    # If a table has been specified, only purge that one
    if table is not None:
        if table in tablesToPurge:
            tablesToPurge = [table]
        else:
            raise Exception("Unknown table %s" % table)

    for tableToPurge in tablesToPurge:
        log(50, "Now purging table %s" % tableToPurge)

        tableObject = ruleset.getTable(tableToPurge)
        for chainToDelete in tableObject.chains(chain):
            log(21, "Now deleting chain %s" % chainToDelete)
            deletions = deletions + purgeChain(tableObject, chainToDelete )
            log(70, "Chain %s removed from table %s" % (chainToDelete, tableToPurge))

    if deletions > 0:
        # Apply changes
        loadRuleset(ruleset, True, True)
        print "Removed %s chains, done." % deletions
    else:
        print "No chains were deleted, configuration unchanged."

def purgeChain(table, chainName):
    removed = 0
    log(71, "PurgeChain: chain %s has root %s" % (chainName, table.getName()))

    # now remove the chain itself
    tableToPurge = table.getName()
    chain = table.getChain(chainName)
    chain.purge()
    log(70, "Purged chain %s" % chainName)

    builtins = TABLE_CHAINS[table.name]
    if chainName in builtins:
        log(80, "Chain %s is builtin, cannot remove it" % chainName)
        result = chain.setPolicy("ACCEPT")
    else:
        refremoved = 0
        referers = chain.getReferers()

        for referer in referers:
            refremoved = refremoved + purgeReferences(table, referer, chain.getName())

        removed = removed + 1
        result = table.removeChain(chain)

        log(40, "Deleted chain %s/%s" % (table.getName(), chainName))
        log(70, "Removed %s references to chain %s" % (str(refremoved), chainName))

    return removed

def purgeReferences(table, chainName, target):
    refremoved = 0
    chain = table.getChain(chainName)
    log(41, "Removing references to chain %s contained in chain %s" % (target, chainName))

    rules = chain.getRules()
    chain.purge()

    for rule in rules:
        if rule.getTarget() != target:
            chain.append(rule)
        else:
            log(41, "Rule '%s' in chain %s referenced chain %s, removed" % (rule, chain.getName(), target))
            refremoved = refremoved + 1

    return refremoved

def getCurrentRuleset():
    iptp = subprocess.Popen(['iptables-save'],stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    (out, err) = iptp.communicate()
    lines = out.split("\n")
    parser = IPTSaveFileParser(lines)
    config = parser.parse()
    config.name = "Currently loaded ruleset"

    return config

def loadRuleset(ruleset, quiet=False, wipe=False):
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

        if not quiet:
            print "\nCould not load config.\nError occurred while loading the following rule (config line# %s, chain %s in %s):\n-->  %s\nError is: %s" % (errline, configChain, configTable, configErrLine, errlines[0])

def mergeRulesetsOLD(master, slave, wipe=False):
    """
    If we requested to wipe the master ruleset, simply return the slave; otherwise, merge the slave into the master.
    The merge is done by comparing each table, and then each chain. If a table does not exist in the master, then create it. If a chain does not exist in the master, the create it. If a chain exists in the master, replace its contents with the corresponding from the slave.
    The result of a non-wipe merge is that each chain int he slave is "injected" into the master, without alterting chains that were already present in the master, but not in the slave.
    """

    result = slave
    if not wipe:
        log(41, "Merging rulesets")
        result = master
        result.name = "Merged ruleset"
        masterTables = master.getTables()
        slaveTables = slave.getTables()

        # Chains are stored in a flat array in the table, so there's no need for recursion when
        # updating or adding a chain. We never remove a chain from a table!

        # Start with updating master tables with corresponding ones in the slave ruleset
        # Update master tables if they're contained in the slave ruleset
        for tableName in masterTables.keys():
            if tableName in slaveTables.keys():
                log(50, "Table %s needs to be merged" % tableName)
                # now check the chains in this table
                masterTable = masterTables[tableName]
                masterChains = masterTable.getChains()
                slaveTable = slaveTables[tableName]
                slaveChains = slaveTable.getChains()

                # verify if chains exist in the master that are also in the slave
                for masterChain in masterChains:
                    slaveChain = slaveTable.getChain(masterChain.getName())
                    if slaveChain is not None:
                        log(50, "Chain %s needs to be merged" % slaveChain.getName())
                        # remove the chain from the master table
                        masterTable.removeChain(masterChain)
                        # now add it back
                        masterTable.appendChain(slaveChain)
                    else:
                        log(71, "Chain %s already synch'ed" % masterChain.getName())

                for slaveChain in slaveChains:
                    masterChain = masterTable.getChain(slaveChain.getName())
                    # Add the slave chain is the masterTable does not contain it
                    if masterChain is None:
                        log(50, "Chain %s needs to be added" % slaveChain.getName())
                        masterTable.appendChain(slaveChain)
                    else:
                        log(71, "Chain %s already synch'ed" % slaveChain.getName())

            else:
                log(71, "Table %s not present in the proposed ruleset but available in the master ruleset: untouched" % tableName)

        # Add slave tables when they're not contained in the master ruleset
        for tableName in slaveTables.keys():
            if tableName not in masterTables.keys():
                log(50, "Table %s needs to be added" % tableName)
                masterTables[tableName] = slaveTables[tableName]
            else:
                log(71, "Table %s is alreasdy synchronized" % tableName)

    return result

