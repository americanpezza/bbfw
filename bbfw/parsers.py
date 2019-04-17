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




import os, traceback

from elements import TABLES, Ruleset, Rule, Table, Chain, TablePropsException
from logger import log



class ConfFileException(Exception):
    pass

class ParserException(Exception):
    pass

class RulesParser:
    def __init__(self, lines):
        self.lines = lines

    def getLines(self, noComments=False):
        buffer = list(self.lines)
        if noComments:
            buffer = []
            for line in self.lines:
                if not line.startswith("#") and len(line) > 0:
                    buffer.append(line)

        return buffer

class FileReader(RulesParser):
    def __init__(self, f):

        RulesParser.__init__(self, [])

        if f is None:
            raise Exception("Invalid filename: %s" % f)

        self.fileName = f
        if not os.path.exists(f):
            raise ConfFileException("File does not exist: %s" % f)

        self.parse()

    def parse(self):
        data = open(self.fileName, 'r')
        props = data.readlines()
        for line in props:
            cleanLine = line.strip()
            self.lines.append(cleanLine)
        data.close()

class Parser():
    def __init__(self):
        pass

    def resetChainLines(self):
        self.chainLines = {}

    def addNewChain(self, chainName):
        if chainName not in self.chainLines.keys():
            self.chainLines[chainName] = {'policy': "-", 'rules': [] }

    def parseTableChains(self, table):
        chainNesting = []

        for chainName in self.chainLines.keys():
            stdTargets = table.getStandardTargets(chainName)
            chain = Chain(chainName, table)
            chain.setPolicy(self.chainLines[chainName]['policy'])
            parent = table

            for line in self.chainLines[chainName]['rules']:
                if len(line) > 1:
                    rule = Rule(line)
                    chain.append(rule)
                    target = rule.getTarget()
                    if target is not None and target not in stdTargets:
                        chainNesting.append( (chainName, target)  )   # (master, slave)
                else:
                    log(71, "While parsing %s/%s found an empty line: %s" % (table.getName(), chainName, line))

            #traceback.print_stack()
            # the chain has been parsed. Shall we add it to the table?
            currentChain = table.getChain(chainName)
            if currentChain is not None:
                if currentChain.equals(chain):
                    log(71, "The new chain parsed for %s/%s is identical to the one already in the table, ignored" % (table.getName(), chainName))
                else:
                    table.removeChain(currentChain)
                    table.appendChain(chain)
                    log(71, "The new chain parsed for %s/%s is different from the one already in the table, replaced" % (table.getName(), chainName))
            else:
                table.appendChain(chain)


        for parent, child in chainNesting:
            p = table.getChain(parent)
            c = table.getChain(child)
            if p is not None and c is not None:
                c.setParent(p)
            else:
                log(1, "While parsing table %s found illegal parent/child relationship: %s -> %s" % (table.getName(), child, parent))

class IPTSaveFileParser(Parser):
    def __init__(self, lines, baseRuleset=None):
        Parser.__init__(self)
        self.lines = lines
        self.baseRuleset = baseRuleset
        self.resetChainLines()

    def parse(self):
        conf = self.baseRuleset
        if conf is None:
            conf = Ruleset("File Ruleset")

        currentTable = None
        for line in self.lines:
            if len(line) < 1:
                continue

            if line.find("#") == 0:
                continue

            if line.find("*") == 0:
                if currentTable is not None:
                    raise ParserException("Found new table %s while parsing table %s, aborting" % (tableName, currentTable))
                currentTable = self.startTable(conf, line)

            elif line.find("COMMIT") == 0:
                self.parseTableChains(currentTable)
                currentTable = None
                self.resetChainLines()

            elif line[0:1] == ":":
                policy, chainName = self.parsePolicy(currentTable, line)
                self.addNewChain(chainName)
                self.chainLines[chainName]['policy'] = policy

            elif line[0:2] == "-A":
                self.addRule(currentTable, line)
            else:
                raise Exception("While parsing table %s found illegal line: %s" % (currentTable.getName()))

        return conf

    def addRule(self, table, line):
        parser = Rule(line)
        targetChain = parser.getProperty("-A")
        if targetChain is None:
            raise ParserException("Can't find chain name to append to in line '%s'" % line)

        if not table.canContainChain(targetChain):
            raise ParserException("Chain %s is not valid for table %s" % (targetChain, table.getName()))

        # Don't use the "-A" portion of the rule
        parts = line.split()
        newline = " ".join(parts[2:])

        # Create a new chain or append a new line to an existing one
        self.addNewChain(targetChain)
        self.chainLines[targetChain]['rules'].append(newline)

    def parsePolicy(self, table, line):
        parts = line.split()
        policy = parts[1]
        chainName = parts[0].strip(':')

        return policy, chainName

    def startTable(self, conf, line):
        tableName = line[1:]
        if tableName not in TABLES:
            raise ParserException("Table %s is not a valid iptables table" % tableName)

        table = conf.getTable(tableName)
        if table is None:
            table = Table(tableName)
            conf.add(table)

        return table

class ConfigParser(Parser):
    def __init__(self, rootDir, baseRuleset=None):
        Parser.__init__(self)
        self.rootDir = rootDir
        self.tablePropsFileExt = ".props"
        self.chainFileExt = ".src"
        self.baseRuleset = baseRuleset
        self.resetChainLines()

    def parse(self):
        conf = self.baseRuleset
        if conf is None:
            conf = Ruleset("Config ruleset")

        tableNames = []

        items = os.listdir(self.rootDir)
        for item in items:
            if not os.path.isfile(os.path.join(self.rootDir, item)):
                tableNames.append(item)

        for tableName in tableNames:
            self.resetChainLines()
            if tableName is not None:
                table = self.parseTable(tableName, conf)
                chainPolicies = self.parseTableProps(table)

                tableRoot = os.path.join(self.rootDir, tableName)
                files = [f for f in os.listdir(tableRoot) if f.endswith(".src") and os.path.isfile(os.path.join(tableRoot, f))]

                for chainFile in files:
                    chainName = chainFile[0:-4]
                    contentReader = FileReader(os.path.join(tableRoot, chainFile))
                    lines = contentReader.getLines(noComments=True)

                    self.addNewChain(chainName)
                    self.chainLines[chainName]['rules'] = lines

                    # Add the chain policy
                    policy = "-"
                    if chainName in chainPolicies.keys():
                        policy = chainPolicies[chainName]

                    self.chainLines[chainName]['policy'] = policy

                self.parseTableChains(table)

        return conf

    def parseTable(self, name, ruleset):
        table = Table(name)
        if self.baseRuleset is not None:
            t = self.baseRuleset.getTable(name)
            if t is not None:
                table = t
            else:
                ruleset.add(table)
        else:
            ruleset.add(table)

        return table

    def parseTableProps(self, table):
        filename = os.path.join(self.rootDir, "%s%s" % (table.getName(), self.tablePropsFileExt))
        policies = {}
        try:
            parser = FileReader(filename)
            for line in parser.getLines(noComments=True):
                parts = line.split()
                if len(parts) == 2:
                    policy = parts[1]
                    chainName = parts[0].strip(':')
                    policies[chainName] = policy

        except ConfFileException, e:
            pass
            #print "Can't parse table props config file %s: %s" % (filename, e.message)

        return policies
