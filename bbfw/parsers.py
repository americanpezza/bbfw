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




import os

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
                if line.find("#") != 0:
                    buffer.append(line)
                    
        return buffer

class FileReader(RulesParser):
    def __init__(self, file):
        
        RulesParser.__init__(self, [])
        
        self.fileName = file
        if not os.path.exists(file):
            raise ConfFileException("File does not exist: %s" % file)
        
        self.parse()
        
    def parse(self):
        data = open(self.fileName,'r')
        props = data.readlines()
        for line in props:
            cleanLine = line.strip()
            self.lines.append(cleanLine)
        data.close()

class Parser():
    def __init__(self):
        self.chainBuffer = {}

    def getBufferedChain(self, name):
        chain = None
        if self.chainBuffer.has_key(name):
            chain = self.chainBuffer(name)

        return chain

    def parseTableChains(self, table):
        for chainName in table.getBuiltinChains():
            self.parseTableChain(chainName, table)
            self.chainBuffer = {}

    def parseTableChain(self, chainName, table, parentChain=None):
        currentChain = table.getChain(chainName)
        if currentChain is None:
             chain = Chain(chainName, table)
             table.appendChain( chain )

        try:
            chain = table.getChain(chainName)
            parent = table
            if parentChain is not None:
                parent = parentChain

            chain.setParent(parent)

            parser = self.getParser(table, chain.getName())
            if parser is not None:
                self.readChainLines(parser, chain, table, parentChain)

            chain.setComplete()

        except ConfFileException, e:
            pass

    def getParser(self, table, chainName):
        pass
        
    def readChainLines(self, parser, chain, table, parentChain):
        for line in parser.getLines(noComments=True):
            if len(line) > 1:
                rule = Rule(line)
                target = rule.getTarget()
                
                if not table.isTargetValid( target, chain.getName()  ):
                    log( 20, "Rule '%s' in chain %s table %s has invalid target, ignored" % (line, chain.getName(), table.getName()) )
                else:
                    chain.append(rule)

                if table.isUserTarget(target, chain):
                    childChain = table.getChain(target)
                    if childChain is None or not childChain.isComplete():
                        self.parseTableChain(target, table, parentChain=chain)

class IPTSaveFileParser(Parser):
    def __init__(self, lines):
        Parser.__init__(self)
        self.lines = lines
        self.chainLines = {}
        
    def parse(self):
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
                self.chainLines = {}
                
            elif line.find(":") == 0:
                self.addPolicy(currentTable, line)
                
            else:
                self.addRule(currentTable, line)

        return conf
        
    def addRule(self, table, line):
        parser = Rule(line)
        targetChain = parser.getProperty("-A")
        if targetChain is None:
            raise ParserException("Can't find chain name to append to in line '%s'" % line)
            
        if not table.canContainChain(targetChain):
            raise ParserException("Chain %s is not valid for table %s" % (targetChain, table.getName()))
            
        parts = line.split()
        newline = " ".join(parts[2:])
        if self.chainLines.has_key(targetChain):
            self.chainLines[targetChain].append(newline)
        else:
            self.chainLines[targetChain] = [newline]

    def addPolicy(self, table, line):
        parts = line.split()
        policy = parts[1]
        chainName = parts[0].strip(':')
        chain = Chain(chainName, table)
        chain.setPolicy(policy)
        table.appendChain(chain)

    def startTable(self, conf, line):
        tableName = line[1:]
        if tableName not in TABLES:
            raise ParserException("Table %s is not a valid iptables table" % tableName)
        
        table = conf.getTable(tableName)
        if table is None:
            table = Table(tableName)
            conf.add(table)

        return table

    def getParser(self, table, chainName):
        parser = None
        if self.chainLines.has_key(chainName):
            parser = RulesParser(self.chainLines[chainName])

        return parser

class ConfigParser(Parser):
    def __init__(self, rootDir):
        Parser.__init__(self)
        self.rootDir = rootDir
        self.tablePropsFileExt = ".props"
        self.chainFileExt = ".src"

    def parse(self):
        conf = Ruleset("Config Ruleset")
        for name in TABLES:
            table = self.parseTable(name)
            if len(table.chains) > 0:
                conf.add(table)

        return conf
        
    def parseTable(self, name):
        table = Table(name)
        self.parseTableChains(table)
        self.parseTableProps(table)
        
        return table

    def parseTableProps(self, table):
        filename = os.path.join(self.rootDir, "%s%s" % (table.getName(), self.tablePropsFileExt))
        try:
            parser = FileReader(filename)
            for line in parser.getLines(noComments=True):
                parts = line.split()
                policy = parts[1]
                chainName = parts[0].strip(':')
 
                chain = table.getChain(chainName)
                if chain is not None:
                    chain.setPolicy(policy)
                                    
        except ConfFileException, e:
            pass
            #print "Can't parse table props config file %s: %s" % (filename, e.message)

    def parseTableChains(self, table):
        folderName = os.path.join(self.rootDir, table.getName())
        if os.path.isdir(folderName):
            Parser.parseTableChains(self, table)
        else:
            log( 20, "No chain folder for table %s, table will be empty" % table.getName()  )

    def getParser(self, table, chainName):
        tableFolderName = os.path.join(self.rootDir, table.getName())
        fileName = os.path.join(tableFolderName, "%s%s" % (chainName, self.chainFileExt))

        return FileReader(fileName)
