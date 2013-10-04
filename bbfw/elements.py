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




from logger import log

global TABLES, TABLE_CHAINS, TABLE_CHAINS_EX, TABLE_TARGETS

# The linux IPTABLES tables
TABLES = ['mangle', 'nat', 'filter', 'raw']

# Default chains per each table
TABLE_CHAINS = {
    'mangle': ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'],
    'nat': ['PREROUTING', 'OUTPUT', 'POSTROUTING'],
    'filter': ['INPUT', 'FORWARD', 'OUTPUT'],
    'raw': ['PREROUTING', 'OUTPUT']
}

# Can the table contain custom chains?
TABLE_CHAINS_EX = { 'mangle': False, 'nat': False, 'filter': True, 'raw': False }

STANDARD_TARGETS = ['DROP', 'RETURN', 'QUEUE', 'ACCEPT']

EXTENDED_TARGETS = ['CLASSIFY', 'CLUSTERIP', 'CONNMARK', 'DSCP', 'LOG', 'NFLOG', 'NFQUEUE', 'RATEEST',
            'SET', 'TCPOPTSTRIP', 'ULOG']
            
TABLE_TARGETS = {
    'mangle': { 
        'PREROUTING' : ['SECMARK', 'CONNSECMARK', 'ECN', 'MARK', 'MIRROR', 'TCPMSS', 'TOS', 'TPROXY', 'TTL'],
        'INPUT' : ['SECMARK', 'CONNSECMARK', 'ECN', 'MARK', 'MIRROR', 'TCPMSS', 'TOS', 'TPROXY', 'TTL'],
        'FORWARD' : ['SECMARK', 'CONNSECMARK', 'ECN', 'MARK', 'MIRROR', 'TCPMSS', 'TOS', 'TPROXY', 'TTL'],
        'OUTPUT' : ['SECMARK', 'CONNSECMARK', 'ECN', 'MARK', 'MIRROR', 'TCPMSS', 'TOS', 'TPROXY', 'TTL'],
        'POSTROUTING' : ['SECMARK', 'CONNSECMARK', 'ECN', 'MARK', 'MIRROR', 'TCPMSS', 'TOS', 'TPROXY', 'TTL']
                
    },
    
    'nat': {
        'PREROUTING' : ['DNAT', 'NETMAP', 'REDIRECT', 'SAME'],
        'OUTPUT' : ['DNAT', 'NETMAP', 'REDIRECT', 'SAME'],
        'POSTROUTING' : ['MASQUERADE', 'NETMAP', 'SNAT', 'SAME']
    },
    
    'filter': {
        'INPUT' : ['REJECT'], 
        'FORWARD': ['REJECT'], 
        'OUTPUT': ['REJECT']    
    },
    
    'raw':{
        'PREROUTING' : ['NOTRACK', 'TRACE'],
        'OUTPUT' : ['NOTRACK', 'TRACE'],
    }
}   

class TablePropsException(Exception):
    pass

class TableChainException(Exception):
    pass







class Rule:
    def __init__(self, line):
        self.properties = []
        self.line = line.strip()
        self.parseLine(line.strip())
    
    def getProperties(self, removeTable=False):
        result = self.properties[:]
        if removeTable:
            if self.getProperty("-A") is not None:
                result.pop(0)
                result.pop(0)

        return result
    
    def toStr(self, removeTable=False):
        props = self.getProperties(removeTable)        
        line = " ".join(props)
        
        return line.strip()
    
    def equals(self, rule, ignoreChainAction=True):
        result = True

        otherProperties = rule.getProperties()
        thisProperties = self.getProperties()
        
        if self.getProperty("-A") is not None:
            thisProperties.pop(0)
            thisProperties.pop(0)
            
        if rule.getProperty("-A") is not None:
            otherProperties.pop(0)
            otherProperties.pop(0)
        
        if len(otherProperties) == len(thisProperties):     
            for i in range(0, len(self.properties)):
                if thisProperties[i] != otherProperties[i]:
                    result = False
                    break
        else:
            result = False

        return result
    
    def isParName(self, string):
        return string[0:1] == '-'
        
    def parseLine(self, line):
        if len(line) > 0:
            parts = line.split()
            index = 0
            argValue = ""
            argName = ""
            done = False
            
            while not done:
                if index == len(parts) - 1:
                    done = True
                    
                if self.isParName( parts[index] ):
                    if  argName != "":
                        self.properties.append(argName)
                    if argValue != "":
                        self.properties.append(argValue)
                        
                    argName = parts[index]
                    argValue = ""
                else:
                    if argValue == "":
                        argValue = parts[index]
                    else:
                        argValue = "%s %s" % (argValue, parts[index])
                
                index = index + 1
            
            # Use the last parameter
            if  argName != "":
                self.properties.append(argName)
            if argValue != "":
                self.properties.append(argValue)
            
    def getProperty(self, name):
        value = None
        prop = None
        
        for i in range(0, len(self.properties)):
            prop = self.properties[i]
            if prop == name:
                value = True
                if (1+i) < len(self.properties) and self.properties[1+i][0:1] != "-":
                    value = self.properties[1+i]
                
                break

        return value

    def getTarget(self):
        return self.getProperty("-j")

class Chain:
    def __init__(self, name, parent, rows=None, policy="-"):
        self.rows = []
        self.name = name
        self.builtin = False
        self.policy = policy
        self.complete = False
        
        self.setParent(parent)      
        if rows is not None:
            for row in rows:
                self.rows.append(row)
    
    def getChildrenNames(self):
        childrenNames = []
        for child in self.getChildren():
            childrenNames.append( child.getName())
            
        return childrenNames
    
    def hasRule(self, targetRule):
        result = False
        for rule in self.rows:
            if rule.equals(targetRule):
                result = True
                break
        
        return result
    
    def equals(self, chain):
        result = True

        if self.getPolicy() != chain.getPolicy():           
            result = False
        elif len(self.getRules()) != len(chain.getRules()):
            result = False                
        else:
            index = 0            
            while index < len(self.rows):
                if not self.rows[index].equals(chain.rows[index]):
                    result = False
                    break
                    
                index = index + 1

        if result:
            if len(self.getChildren()) != len(chain.getChildren()):
                result = False
            else:
                thisChildren = self.getChildren()
                index = 0
                done = False
            
                while index < len(thisChildren):
                    childDifferences = []
                    thisChild = thisChildren[index]
                    otherChild = chain.getRoot().getChain(thisChild.getName())
                    if not thisChild.equals(otherChild):
                        result = False
                        break
                                            
                    index = index + 1
        
        return result        
   
    def isComplete(self):
        return self.complete
    
    def setComplete(self):
        self.complete = True
    
    def __str__(self):
        return "Chain %s [parent %s]" % (self.name, self.parent)
    
    def append(self, row):
        if row is not None:
            self.rows.append(row)
    
    def setParent(self, parent):
        self.parent = parent
        if parent is not None:
            if isinstance(parent, Table):
                self.builtin = TABLE_CHAINS_EX[parent.getName()]    
            
    def isChain(self):
        return not self.parent is None

    # The root chain (=one of the builtin chains in the table)
    def getRootChain(self, child=None):
        if self.parent is not None:
            return self.parent.getRootChain(child=self)
        else:
            return child

    def getRoot(self):
        if self.parent is not None:
            return self.parent.getRoot()
        else:
            return self

    def getChildren(self):  
        parentTable = self.getRoot()
        return parentTable.getChildren(self)
    
    def getParent(self):
        return self.parent
    
    def getName(self):
        return self.name
    
    def getPolicy(self):
        return self.policy
        
    def setPolicy(self, policy):
        if policy != "":
            self.policy = policy
            
    def getRules(self):
        return self.rows

class Table(Chain):
    def __init__(self, name, *args, **kwargs):
        Chain.__init__(self, name, None, *args, **kwargs)
        
        # The chains in this table
        self.chains = []

    def getChainFromRule(self, rule):
        result = None
        for chain in self.chains:
            if chain.hasRule(rule):
                result = chain
                break
            else:
                for child in chain.getChildren():
                    if child.hasRule(rule):
                        result = child
                        break
                        
        return result

    def __str__(self):
        return "Table %s" % self.name

    def equals(self, otherTable):
        result = True
        
        if otherTable.getName() != self.name:
            log( 20, "Cannot compare table %s with table %s" % (self.name, otherTable.getName()) )
            result = False
        else:
            thisTableChains = []
            for chainName in self.getBuiltinChains():
                thisChain = self.getChain(chainName)
                otherChain = otherTable.getChain(chainName)
                
                if otherChain is None:
                    result = False
                
                elif thisChain is None:
                    result = False
                
                else:
                    if not thisChain.equals(otherChain):
                        result = False

        return result
       
    def getChain(self, name):
        result = None
        for chain in self.chains:
            if chain.getName() == name:
                result = chain
            
        return result

    def appendChain(self, newChain):
        chain = self.getChain(newChain.getName())
        if chain is None:
            self.chains.append(newChain)

    def hasChain(self, chainName):
        result = True
        c = self.getChain(chainName)
        if c is None:
            result = False

        return result

    def canContainCustomChains(self):
        result = False
        if self.name in TABLE_CHAINS_EX and TABLE_CHAINS_EX[self.name]:
            result = True
        
        return result
        
    def canContainChain(self, chainName):
        result = False
        # If the chain is a builtin chain *or* the table is extensible
        if self.name in TABLES and (chainName in TABLE_CHAINS[self.name] or TABLE_CHAINS_EX[self.name]):
            result = True
            
        return result
    
    def isUserTarget(self, target, chain):
        result = False
        valid = self.isTargetValid(target, chain.getName())
        if valid and self.name == 'filter':
            # If we're not a standard, extended or per table target, we must be a user defined chain
            tableChainTargets = []
            rootChain = chain.getRootChain()
            
            if TABLE_TARGETS[self.name].has_key(rootChain.getName()):
                tableChainTargets = TABLE_TARGETS[self.name][rootChain.getName()]
            
            if target not in STANDARD_TARGETS and target not in EXTENDED_TARGETS and target not in tableChainTargets:
                result = True
                
        return result           
    
    def isTargetValid(self, target, chain):
        result = False
        tableChainTargets = []
        
        if self.name in TABLE_TARGETS.keys() and chain in TABLE_TARGETS[self.name].keys():
            tableChainTargets = TABLE_TARGETS[self.name][chain]
        
        if target in STANDARD_TARGETS or target in EXTENDED_TARGETS or target in tableChainTargets:
            result = True

        if target is not None and not result and self.name == "filter":
            result = True

        return result

    def getChildren(self, chain):
        result = []
        for c in self.chains:
            parent = c.getParent()
            if parent is not None and parent.getName() == chain.getName():
                result.append(c)
        
        return result

    def getBuiltinChains(self):
        result = []
        if self.name in TABLE_CHAINS:
            result = TABLE_CHAINS[self.name]
            
        return result
        
class Ruleset:
    def __init__(self, name):
        self.tables = {}
        self.name = name
        
    def getName(self):
        return self.name
        
    def add(self, table):
        if table is not None:
            self.tables[table.getName()] = table
    
    def getTable(self, name):
        result = None
        if self.tables.has_key(name):
            result = self.tables[name]
        
        return result
            
    def getTables(self):
        return self.tables

    def getChainFromRule(self, rule):
        result = None
        for name, table in self.tables.items():
            chain = table.getChainFromRule(rule)
            if chain is not None:
                result = chain
                
        return result

    def equals(self, otherConfig):
        result = True
        thisTables = len(self.tables.keys())
        otherTables = len(otherConfig.tables.keys())
        
        if thisTables != otherTables:
            result = False
        else:
            for tableName in self.getTables().keys():
                table = self.tables[tableName]
                otherTable = otherConfig.getTable(tableName)
            
                if otherTable is None:
                    result = False
                    break
                else:
                    if not table.equals(otherTable):
                        result = False
        
        return result