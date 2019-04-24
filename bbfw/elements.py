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
from matchers import getMatcher, propToBeIgnored

global TABLES, TABLE_CHAINS, TABLE_CHAINS_EX, TABLE_TARGETS

# for a quick intro to netfilter and iptables: https://www.dbsysnet.com/2016/06/a-deep-dive-into-iptables-and-netfilter-architecture-2
# for quick diagrams on netfilter inner flows: https://gist.github.com/nerdalert/a1687ae4da1cc44a437d

# The linux IPTABLES tables
TABLES = ['mangle', 'nat', 'filter', 'raw', 'security']

# The default chain policy
DEFAULT_POLICY = 'ACCEPT'

# Default chains per each table
TABLE_CHAINS = {
    'mangle': ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'],
    'nat': ['PREROUTING', 'OUTPUT', 'POSTROUTING'],
    'filter': ['INPUT', 'FORWARD', 'OUTPUT'],
    'security': ['INPUT', 'FORWARD', 'OUTPUT'],
    'raw': ['PREROUTING', 'OUTPUT']
}

# Can the table contain custom chains?
TABLE_CHAINS_EX = { 'mangle': True, 'nat': True, 'filter': True, 'raw': True, 'security': True }

STANDARD_TARGETS = ['DROP', 'RETURN', 'QUEUE', 'ACCEPT']

EXTENDED_TARGETS = ['CLASSIFY', 'CLUSTERIP', 'CONNMARK', 'DSCP', 'LOG', 'NFLOG', 'NFQUEUE', 'RATEEST', 'SET', 'TCPOPTSTRIP', 'ULOG']

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

    'security': {
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




class Property:
    def __init__(self, name, value=None):
        self.name = name
        self.value = value

    def __str__(self):
        return "Property %s with value %s" % (self.name, self.value)

class Rule:
    def __init__(self, line):
        self.properties = []
        self.line = line.strip()
        self.parseLine(line.strip())

    def getProperties(self, removeTable=False):
        result = []
        for prop in self.properties:
            if removeTable and prop.name == "-A":
                continue

            result.append(prop.name)
            if prop.value is not None:
                result.append(prop.value)

        return result

    def toStr(self, removeTable=False):
        props = self.getProperties(removeTable)
        line = " ".join(props)

        return line.strip()

    def propEquals(self, this, that):
        """
        Compare rule properties taking into account possible aliases
        """

        result = this.name == that.name
        if this.name in RULE_PROP_ALIASES.keys():
            aliases = RULE_PROP_ALIASES[this.name]
            for alias in aliases:
                if that.name == alias:
                    result = True
                    break

        return result

    def equals(self, rule):
        result = True

        thisProps = self.properties
        thatProps = rule.properties

        for prop in thisProps:
            if prop.name == "-A":
                continue

            found = False
            matcher = getMatcher(prop)

            for otherProp in thatProps:
                if matcher(prop, otherProp):
                    found = True
                    break

            if not found and not propToBeIgnored(prop, rule):
                result = False

            if not result:
                break

        return result

    def isParName(self, string):
        return (string[0:1] == '-' or string[0:1] == '!')

    def parseLine(self, line):
        if len(line) > 0:
            parts = line.split()
            index = 0
            argValue = ""
            argName = ""
            done = False

            while not done:
                argName = parts[index]
                argValue = None

                found = False
                while not found:
                    index = index + 1
                    if index == len(parts):
                        break

                    if not self.isParName(parts[index]):
                        if argValue is None:
                            argValue = ""

                        argValue = "%s%s " % (argValue, parts[index])
                    else:
                        found = True

                if argValue is not None:
                    argValue = argValue.strip()

                if self.validateProp(argName, argValue):
                    self.properties.append(Property(argName, argValue))

                if index >= len(parts):
                    done = True

    def validateProp(self, name, value):
        result = True

#        # tcp protocol is a default (and redundant) value
#        if name == "-m" and value == "tcp":
#            result = False

        return result

    def getProperty(self, name):
        value = None
        prop = None

        for i in range(0, len(self.properties)):
            prop = self.properties[i]
            if prop.name == name:
                value = True
                if prop.value is not None:
                    value = prop.value

                break

        return value

    def getTarget(self):
        # -j or -g decide the target. -j has precedence
        target = self.getProperty("-j")
        if target is None:
            target = self.getProperty("-g")

        #return self.getProperty("-j")
        return target

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

    def __len__(self):
        return len(self.rows)

    def getChildrenNames(self):
        childrenNames = []
        #for child in self.getChildren():
        #    childrenNames.append( child.getName() )

        stdTargets = self.getRoot().getStandardTargets(self.getName())

        for rule in self.getRules():
            t = rule.getTarget()
            if t is not None and t not in childrenNames and t not in stdTargets:
                childrenNames.append(t)

        return childrenNames

    def getReferers(self):
        result = []
        root = self.getRoot()
        for chain in root.chains():
            targets = chain.getChildrenNames()
            if self.getName() in targets:
                result.append(chain.getName())

        return result

    def getRuleByTarget(self, target):
        """return the rules in this chain that references a certain target"""
        result = []
        for rule in self.rows:
            if rule.getTarget() == target:
                result.append(rule)

        return result

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
        elif len(self) == 0 and len(self) == len(chain):
            pass
        elif len(self) != len(chain):
            log(71, "Chain %s has different number of rows" % self.name)
            result = False
        else:
            index = 0
            while index < len(self.rows):
                if not self.rows[index].equals(chain.rows[index]):
                    result = False
                    break

                index = index + 1

        # TODO: review this logic to make it recursive
        # it's not needed to compare children. even when loading a new ruleset, the children will be compared anyway when needed
        #if result:
        #    if len(self.getChildren()) != len(chain.getChildren()):
        #        result = False
        #    else:
        #        thisChildren = self.getChildren()
        #        index = 0
        #        done = False
#
#                while index < len(thisChildren):
#                    childDifferences = []
#                    thisChild = thisChildren[index]
#                    otherChild = chain.getRoot().getChain(thisChild.getName())
#                    if not thisChild.equals(otherChild):
#                        result = False
#                        break
#
#                    index = index + 1

        return result

    def isComplete(self):
        return self.complete

    def setComplete(self):
        self.complete = True

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "Chain %s [parent %s]" % (self.name, self.parent)

    def append(self, row):
        if row is not None:
            self.rows.append(row)

    def remove(self, rule):
        result = False
        for row in self.rows:
            if row.equals(rule):
                self.rows.remove(row)
                result = True
                break

        return result

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
        self.policy = policy

    def getRules(self):
        return self.rows

    def purge(self):
        self.rows = []

class Table(Chain):
    def __init__(self, name, *args, **kwargs):
        Chain.__init__(self, name, None, *args, **kwargs)

        # The chains in this table
        self._chains = []

    def __len__(self):
        return len(self._chains)

    def getChainFromRule(self, rule):
        result = None
        for chain in self._chains:
            if chain.hasRule(rule):
                result = chain
                break
            else:
                for child in chain.getChildren():
                    if child.hasRule(rule):
                        result = child
                        break

        return result

    def getChainsTree(self, parentChainName=None ):
        tree = {}
        if parentChainName is None:
            topChains = self.getBuiltinChains()

            # if a chain has no referers, it's at the top level
            for chain in self.chains():
                chainName = chain.getName()
                referers = chain.getReferers()
                if len(referers) == 0:
                    topChains.append(chainName)

            for chainName in topChains:
                tree[chainName] = self.getChainsTree(chainName)

        else:
            for chain in self.chains():
                chainName = chain.getName()
                referers = chain.getReferers()
                if parentChainName in referers:
                    tree[chainName] = self.getChainsTree(chainName)

        return tree

    def __str__(self):
        return "Table %s (%d chains)" % (self.name, len(self._chains))

    def isEmpty(self):
        result = True
        stdChains = TABLE_CHAINS[self.getName()]

        if len(self) != len(stdChains):
            log(21, "Table %s contains more chains than standard"% self.getName())
            result = False
        else:
            for chain in self.chains():
                chainName = chain.getName()
                if chainName not in stdChains:
                    log(21, "Chain %s/%s is not standard, table not empty" % (self.getName(), chainName))
                    result = False
                    break

                if chain.getPolicy() != DEFAULT_POLICY:
                    log(21, "Chain %s/%s has non-default policy, table not empty" % (self.getName(), chainName))
                    result = False
                    break

                if len(chain) != 0:
                    log(21, "Chain %s/%s has rules, table not empty" % (self.getName(), chainName))
                    result = False
                    break

        return result

    def equals(self, otherTable):
        result = True

        if otherTable.getName() != self.name:
            log( 10, "Cannot compare table %s with table %s" % (self.name, otherTable.getName()) )
            result = False
        else:
            if len(self) != len(otherTable):
                log(21, "Tables not the same: number of chains differ")
                result = False
            else:
                for thisChain in self.chains():
                    thatChain = otherTable.getChain(thisChain.getName())
                    if thatChain is None:
                        log(21, "Chain %s/%s not present in table" % (self.getName(), thisChain.getName()))
                        result = False
                        break

                    if not thisChain.equals(thatChain):
                        log(21, "Chain %s/%s differs" % (self.getName(), thisChain.getName()))
                        result = False
                        break

        return result

    def getChain(self, name):
        result = None
        #log(60, "Gettign chain %s from table %s. Chains in table: \n%s" % (name, self.getName(), str(self._chains)))
        for chain in self._chains:
            if chain.getName() == name:
                result = chain

        if result is None:
            log(101, "Can't find chain %s in table %s. Chains in table: \n%s" % (name, self.getName(), str(self._chains)))

        return result

    def setDefaultPolicy(self, chain):
        # Reset the chain's policy if this is a system chain.
        policy = chain.getPolicy()
        if policy == '-' and not self.isUserChain(chain.getName()):
            chain.setPolicy("ACCEPT")

    def appendChain(self, newChain):
        chain = self.getChain(newChain.getName())
        if chain is None:
            self._chains.append(newChain)
        else:
            raise Exception("Chain %s already exists in table %s" % (chain.getName(), self.name))

    def removeChain(self, chainToDelete):
        result = False
        chain = self.getChain(chainToDelete.getName())
        if chain is not None:
            self._chains.remove(chain)
            result = True

        return result

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

    def isUserChain(self, name):
        result = False
        systemChains = TABLE_CHAINS[self.name]
        if name not in systemChains:
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

    def getStandardTargets(self, chainName):
        result = []
        result.extend(STANDARD_TARGETS)
        result.extend(EXTENDED_TARGETS)
        if self.getName() in TABLE_TARGETS.keys() and chainName in TABLE_TARGETS[self.getName()].keys():
            result.extend(TABLE_TARGETS[self.getName()][chainName])

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
        for c in self._chains:
            parent = c.getParent()
            if parent is not None and parent.getName() == chain.getName():
                result.append(c)

        return result

    def getBuiltinChains(self):
        result = []
        if self.name in TABLE_CHAINS:
            result = TABLE_CHAINS[self.name]

        return result

    def getChains(self):
        return self._chains

    def chains(self, chainName=None):
        chainNames = [chainName]
        if chainName is None:
            for c in self._chains:
                chainNames.append(c.getName())

        for c in chainNames:
            chain = self.getChain(c)
            if chain is not None:
                yield chain

    def __iter__(self):
        self._chainnames = []
        for c in self._chains:
            self._chainnames.append(c.getName())

        self._chainNamesCtr = 0

        return self

    def __next__(self):
        result = self._chainnames[self.chainNamesCtr]
        if self.chainNamesCtr == len(self._chainnames):
            raise StopIteration
        else:
            self.chainNamesCtr = self.chainNamesCtr + 1

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
        thisTables = len(self.getTables().keys())
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
                    log(61, "Comparing table %s with table %s" % (table.getName(), otherTable.getName()))
                    if not table.equals(otherTable):
                        result = False

        return result

    def validate(self):
        """Performs checks on the tables to ensure integrity.
        Return a list of problems found, with an index (Critical, Warning, info) of their severity
        """

        result = { "Critical": [], "Warning": [], "Info": []}
        tables = self.getTables()

        # Check targets in each chain and ensure they are self-contained
        for table in tables:
            for chain in table.chains():
                targets = chain.getChildrenNames()
                for target in targets:
                    c = table.getChain(target)
                    if c is None:
                        result['Critical'].append("Chain %s/%s refers to non-existant target %s" % table.getName(), chain.getName(), target)

        return result

