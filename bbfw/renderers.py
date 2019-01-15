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




from elements import TABLES, TABLE_CHAINS
import os

class Renderer:
    def __init__(self, config):
        self.tables = config.getTables()
        self.conf = config

    def render(self, table=None, chain=None):
        return "\n".join(self.renderLines(table, chain))
            
    def renderLines(self, table=None, chain=None):
        pass

class RulesetSaver(Renderer):
    def __init__(self, conf, folderName):
        Renderer.__init__(self, conf)
        self.folderName = folderName
        
    def renderLines(self, table=None, chain=None):
        result = []
        os.makedirs(self.folderName)
        
        for name, table in self.tables.items():
            os.makedirs(self.getFolderName(name))
            self.renderTable(table, name)
            result.append( "Table %s saved." % name )
    
        return result
        
    def getFolderName(self, name):
        return os.path.join(self.folderName, name)
        
    def renderTable(self, table, name):
        tableFolderName = self.getFolderName(name)
        
        # Chain policies
        policies = {}
        for chainName in table.getBuiltinChains():
            chain = table.getChain(chainName)
            if chain is not None:
                self.renderChain(tableFolderName, policies, chain)                
        
        self.renderTableProps(table, policies)
        
    def renderChain(self, folderName, policies, chain):
        chainFileName = os.path.join(folderName, "%s.src" % chain.getName())
        file = open(chainFileName, "w")
        for rule in chain.getRules():
            file.write( "%s\n" % rule.toStr(True) )
        
        file.close()

        # append this chain's policy to the table props
        policies[chain.getName()] = chain.getPolicy()

        for child in chain.getChildren():
            self.renderChain(folderName, policies, child)

    def renderTableProps(self, table, policies):
        tableFileName = os.path.join(self.folderName, "%s.props" % table.getName())
        file = open(tableFileName, "w")
        for name, policy in policies.items():
            file.write(":%s %s [0:0]\n" % (name, policy) )

        file.close()

class FileRenderer(Renderer):
    def __init__(self, config):
        Renderer.__init__(self, config)
        
    def renderLines(self, table=None, chain=None):
        buffer = []
        buffer.append( self.getHeader()  )

        tables = self.tables.keys()
        if table is not None:
            tables = [table]
                    
        for name in tables:            
            if self.tables.has_key(name):
                lines = self.renderTable(self.tables[name], chain)
                buffer.extend(lines)
             
        buffer.append( self.getFooter() )
        
        return buffer
    
    def getHeader(self):
        return "############\n\n"
    
    def getFooter(self):
        return "###########\n# End\n###########\n\n"

    def getChainHeader(self, chain):
        return "#####\n# The %s %s chain\n#####" % (chain.getRoot().getName(), chain.name)

    def getChainFooter(self, chain):
        return "#####\n# End of the %s %s chain\n#####" % (chain.getRoot().getName(), chain.name)       

    def getTableHeader(self, table):
        return "########\n# The %s table\n########\n*%s" % (table.name, table.name)

    def getTableFooter(self, table):
        return "\nCOMMIT\n########\n# End of the %s table\n########\n\n" % (table.name)
            
    def renderTable(self, table, chainName=None):
        buffer = []
        body = []

        chains = table.getBuiltinChains()
        if chainName is not None:
            chains = [chainName]

        for name in chains:
            chain = table.getChain(name)
            if chain is not None:
                chainLines = self.renderChain(chain)
                if len(chainLines) > 0:
                    body.extend(chainLines)

        if len(body) > 0:
            if chainName is None:
                buffer.append( self.getTableHeader(table))
                buffer.extend(self.renderPolicies(table))
            buffer.extend(body)

            if chainName is None:
                buffer.append( self.getTableFooter(table))

        return buffer

    def renderPolicies(self, table):
        buffer = []
        for chain in table.chains:
            policyText = ":%s %s [0:0]" % (chain.getName(), chain.getPolicy())
            buffer.append(policyText)

        return buffer

    def renderChain(self, chain):
        buffer = []
        rows = chain.getRules()

        if len(rows) > 0:
            buffer.append(self.getChainHeader(chain))

            for row in rows:
                buffer.append("-A %s %s" % (chain.getName(), row.toStr()))

            buffer.append(self.getChainFooter(chain))

        for child in chain.getChildren():
            lines = self.renderChain(child)
            buffer.extend(lines)

        return buffer

class SummaryRenderer(Renderer):
    def __init__(self, config):
        Renderer.__init__(self, config)

    def renderLines(self, table=None, chain=None):
        pass

    def renderWithSeparators(self, separators, name):
        line = ""
        for last, sep in separators:
            fragment = ""
            for i in range(0, sep + 3):
                fragment = fragment + " "

            line = line + fragment

            if not last:
                line = line + "|"

        sep = ""
        if len(separators) > 0:
            (last, s) = separators[len(separators) - 1]
            if last:
                sep = sep + "+"

        line = line + "%s-->%s" % (sep, name)

        return line

class RulesetSummaryRenderer(SummaryRenderer):
    def __init__(self, config):
        SummaryRenderer.__init__(self, config)

    def renderLines(self, table=None, chain=None):
        buffer = []

        if table is not None:
            buffer = self.renderTableChain(table, chain)
        else:
            buffer = self.renderAll()

        return buffer

    def renderTableChain(self, tableName, chainName=None):
        buffer = []
        separators = []
        index = 0

        if tableName not in self.tables.keys():
            raise "Uknown table %s" % tableName
        else:
            buffer.append( self.renderWithSeparators(separators, tableName) )

            table = self.tables[tableName]

            chains = table.getBuiltinChains()
            if chainName is not None:
                chains = [chainName]

            yindex = 0
            for chainName in chains:
            #while len(chains) > 0:
            #    chainName = chains.pop()
                chain = table.getChain(chainName)
                if chain is not None:
                    yindex += 1
                    last = False
                    if yindex == len(table.chains) :
                        last = True
                    self.showSummaryChain(buffer, chain, separators, last)
            index += 1

        return buffer

    def renderAll(self):
        buffer = []
        separators = []
        index = 0

        for tableName in self.tables.keys():
            buffer.append( self.renderWithSeparators(separators, tableName) )

            table = self.tables[tableName]
            builtin = table.getBuiltinChains()
            yindex = 0
            for chainName in builtin:
                chain = table.getChain(chainName)
                if chain is not None:
                    yindex += 1
                    last = False
                    if yindex == len(table.chains) :
                        last = True
                    self.showSummaryChain(buffer, chain, separators, last)
            index += 1

        return buffer

    def showSummaryChain(self, buffer, chain, separators, last):
        children = chain.getChildren()
        separators.append((last, len(chain.getParent().getName()) / 2))
        buffer.append( self.renderWithSeparators(separators, chain.getName()) )

        index = 0
        for child in children:
            lastOne = False
            if index == len(children) - 1:
                lastOne = True

            self.showSummaryChain(buffer, child, separators, lastOne)
            index += 1

        separators.pop()

class RulesetDiffRenderer(SummaryRenderer):
    def __init__(self, thisRuleset, otherRuleset, table=None, chain=None):
        self.thisRuleset = thisRuleset
        self.otherRuleset = otherRuleset
        self.table = table
        self.chain = chain

    def renderLines(self, table=None, chain=None):
        buffer = []
        separators = []
        order = 0

        msg = "Compare %s (<) and %s (>)" % (self.thisRuleset.getName(), self.otherRuleset.getName())
        if self.table is not None:
            msg = msg + "\n" + "Only compare table %s" % self.table
            if self.chain is not None:
                msg = msg + ". "+ "Only compare chain %s in table %s" % (self.chain, self.table)

        print msg

        tablesToCompare = TABLES
        if self.table is not None:
            tablesToCompare = [self.table]

        for tableName in tablesToCompare:
            this = self.thisRuleset.getTable(tableName)
            that = self.otherRuleset.getTable(tableName)

            if this is None and that is None:
                continue

            if self.chain is not None:
                this = this.getChain(self.chain)
                that = that.getChain(self.chain)

            if this is not None and that is not None:
                result = this.equals(that)
                if not this.equals(that):
                    buffer.append( (order, tableName) )
                    if self.chain is None:
                        buffer.append( (order + 1, self.renderItemDiff(this, that, order ) )  )
                    else:
                        buffer.append( (order + 1, self.renderItemDiff(this.getParent(), that.getParent(), order, self.chain ) )  )

            else:
                buffer.append( (order, tableName) )
                buffer.append( (order + 1, self.renderElemDiff( this, that, order) ) )
        
        return self.renderTabbed(buffer, separators, 0)

    def renderTabbed(self, data, separators, length):
        buffer = []
        indices = {}
        newLength = 0
        
        lastOne = False
        for order, info in data:
            firstOne = False
            if not indices.has_key(order):
                firstOne = True
                indices[order] = 0
        
            siblings = self.countSiblings( data, order )
            if (indices[order] + 1) == siblings:
                lastOne = True
                
            if isinstance(info, basestring):
                newLength = len(info)
                    
                separators.append((lastOne, length / 2))
                buffer.append(  self.renderWithSeparators(separators, info)  )
                separators.pop()

                indices[order] += 1
            else:
                separators.append((lastOne, length / 2))
                buffer.extend( self.renderTabbed(info, separators, newLength)  )
                separators.pop()
        
        return buffer

    def countSiblings(self, data, key):
        result = 0
        for order, data in data:
            if order == key:
                result += 1
        
        return result

    def renderChainRulesDiff(self, thisChain, otherChain, order):
        # Order is relevant in comparing rules
        buffer = []
        index = 0
        done = False

        while not done:
            count = 0
            elem = "<empty>"
            if index < len(thisChain.getRules()):
                elem = thisChain.getRules()[index].toStr()
                count += 1
            left = "  < %s" % elem
    
            elem = "<empty>"
            if index < len(otherChain.getRules()):
                elem =  otherChain.getRules()[index].toStr()
                count += 1
            right = "  > %s" % elem
    
            if count == 0:
                done = True
            elif count == 2 and not thisChain.getRules()[index].toStr() == otherChain.getRules()[index].toStr() or count < 2:
                buffer.append( (order, left )  )
                buffer.append( (order, right )  )

            index = index + 1
            
        return buffer

    def renderChainRulesCompare(self, thisChain, otherChain, order):
        buffer = []
        index = 0
                    
        thisChainRows = thisChain.getRules()
        otherChainRows = otherChain.getRules()

        while index < len(thisChainRows):
            if not thisChainRows[index].equals(otherChainRows[index]):
                buffer.append( (order,  "  < %s" % thisChainRows[index].toStr()  )  )
                buffer.append( (order,  "  > %s" % otherChainRows[index].toStr()  )  )
                
            index = index + 1

        return buffer    

    def renderPolicyDiff(self, thisChain, otherChain, order):
        buffer = []
        lastChain = False
        
        if thisChain.getPolicy() != otherChain.getPolicy():
            buffer.append( (order,  "  < policy is %s" % thisChain.getPolicy()   ) )
            buffer.append( (order,  "  > policy is %s" % otherChain.getPolicy()   ) )

        return buffer

    def renderChainDiff(self, thisChain, otherChain, order):
        buffer = []
        policyBuffer = []
        ruleExistanceBuffer = []
        childrenBuffer = []
        
        chainName = thisChain.getName()
            
        # Check policies
        policyBuffer = self.renderPolicyDiff(thisChain, otherChain, order + 1)
                
        # Check rules
        if len(thisChain.getRules()) != len(otherChain.getRules()):
            ruleExistanceBuffer = self.renderChainRulesDiff( thisChain, otherChain, order + 1  )
        else:
            ruleExistanceBuffer = self.renderChainRulesCompare( thisChain, otherChain, order + 1 )
            
        # Check children
        childrenBuffer = self.renderItemDiff(thisChain, otherChain, order)
        
        if len(policyBuffer) != 0 or len(ruleExistanceBuffer) != 0 or len(childrenBuffer) != 0:
            buffer.append( (order, chainName ) )

            if len(policyBuffer) > 0:
                buffer.append( (order + 1, policyBuffer) )
            
            if len(ruleExistanceBuffer) > 0:
                buffer.append( (order + 1, ruleExistanceBuffer) )

            if len(childrenBuffer) > 0:
                buffer.append( (order + 1, childrenBuffer) )

        return buffer

    def renderItemDiff(self, thisItem, otherItem, order, chain=None):
        buffer = []
        
        children = []
        if chain is not None:
            children = [chain]
        else:
            if thisItem.isChain():
                thisChildren = thisItem.getChildrenNames()
                otherChildren = otherItem.getChildrenNames()

                children = list(set(thisChildren + otherChildren))
            else:
                children = TABLE_CHAINS[thisItem.getName()]

        # Check common children
        for child in children:
            thisChild = thisItem.getRoot().getChain(child)
            otherChild = otherItem.getRoot().getChain(child)

            if thisChild is None and otherChild is None:
                continue

            elif thisChild is not None and otherChild is not None:
                if not thisChild.equals(otherChild):
                    buffer.extend( self.renderChainDiff(thisChild, otherChild, order + 1) )
                
            else:
                buffer.append( (order, thisItem.getName()) )
                buffer.extend( self.renderElemDiff(thisChild, otherChild, order)   )

        return buffer

    def renderElemDiff(self, elem1, elem2, order):
        buffer = []
        elemText = "<not present>"
        if elem1 is not None:
            elemText = "present" 
        buffer.append( (order, "  < %s" % elemText) )
        
        elemText = "<not present>"
        if elem2 is not None:
            elemText = "present" 
        buffer.append( (order, "  > %s" % elemText) )
        
        return buffer
