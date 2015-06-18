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




import os, subprocess, traceback, sys
from bbfw.parsers import ConfigParser, FileReader, IPTSaveFileParser
from bbfw.renderers import RulesetSummaryRenderer, FileRenderer, RulesetDiffRenderer, RulesetSaver
from bbfw.elements import Rule
from bbfw.logger import log
from bbfw.util import loadRuleset
from bbfw.elements import TABLES
from bbfw.util import purgeTable, getCurrentRuleset


DEFAULT_CONF="tables"
DEFAULT_FILE="iptables.src"





def purge(args):
    """
    Purge a chain and all its children
    """

    currentRuleset = _getCurrentRuleset()

    chainmsg = "All chains"
    if args.chain is not None:
        chainmsg = "Chain %s" % args.chain

    tablemsg = "from all tables"
    if args.table is not None:
        tablemsg = "from table %s" % args.table

    msg = "\n\n%s %s will be deleted. You cannot undo this operation. Do you want to continue (Y/n)?" % (chainmsg, tablemsg)

    proceed = True
    if not args.force:
        proceed = _confirm( msg )

    if proceed:
        purgeTable(args.table, args.chain, args.recursive, args.reset)

def export(args):
    """
    Export the current netfilter configuration into a configuration folder.
    Use this to create your first configuration form a running iptables set.
    Defaults to exporting into the default folder ('%s' in the current directory)
    """ % DEFAULT_CONF
    
    confName = args.directory
    if confName is None:
        confName = DEFAULT_CONF
        
    currentRuleset = _getCurrentRuleset()
    renderer = RulesetSaver(currentRuleset, confName)
    renderer.render()

def load(args):
    """
    Load a configuration from disk into netfilter, enabling it.
    Defaults to using the configuration found in the default folder 
    ('%s' in the current directory)
    """  % DEFAULT_CONF

    configRuleset = _getFirstRuleset(args.directory, args.file)
    currentRuleset = _getCurrentRuleset()
    if configRuleset.equals(currentRuleset):
        print "\nConfiguration and current rules are identical, nothing to do.\n"
    else:
        renderer = RulesetDiffRenderer(currentRuleset, configRuleset)

        if args.verbose:
            print renderer.render()

        proceed = True
        if not args.force:
            proceed = _confirm( "\n\nThe configuration will be loaded, applying the above changes. Are you sure? (Y/n)" )

        if proceed:
            loadRuleset(configRuleset)
        else:
            print "\nNo changes applied.\n"

def show(args):
    """
    Prints out the current netfilter configuration. 
    Use -v for a detailed print.
    """

    ruleset = None
    if args.directory is None and args.file is None:
        ruleset = _getCurrentRuleset()
    else:
        if args.directory is not None:
            ruleset = _getRuleset(args.directory)
        else:
            ruleset = _getFileRuleset(args.file)

    _printRuleset(ruleset, args.verbose, args.table, args.chain)
        
def compare(args):
    """
    Compare two netfilter configurations.
    Defaults to comparing the current netfilter configuration with the
    folder configuration found in the default folder '%s'.
    Use -c or -o to compare with a different configuration folder or file.
    Use -v for a detailed print.
    """ % DEFAULT_FILE    

    rightRuleset = None
    leftRulesset = None

    if args.directory is None or args.file is None:
        leftRuleset = _getCurrentRuleset()
        if args.directory is None:
            rightRuleset = _getFileRuleset(args.file)
        else:
            rightRuleset = _getRuleset(args.directory)

    else:
        rightRuleset = _getFileRuleset(args.file)
        leftRuleset = _getRuleset(args.directory)

    if leftRuleset.equals(rightRuleset):
        print "The rulesets are identical"
    else:
        renderer = RulesetDiffRenderer(leftRuleset, rightRuleset, args.table, args.chain)
        print renderer.render()

def _getFirstRuleset(conf, fileConf):
    configRuleset = None

    if conf is not None:
        configRuleset = _getRuleset(conf)
    elif fileConf is not None:
        configRuleset = _getFileRuleset(fileConf)
    else:
        configRuleset = _getRuleset(DEFAULT_CONF)

    return configRuleset
    
def _getCurrentRuleset():
    return getCurrentRuleset()

def _getRuleset(confFolder):
    parser = ConfigParser(confFolder)
    config = parser.parse()
    config.name = "Ruleset loaded from directory %s" % confFolder

    return config

def _getFileRuleset(fileName):
    fileReader = FileReader(fileName)
    fileConfigParser = IPTSaveFileParser(fileReader.getLines(noComments=True))
    config = fileConfigParser.parse()
    config.name = "Ruleset loaded from file %s" % fileName

    return config
         
def _printRuleset(ruleset, detailed, table=None, chain=None):
    renderer = None
    if not detailed:
        renderer = RulesetSummaryRenderer(ruleset)
    else:
        renderer = FileRenderer(ruleset)

    print renderer.render(table, chain)

def _confirm(msg):
    result = False

    done = False
    answer = "n"
    while not done:
        answer = raw_input(msg)
        if not (answer.find("Y") == 0 or answer.find("n") == 0):
            print "\nPlease answer 'Y' or 'n'"
        else:
            done = True
                
    if answer.find("Y") == 0:
        result = True

    return result
