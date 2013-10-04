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
from parsers import ConfigParser, FileReader, IPTSaveFileParser
from renderers import RulesetSummaryRenderer, FileRenderer, RulesetDiffRenderer, RulesetSaver
from elements import Rule
from logger import log
from util import loadRuleset



DEFAULT_CONF="tables"
DEFAULT_FILE="iptables.src"

class CommandLineInterpreter:
    def __init__(self):
        self.commands = ['show', 'showconfig', 'compare', 'load', 'export']
        
    def run(self, command, conf, fileconf, brief, *args, **kwargs):
        if command in self.commands:
            try:
                commandFunc = getattr(self, command)
                commandFunc( conf, fileconf, brief, *args, **kwargs)
            except Exception, e:
                if brief:
                    print "An error occurred. Use --verbose for more details."
                else:
                    traceback.print_exc()
        else:
            print "Unknown command '%s'. Use -h for help" % command
             
    def getFirstRuleset(self, conf, fileConf, brief, *args, **kwargs):
        configRuleset = None

        if conf is not None:
            configRuleset = self.getRuleset(conf)
        elif fileConf is not None:
            configRuleset = self.getFileRuleset(fileConf)
        else:
            configRuleset = self.getRuleset(DEFAULT_CONF)

        return configRuleset
        
    def getCurrentRuleset(self):
        iptp = subprocess.Popen(['iptables-save'],stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        
        (out, err) = iptp.communicate()
        lines = out.split("\n")
        parser = IPTSaveFileParser(lines)
        config = parser.parse()
        config.name = "Currently loaded ruleset"

        return config
        
    def getRuleset(self, confFolder):
        parser = ConfigParser(confFolder)
        return parser.parse()

    def getFileRuleset(self, fileName):
        fileReader = FileReader(fileName)
        fileConfigParser = IPTSaveFileParser(fileReader.getLines(noComments=True))
        return fileConfigParser.parse()
             
    def printRuleset(self, ruleset, brief, table=None, chain=None):
        renderer = None
        if brief:
            renderer = RulesetSummaryRenderer(ruleset)
        else:
            renderer = FileRenderer(ruleset)

        print renderer.render(table, chain)

    def export(self, conf, *args, **kwargs):
        """
        Export the current netfilter configuration into a configuration folder.
        Use this to create your first configuration form a running iptables set.
        Defaults to exporting into the default folder ('%s' in the current directory)
        """ % DEFAULT_CONF
        
        confName = conf
        if confName is None:
            confName = DEFAULT_CONF
            
        currentRuleset = self.getCurrentRuleset()
        renderer = RulesetSaver(currentRuleset, confName)
        renderer.render()

    def load(self, conf, fileConf, brief, *args, **kwargs):
        """
        Load a configuration from disk into netfilter, enabling it.
        Defaults to using the configuration found in the default folder 
        ('%s' in the current directory)
        """  % DEFAULT_CONF
    
        configRuleset = self.getFirstRuleset(conf, fileConf, brief, *args, **kwargs)
        currentRuleset = self.getCurrentRuleset()
        if configRuleset.equals(currentRuleset):
            print "\nConfiguration and current rules are identical, nothing to do.\n"
        else:
            renderer = RulesetDiffRenderer(currentRuleset, configRuleset)
            print renderer.render()
            
            done = False
            answer = "n"
            while not done:
                answer = raw_input("\n\nThe configuration will be loaded, applying the above changes. Are you sure? (Y/n)")
                if not (answer.find("Y") == 0 or answer.find("n") == 0):
                    print "\nPlease answer 'Y' or 'n'"
                else:
                    done = True
                    
            if answer.find("Y") == 0:
                loadRuleset(configRuleset)
            else:
                print "\nNo changes applied.\n"

    def show(self, conf, fileConf, brief, force, table, chain, *args, **kwargs):
        """
        Prints out the current netfilter configuration. 
        Use -v for a detailed print.
        """
        self.printRuleset(self.getCurrentRuleset(), brief, table, chain)
            
    def showconfig(self, conf, fileConf, brief, force, table, chain, *args, **kwargs):
        """
        Prints out the configuration loaded from the specified folder or file.
        Defaults to using the configuration found in the default folder 
        ('%s' in the current directory)         
        Use -v for a detailed print.
        """ % DEFAULT_CONF
        
        self.printRuleset(self.getFirstRuleset( conf, fileConf, brief, *args, **kwargs ), brief, table, chain)

    def compare(self, conf, fileConf, brief, *args, **kwargs):
        """
        Compare two netfilter configurations.
        Defaults to comparing the current netfilter configuration with the
        folder configuration found in the default folder '%s'.
        Use -c or -o to compare with a different configuration folder or file.
        Use -v for a detailed print.
        """ % DEFAULT_FILE    

        rightRuleset = self.getFirstRuleset( conf, fileConf, brief, *args, **kwargs )

        # Don't use the current ruleset if both conf and file are specified        
        if conf is not None and fileConf is not None:    
            leftRuleset = self.getRuleset(conf)
        else:
            leftRuleset = self.getCurrentRuleset()
                            
        differences = []
        if leftRuleset.equals(rightRuleset):
            print "The rulesets are identical"
        else:
            renderer = RulesetDiffRenderer(leftRuleset, rightRuleset)
            print renderer.render()

            