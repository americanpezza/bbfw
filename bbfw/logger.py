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




import sys

# Default loglevel
LOGLEVEL = 20
LOGLEVELS = [
              ('CRITICAL', 10),
              ('ERROR', 20),
              ('INFO', 40),
              ('WARNING', 70),
              ('DEBUG', 100),
              ('LOWLEVEL', 200)
            ]

def setLogLevel(l):
    global LOGLEVEL
    LOGLEVEL = l

def getLogLevels():
    global LOGLEVELS

    return LOGLEVELS

def getPrefix(level):
    prefix = "DEF"
    for l in LOGLEVELS:
        (name, lv) = l

        if level <= lv:
            prefix = name
            break

    return prefix

def log(level, message):

    if level <= LOGLEVEL:
        sys.stderr.write( "%s: %s\n" % (getPrefix(level), message))
