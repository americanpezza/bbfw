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



global matchers
matchers = {}

icmpcommontypes = { "echo-reply": 0,
                      "destination-unreachable": 3,
                      "source-quench": 4,
                      "redirect": 5,
                      "echo-request": 8,
                      "time-exceeded": 10,
                     "parameter-problem": 11
}


def getMatcher(prop):
    global matchers
    result = matchers["__default__"]
    if matchers.has_key(prop.name):
        result = matchers[prop.name]

    return result

def registerMatcher(name, matcher):
    global matchers
    if not matchers.has_key(name):
        matchers[name] = matcher

def defaultMatcher(this, that):
    result = False
    if this.name == that.name and this.value == that.value:
        result = True

    return result

registerMatcher("__default__", defaultMatcher)

def setmarkMatcher(this, that):
    def validate(prop):
        result = {'name': "--set-xmark", "value": prop.value }
        if prop.name == "--set-mark":
            result['name'] = "--set-xmark"
            result['value'] = "%s/0xffffffff" % prop.value

        return result

    result = False
    validatedThis = validate(this)
    validatedThat = validate(that)

    if validatedThis['name'] == validatedThat['name'] and validatedThis['value'] == validatedThat['value']:
        result = True

    return result

registerMatcher("--set-mark", setmarkMatcher)
registerMatcher("--set-xmark", setmarkMatcher)

def ipaddress_normalizer(value):
    result = value
    if result is not None and result.find("/") == -1:
        result = "%s/32" % result

    return result

def ipprotocol_normalizer(value):
    result = value
    if result is not None and result.find("/") == -1:
        result = "%s/32" % result

    return result

def ippropertyMatcher(this, that, validNames):
    """match 2 properties containing IP addresses"""

    result = False

    thisvalue = ipaddress_normalizer(this.value)
    thatvalue = ipaddress_normalizer(that.value)

    if this.name in validNames and that.name in validNames and thisvalue == thatvalue:
        result = True

    return result

def dstpropertyMatcher(this, that):
    return ippropertyMatcher(this, that, ['-d', '--dst', '--destination'])

registerMatcher("-d", dstpropertyMatcher)
registerMatcher("--destination", dstpropertyMatcher)
registerMatcher("--dst", dstpropertyMatcher)

def srcpropertyMatcher(this, that):
    return ippropertyMatcher(this, that, ['-s', '--src', '--source'])

registerMatcher("-s", srcpropertyMatcher)
registerMatcher("--src", srcpropertyMatcher)
registerMatcher("--source", srcpropertyMatcher)

def ipprotocolMatcher(this, that):
    """match 2 properties containing a protocol"""

    result = False
    thisvalue = ipprotocol_normalizer(this.value)
    thatvalue = ipprotocol_normalizer(that.value)

    if this.name == that.name and thisvalue == thatvalue:
        result = True

    return result

registerMatcher("-p", ipprotocolMatcher)
registerMatcher("--protocol", ipprotocolMatcher)

def stringValidator(value):
    result = value
    if value is not None and not value.startswith('"'):
        result = '"%s"' % value

    return result

def commentMatcher(this, that):
    result = False
    thisValue = stringValidator(this.value)
    thatValue = stringValidator(that.value)

    if thisValue == thatValue:
        result = True

    return result

registerMatcher("--comment", commentMatcher)

def recentDefaults(this, that):
    return True

registerMatcher("--rsource", recentDefaults)

def optionalModuleSpecMatcher(this, that):
    protocols = ['tcp', 'udp', 'icmp']
    result = False
    value = str(this.value)
    value2 = str(that.value)
    if value in protocols or value2 in protocols:
        result = True
    else:
        if value == value2:
            result = True

    return result

registerMatcher("--module", optionalModuleSpecMatcher)
registerMatcher("-m", optionalModuleSpecMatcher)

def tcpflagsMatchGroup(groupSX, groupDX):
    result = True
    for flag in groupSX:
        if flag not in groupDX:
            result = False
            break

    return result

def tcpflagsGroupCompare(groupSX, groupDX):
    result = False
    if tcpflagsMatchGroup(groupSX, groupDX) and tcpflagsMatchGroup(groupDX, groupSX):
        result = True

    return result

def tcpflagsGroups(this):
    result = None
    parts = this.value.split(" ")
    if len(parts) == 2:
        flagsSX = parts[0].split(",")
        flagsDX = parts[1].split(",")
        result = (flagsSX, flagsDX)

    return result

def tcpflagsMatcher(this, that):
    result = False
    thisGroups = None
    thatGroups = None

    if this.value is not None and that.value is not None:
        thisGroups = tcpflagsGroups(this)
        thatGroups = tcpflagsGroups(that)

    if thisGroups is not None and thatGroups is not None:
        leftCompare = tcpflagsGroupCompare(thisGroups[0], thatGroups[0])
        rightCompare = tcpflagsGroupCompare(thisGroups[1], thatGroups[1])

        result = (leftCompare and rightCompare)

    return result

registerMatcher("--tcp-flags", tcpflagsMatcher )

def getICMPValue(val):
    result = val
    if val is not None and (not val.isdigit()) and (val in icmpcommontypes.keys()):
        result = str(icmpcommontypes[val])

    return result

def icmptypeMatcher(this, that):
    result = False
    newThis = str(this.value)
    newThat = str(that.value)

    if this.value != that.value:
        newThis = getICMPValue(this.value)
        newThat = getICMPValue(that.value)

    if newThis == newThat:
        result = True

    return result

registerMatcher("--icmp-type", icmptypeMatcher )

