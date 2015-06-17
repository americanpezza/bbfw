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
        result = {'name': "--set-xmark", "value": this.value }
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


