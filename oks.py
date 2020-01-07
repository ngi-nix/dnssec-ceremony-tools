#! /usr/bin/env python3

__author__ = "Berry van Halderen"
__date__ = "$Nov 13, 2019 10:27:32 AM$"

import os
import sys
import getopt
import hjson
import yaml
import re
import datetime
import calendar
import pkcs11
import base64
import binascii
import random

# These parameters should come from a configuration file, the KASP configuration and command line arguments
kasp_refresh=None
kasp_validity=None
kasp_inceptionoffset=None
kasp_keyttl=None
kasp_kskalgo=None
kasp_ksksize=None
args_until=None
args_now=None
args_debug=None
args_recipedescription=None

# Regular expressions used to match input
duration_pattern=r"P((?P<years>\d+)Y)?((?P<months>\d+)M)?((?P<weeks>\d+)W)?((?P<days>\d+)D)?(T((?P<hours>\d+)H)?((?P<minuts>\d)+M)?((?P<seconds>\d+)S?)?)?"
dnskey_pattern=r"(?P<zone>\S+)\s+(?P<ttl>\d+)\s+IN\s+DNSKEY\s+(?P<keytype>\d+)\s+3\s+(?P<keyalgo>\d+)\s+(?P<keydata>\S+)\s*(;.*id\s*=\s*(?P<keytag>\d+).*)?$"
rrsig_pattern=r"(?P<zone>[^\s]+)\s+(?P<ttl>\d+)\s+IN\s+RRSIG\s+DNSKEY\s+(?P<sigalgo>\d+)\s+(?P<siglabels>\d+)\s+(?P<sigorigttl>\d+)\s+(?P<sigexpiration>\S+)\s+(?P<siginception>\S+)\s+(?P<keytag>\d+)\s+(?P<signame>\S+)\s+(?P<sigdata>\S+)$"
datetime_pattern=r"(?P<year>\d\d\d\d)-?(?P<month>\d\d)-?(?P<day>\d\d) ?(?P<hour>\d\d):?(?P<minute>\d\d)[:.]?(?P<second>\d\d)"
date_pattern=r"(?P<year>\d\d\d\d)-?(?P<month>\d\d)-?(?P<day>\d\d)"
duration_pattern= re.compile(duration_pattern)
dnskey_pattern=re.compile(dnskey_pattern, re.IGNORECASE)
rrsig_pattern=re.compile(rrsig_pattern, re.IGNORECASE)
datetime_pattern=re.compile(datetime_pattern)
date_pattern=re.compile(date_pattern)


def now():
    global args_now
    if args_now == None:
        return datetime.datetime.now()
    else:
        return args_now


def equals(s,i):
    if s == i:
        return True;
    else:
        try:
            if int(s) == i:
                return True
        except ValueError:
            pass
        return False


class Burned(Exception):
    message = None

    def __init__(self, message):
        self.message = message


class Record:
    name = None
    type = "DNSKEY"
    ttl = None
    keytype = None
    keydata = None
    keystore = None
    keyckaid = None
    keyalgo = None
    keytag:int = None
    keyonhsm = True
    keysecretdata = None
    keylabel = None
    keysize = None
    keystore = None
    handles = { }
    rdata = None

    def __init__(self, name):
        self.name = name

    def name(self):
        s = self.name
        if(not s.endswith(".")):
            s += "."
        return s

    def getttl(self):
        return int(self.ttl)

    def typestr(self):
        return self.type.upper()

    def typenum(self):
        if self.type.upper() == 'DNSKEY':
            return 48
        else:
            return int(self.type)

    def iskey(self):
        if self.keytype != None:
            return True
        else:
            return False

    def keyalgonum(self):
        return int(self.keyalgo)

    def keyalgostr(self):
        return str(self.keyalgo)

    def keytypenum(self):
        if isinstance(self.keytype, str):
            if self.keytype.upper() == 'KSK' or equals(self.keytype, 257):
                return 257
            elif self.keytype.upper() == 'ZSK' or equals(self.keytype, 256):
                return 256
            else:
                return int(self.keytype)
        else:
            return int(self.keytype)

    def keytypestr(self):
        if isinstance(self.keytype, str):
            if self.keytype.upper() == 'KSK' or equals(self.keytype, 257):
                return 'ksk'
            elif self.keytype.upper() == 'ZSK' or equals(self.keytype, 256):
                return 'zsk'
            else:
                return str(self.keytype)
        else:
            return str(self.keytype)

    def isksk(self):
        if isinstance(self.keytype, str) and self.keytype.upper() == 'KSK':
            return True
        elif equals(self.keytype, 257):
            return True
        else:
            return False

    def isnativeksk(self):
        if self.isksk() and self.keyonhsm:
            return True
        else:
            return False

    def iszsk(self):
        if isinstance(self.keytype, str) and self.keytype.upper() == 'ZSK':
            return True
        elif equals(self.keytype, 256):
            return True
        else:
            return False

    def getkeytag(self):
        if self.keytag == None:
            self.keytag = 0;
            i = 0
            for ch in self.bytes(onlyrdata=True):
                if (i & 0x1) == 0x1:
                    self.keytag += ch
                else:
                    self.keytag += ch << 8
                i += 1
            self.keytag += (self.keytag >> 16) & 0xFFFF
            self.keytag  = self.keytag & 0xFFFF
        return self.keytag

    def getkeyckaid(self):
        if isinstance(self.keyckaid,str):
            s = self.keyckaid
            if s.lower().startswith("base64 "):
                s = s[7:].strip() # skip the base64 and space being 7 characters 
            elif s.lower().startswith("hex "):
                s = s[4:].strip() # skip the hex and space being 4 characters
                return binascii.a2b_hex(s)
            try:
                return base64.b64decode(s)
            except binascii.Error:
                raise Burned("not a valid key id {0}".format(s))
        else:
            return self.keyckaid

    def location(self):
        location = None
        if self.keyckaid != None:
            location = "id=" + self.keyckaid
        if self.keylabel != None:
            if location == None:
                location = location + " "
            else:
                location = ""
            location = location + "label=" + self.keylabel
        return location

    def getkeysize(self):
        if self.keysize == None:
            return int(len(self.keydata) * 6 / 8 / 128) * 128
        else:
            return keysize

    def str(self):
        s  = self.name
        if not self.name.endswith("."):
            s += "."
        s += "\t"
        s += str(self.ttl)
        s += "\tIN\t"
        s += self.typestr()
        s += "\t"
        if self.iskey():
            s += str(self.keytypenum())
            s += " "
            s += str(3)
            s += " " 
            s += str(self.keyalgo)
            s += " "
            if isinstance(self.keydata, (bytes,bytearray)):
                s += str(self.keydata, "ascii")
            else:
                s += self.keydata;
            s += " ;{id = " + str(self.getkeytag()) + " (" + self.keytypestr() + "), size = " + str(self.getkeysize()) + "b}"
        else:
            first = True
            for rdata in self.data:
                if first:
                    first = False
                else:
                    s += " "
                if isinstance(rdata, str):
                    s += rdata
                elif isinstance(rdata, datetime.date):
                    s += rdata.strftime("%4Y%02d%02m%02H%02M")
                elif isinstance(rdata, (bytes,bytearray)):
                    s += base64.b64encode(rdata).decode()
                else:
                    s += str(rdata)
        return s

    def describe(self):
        print("Record name=", end='')
        print(self.name, end='')
        print(" ttl=", end='')
        print(self.ttl, end='')
        print(" type=", end='')
        print(self.type, end='')
        print(" keytype/flags=", end='')
        print(self.keytype, end='')
        print(" keyalgo=", end='')
        print(self.keyalgo)

    def bytes(self, onlyrdata=False):
        buffer = bytearray()
        if not onlyrdata:
            dnsname = self.name
            ttl = self.getttl()
            type = self.typenum()
            if(not dnsname.endswith(".")):
                dnsname += "."
            for term in dnsname.split("."):
                buffer.append(len(term))
                for ch in term:
                    buffer.append(ord(ch))
            # Add type (2 bytes)
            buffer.append((type>>8)  & 0xff)
            buffer.append(type       & 0xff)
            # Add class (2 bytes), always IN
            buffer.append(0)
            buffer.append(1)
            # Add TTL (4 bytes)
            buffer.append((ttl>>24) & 0xff)
            buffer.append((ttl>>16) & 0xff)
            buffer.append((ttl>>8)  & 0xff)
            buffer.append(ttl       & 0xff)
        # RDATA parts: keyflags, keyproto, keyalgo
        buffer.append((self.keytypenum()>>8) & 0xff)
        buffer.append((self.keytypenum())    & 0xff)
        buffer.append(3                 & 0xff)
        buffer.append(self.keyalgonum() & 0xff)
        size = 0
        if isinstance(self.keydata, (bytes,bytearray)):
            size = len(self.keydata)
            buffer.append(size >> 8)
            buffer.append(size & 0xff)
            buffer.extend(self.keydata)           
        else:
            data = base64.b64decode(bytes(self.keydata, 'ascii'))
            for ch in data:
                buffer.append(ch)
        return buffer


# Convert string to datetime object
def todatetime(str):
    m = datetime_pattern.match(str)
    if(m):
        dict = m.groupdict()
        dt = datetime.datetime(int(dict['year']),int(dict['month']),int(dict['day']),int(dict['hour']),int(dict['minute']),int(dict['second']))
        return dt
    else:
        m = date_pattern.match(str)
        if(m):
            dict = m.groupdict()
            dt = datetime.datetime(int(dict['year']),int(dict['month']),int(dict['day']))
            return dt
        else:
            return now()


def tostrtime(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def tointtime(dt):
    return int(dt.timestamp())


# Convert string to duration pattern (a dict or int)
def toduration(str):
    duration = { }
    m = duration_pattern.match(str)
    if(m):
        dict = m.groupdict()
        for key, val in dict.items():
            if(val != None):
                duration[key] = int(val)
        return duration
    else:
        return int(str)


# increase a datetime with a duration, returning the resulting datetime object
def duration_incr(dt, duration, add=True):
    delta = { 'years':0,  'months':0, 'days':0, 'hours':0, 'minutes':0, 'seconds':0, 'weeks':0 }
    delta = { **delta, **duration }
    delta['days'] += duration.get('weeks', 0);
    if(add == False):
        for key, val in delta.items():
            delta[key] = -val;
    
    delta['minutes'] += int((dt.second + delta['seconds']) / 60)
    delta['seconds']  =     (dt.second + delta['seconds']) % 60
    if(delta['seconds'] < 0):
        delta['seconds'] += 60
        delta['minutes'] -= 1

    delta['hours']   += int((dt.minute + delta['minutes']) / 60)
    delta['minutes']  =     (dt.minute + delta['minutes']) % 60
    if(delta['minutes'] < 0):
        delta['minutes'] += 60
        delta['hours'] -= 1

    delta['days']    += int((dt.hour   + delta['hours']) / 24)
    delta['hours']    =     (dt.hour   + delta['hours']) % 24
    if(delta['hours'] < 0):
        delta['hours'] += 24
        delta['days'] -= 1

    delta['days'] += delta['weeks'] * 7

    while True:
        if(dt.day + delta['days'] > calendar.monthrange(dt.year, dt.month)[1]):
            delta['days'] -= calendar.monthrange(dt.year, dt.month)[1]
            delta['months'] += 1
        elif(dt.day + delta['days'] < 1):
            delta['days'] += calendar.monthrange(dt.year, dt.month)[1]
            delta['months'] -= 1
        else:
            break
    delta['days']    += dt.day

    delta['years']   += int((dt.month-1  + delta['months']) / 12)
    delta['months']  +=     (dt.month-1  + delta['months']) % 12
    if(delta['months'] < 0):
        delta['months'] += 12
        delta['years'] -= 1
    delta['years']   += dt.year

    return datetime.datetime(delta['years'], delta['months'] + 1, delta['days'],
                             delta['hours'], delta['minutes'], delta['seconds'])


# decrament a datetime with a duration, returning the resulting datetime object
def duration_decr(dt, duration):
    return duration_incr(dt, duration, False)


def signkey(inception, expiration, key, keys, ttl, ownername, signername=None):
    if signername == None:
        signername = ownername
    sigalgo = key.keyalgo
    sigover = 'DNSKEY'
    siglabels = 0
    signame = signername
    sigttl = ttl
    siglabels = len(ownername.strip(".").split("."))
    rrsig = Record(ownername)
    rrsig.type = 'RRSIG'
    rrsig.ttl = sigttl
    rrsig.data = [ sigover, sigalgo, siglabels, sigttl, expiration, inception, key.getkeytag(), signame ]

    # Build the sign buffer
    buffer = bytearray()
    # Add type (2 bytes)
    buffer.append((48>>8)                     & 0xff) # sigover as num, being always DNSKEY for us
    buffer.append(48                          & 0xff)
    # Add algo (1 bytes)
    buffer.append(sigalgo                     & 0xff)
    # Add label count (1 byte)
    buffer.append(siglabels                   & 0xff)
    # Add the original TTL
    buffer.append((sigttl>>24)                & 0xff)
    buffer.append((sigttl>>16)                & 0xff)
    buffer.append((sigttl>>8)                 & 0xff)
    buffer.append(sigttl                      & 0xff)
    # Add the expiration
    buffer.append((tointtime(expiration)>>24) & 0xff)
    buffer.append((tointtime(expiration)>>16) & 0xff)
    buffer.append((tointtime(expiration)>>8)  & 0xff)
    buffer.append(tointtime(expiration)       & 0xff)
    # Add the inception
    buffer.append((tointtime(inception)>>24)  & 0xff)
    buffer.append((tointtime(inception)>>16)  & 0xff)
    buffer.append((tointtime(inception)>>8)   & 0xff)
    buffer.append(tointtime(inception)        & 0xff)
    # Add the keytag
    buffer.append((key.getkeytag()>>8)        & 0xff)
    buffer.append(key.getkeytag()             & 0xff)
    # Add signername
    dnsname = signame
    if(not dnsname.endswith(".")):
        dnsname += "."
    for term in dnsname.split("."):
        buffer.append(len(term))
        for ch in term:
            buffer.append(ord(ch))
    # Add the keys
    for k in keys:
        for ch in k.bytes():
            buffer.append(ch)

    session = gethsmsession(key)
    digest = session.digest(bytes(buffer), mechanism=pkcs11.mechanisms.Mechanism.SHA256)
    gethsmkeys(key)
    signature = key.handles['private'].sign(digest)
    rrsig.data.append(signature)
    return rrsig


def signkeyset(inception, expiration, keys, keyset, ttl, ownername, signername=None):
    records = ""
    # TODO sort the keyset such that the order is correct
    for key in keyset:
        key.ttl = ttl
        getkeydata(key, key.handles['public'])
        records += key.str() + "\n"
    for key in keys:
        rrsig = signkey(inception, expiration, key, keyset, ttl, ownername, signername)
        records += rrsig.str() +"\n"
    return records


def composekeydata(modulus, exponent):
    modulus_skip = 0
    while modulus_skip < len(modulus) and modulus[modulus_skip] == 0:
        ++modulus_skip
    exponent_skip = 0
    while exponent_skip < len(exponent) and exponent[exponent_skip] == 0:
        ++exponent_skip
    if len(exponent) - exponent_skip > 65535:
        raise Burned("len exponent longer than allowed ("+len(exponent)+")")
    elif len(exponent) - exponent_skip > 255:
        buffer = bytearray()
        buffer.append(0)
        buffer.append((len(exponent) - exponent_skip) >> 8)
        buffer.append((len(exponent) - exponent_skip) & 0xff)
        buffer.extend(exponent[exponent_skip:])
        buffer.extend(modulus[modulus_skip:])
    else:
        buffer = bytearray()
        buffer.append(len(exponent) - exponent_skip)
        buffer.extend(exponent[exponent_skip:])
        buffer.extend(modulus[modulus_skip:])
    return buffer


def decomposekeydata(buffer):
    if buffer[0] == 0:
        exponent_len = buffer[1] << 8 | buffer[2]
        exponent = buffer[3:exponent_len+3]
        modulus = buffer[exponent_len+3:]
    else:
        exponent_len = buffer[0]
        exponent = buffer[1:exponent_len+1]
        modulus = buffer[exponent_len+1:]
    return ( modulus, exponent )


def newkey(key, exportable=False, ontoken=True):
    success = True

    if key.keysecretdata == None:
        importkey = False
        importprivkey = False
    else:
        importkey = True
        importprivkey = True
    if key.keydata == None:
        importpubkey = False
    else:
        importpubkey = True
    
    flags = pkcs11.constants.MechanismFlag.HW | pkcs11.constants.MechanismFlag.SIGN | pkcs11.constants.MechanismFlag.VERIFY
    flags |= pkcs11.constants.MechanismFlag.WRAP | pkcs11.constants.MechanismFlag.ENCRYPT | pkcs11.constants.MechanismFlag.DECRYPT
    flags |= pkcs11.constants.MechanismFlag.UNWRAP | pkcs11.constants.MechanismFlag.DIGEST
    template     = { }
    pubtemplate  = { pkcs11.constants.Attribute.TOKEN: False, pkcs11.constants.Attribute.PRIVATE: False }
    privtemplate = { pkcs11.constants.Attribute.TOKEN: True,  pkcs11.constants.Attribute.PRIVATE: True  }
    id = key.getkeyckaid()
    label = key.keylabel
    if label != None:
        # template[pkcs11.constants.Attribute.LABEL] = label
        pubtemplate[pkcs11.constants.Attribute.LABEL]  = label
        privtemplate[pkcs11.constants.Attribute.LABEL] = label
    if id != None:
        # template[pkcs11.constants.Attribute.ID] = id
        pubtemplate[pkcs11.constants.Attribute.ID]  = id
        privtemplate[pkcs11.constants.Attribute.ID] = id
    if label != None and id != None:
        raise Burned("No label or id specified")
        success = False
        return success

    #template[pkcs11.constants.Attribute.TRUSTED]        = True
    template[pkcs11.constants.Attribute.CLASS]        = pkcs11.ObjectClass.SECRET_KEY
    template[pkcs11.constants.Attribute.KEY_TYPE]     = pkcs11.KeyType.AES
    template[pkcs11.constants.Attribute.TOKEN]        = True
    template[pkcs11.constants.Attribute.PRIVATE]      = True
    template[pkcs11.constants.Attribute.ENCRYPT]      = True
    template[pkcs11.constants.Attribute.DECRYPT]      = True
    template[pkcs11.constants.Attribute.WRAP]         = True
    template[pkcs11.constants.Attribute.UNWRAP]       = True
    #if importkey:
    #    template[pkcs11.constants.Attribute.SECRET] = base64.b64decode(key.keysecretdata)
    template[pkcs11.constants.Attribute.EXTRACTABLE] = True
    template[pkcs11.constants.Attribute.SENSITIVE] = False

    pubtemplate[pkcs11.constants.Attribute.CLASS]          = pkcs11.ObjectClass.PUBLIC_KEY
    pubtemplate[pkcs11.constants.Attribute.KEY_TYPE]       = pkcs11.KeyType.RSA
    pubtemplate[pkcs11.constants.Attribute.TOKEN]          = ontoken
    pubtemplate[pkcs11.constants.Attribute.PRIVATE]        = True
    pubtemplate[pkcs11.constants.Attribute.ENCRYPT]        = True
    pubtemplate[pkcs11.constants.Attribute.VERIFY]         = True
    pubtemplate[pkcs11.constants.Attribute.VERIFY_RECOVER] = True
    pubtemplate[pkcs11.constants.Attribute.WRAP]           = True
    #pubtemplate[pkcs11.constants.Attribute.TRUSTED]        = True
    if importpubkey:
        ( modulus, exponent ) = decomposekeydata(base64.b64decode(key.keydata))
        key.keydata = base64.b64encode(composekeydata(modulus, exponent)).decode()
        pubtemplate[pkcs11.constants.Attribute.MODULUS] = modulus
        pubtemplate[pkcs11.constants.Attribute.PUBLIC_EXPONENT] = exponent

    privtemplate[pkcs11.constants.Attribute.CLASS]        = pkcs11.ObjectClass.PRIVATE_KEY
    privtemplate[pkcs11.constants.Attribute.KEY_TYPE]     = pkcs11.KeyType.RSA
    privtemplate[pkcs11.constants.Attribute.TOKEN]        = ontoken
    privtemplate[pkcs11.constants.Attribute.PRIVATE]      = True
    privtemplate[pkcs11.constants.Attribute.DECRYPT]      = True
    privtemplate[pkcs11.constants.Attribute.SIGN]         = True
    privtemplate[pkcs11.constants.Attribute.SIGN_RECOVER] = True
    privtemplate[pkcs11.constants.Attribute.UNWRAP]       = True
    if importprivkey:
        ( modulus, exponent ) = decomposekeydata(base64.b64decode(key.keysecretdata))
        privtemplate[pkcs11.constants.Attribute.MODULUS] = modulus
        privtemplate[pkcs11.constants.Attribute.PRIVATE_EXPONENT] = exponent

    if exportable != None:
        privtemplate[pkcs11.constants.Attribute.EXTRACTABLE] = True
        privtemplate[pkcs11.constants.Attribute.SENSITIVE] = False

    key.keydata = None
    key.keysecretdata = None

    session = gethsmsession(key)
    if key.keyalgostr() in ( "AES" ):
        if not importkey:
            len = 16 * 8
            secretkey = session.generate_key(key_type=pkcs11.mechanisms.KeyType.AES, key_length=len, id=id, label=label, store=True, template=template)
        else:
            secretkey = session.create_object(ptemplate)
        key.keysecretdata = None
        key.keyckaid = secretkey.id
        key.keylabel = secretkey.label
        key.handles['secret'] = secretkey
    else:
        if not importpubkey and not importprivkey:
            (pubkey, privkey) = session.generate_keypair(key_type=pkcs11.mechanisms.KeyType.RSA, key_length=2048,
                                                         store=True, capabilities=flags,
                                                         mechanism=pkcs11.mechanisms.Mechanism.RSA_PKCS_KEY_PAIR_GEN,
                                                         public_template=pubtemplate, private_template=privtemplate)
            key.handles['public']  = pubkey
            key.handles['private'] = privkey
        else:
            if importprivkey:
                privkey = session.create_object(privtemplate)
                key.handles['private'] = privkey
            if importpubkey:
                pubkey = session.create_object(pubtemplate)
                key.handles['public'] = pubkey
        key.ckakeyid = pubkey.id
        key.keylabel = pubkey.label
        #getkeydata(session, key, pubkey)
        #if importprivkey:
        #    getkeydata(session, key, privkey, False, exportable)

    #if label == None:
    #    keylabel = str(key.getkeytag())
    #    pubkey.label = keylabel
    #    privkey.label = keylabel
    #    key.keylabel = keylabel
    return success



def getkeydata(key, handle, public=True, private=False):
    if public == False and private == False:
        return None
    modulus = handle[pkcs11.constants.Attribute.MODULUS]
    try:
        if handle[pkcs11.constants.Attribute.PUBLIC_EXPONENT] != None:
            key.keydata = composekeydata(modulus, handle[pkcs11.constants.Attribute.PUBLIC_EXPONENT])
            key.keydata = base64.b64encode(key.keydata).decode()
    except pkcs11.AttributeTypeInvalid:
        pass
    try:
        if handle[pkcs11.constants.Attribute.PRIVATE_EXPONENT] != None:
            key.keydata = composekeydata(modulus, handle[pkcs11.constants.Attribute.PRIVATE_EXPONENT])
            key.keydata = base64.b64encode(key.keydata).decode()
    except pkcs11.AttributeTypeInvalid:
        pass
    return key.keydata


def gethsmsession(key):
    global sessions
    if key.keystore == None:
        session = sessions["default"]
    else:
        session = sessions[key.keystore]
    return session


def gethsmkeys(key):
    handles = { }
    attrs = { }
    session = gethsmsession(key)
    if key.keylabel != None:
        attrs[pkcs11.constants.Attribute.LABEL] = str(key.keylabel)
    if key.keyckaid != None:
        attrs[pkcs11.constants.Attribute.ID] = key.getkeyckaid()
    for handle in session.get_objects(attrs):
        if isinstance(handle, pkcs11.SecretKey):
            handles['secret'] = handle
        elif isinstance(handle, pkcs11.PublicKey):
            handles['public'] = handle
        elif isinstance(handle, pkcs11.PrivateKey):
            handles['private'] = handle
        else:
            sys.exit(1)
    if len(handles) > 0:
        key.handles = handles
        return True
    else:
        return False


def deletekeys(key):
    success = True
    gethsmkeys(key)
    for handle in key.handles.values():
        try:
            handle.destroy()
        except:
            success = False
    return success


def wrapkey(key, wrappingkey, wrapPublic=False):
    gethsmkeys(key)
    gethsmkeys(wrappingkey)
    if wrapPublic:
        wraphandle = wrappingkey.handles['public']
        keyhandle  = key.handles['secret']
        mechanism = pkcs11.mechanisms.Mechanism.RSA_PKCS
    else:
        wraphandle = wrappingkey.handles['secret']
        keyhandle  = key.handles['private']
        mechanism = pkcs11.mechanisms.Mechanism.AES_KEY_WRAP_PAD
    bytes = wraphandle.wrap_key(keyhandle, mechanism=mechanism)
    return base64.b64encode(bytes).decode()


def byrefkey(key):
    dict = { 'keyType' : "byRef" }
    if not key.keystore == None:
        dict['store'] = key.keystore
    if not key.keyckaid == None:
        dict['keyID'] = key.keyckaid
    if not key.keylabel == None:
        dict['keyLabel'] = key.keylabel
    if key.keyckaid == None and key.keylabel == None:
        if key.keytag != None or key.keydata != None:
            dict['keyLabel'] = key.getkeytag()
    return dict


def directkey(key):
    dict = { 'keyType' : "direct" }
    dict['keyAlgo'] = key.keyalgo
    dict['keyFlags'] = key.keytypenum()
    dict['keyData'] = key.keydata
    return dict


def parsekey(params):
    key = Record(None)
    if params.get('keyAlgo') != None:
        key.keyalgo = params['keyAlgo']
    if params.get('keyFlags') != None:
        key.keytype = params['keyFlags']
    if params.get('keySecretData'):
        key.keysecretdata = params['keySecretData']
    if params.get('keyData'):
        key.keydata = params['keyData']
    if params.get('keyStore'):
        key.keystore = params['keyStore']
    if params.get('keyID'):
        key.keyckaid = params['keyID']
    if params.get('keyLabel'):
        key.keylabel = params['keyLabel']
    return key


def readkeyset(filename):
    keys = { }
    sigs = { }
    origin = None
    with open(filename, "r") as file:
        line = file.readline()
        while line:
            m = dnskey_pattern.match(line)
            if(m):
                m = m.groupdict()
                key = Record(m['zone'])
                key.ttl = int(m['ttl'])
                key.type = 'DNSKEY'
                key.keytype = m['keytype']
                key.keyalgo = m['keyalgo']
                key.keydata = m['keydata']
                #if()
                if m.get('keytag') != None and m.get('keytag') != "":
                    key.keytag = int(m['keytag'])
                else:
                    key.keyonhsm = False
                keys[key.getkeytag()] = key
            m = rrsig_pattern.match(line)
            if(m):
                m = m.groupdict()
                keytag = m['keytag']
                m['sigexpiration'] = todatetime(m['sigexpiration'])
                m['siginception'] = todatetime(m['siginception'])
                sigs[keytag] = { **sigs.get(keytag, { }), **m }
            line = file.readline()
        file.close()
    expiration = now()
    for sig in sigs.values():
        expiration = max(expiration, sig.get("sigexpiration", datetime.datetime.min))
    return ( origin, keys, expiration )


def producerecipe(zone, inputfile, outputfile):
    global kasp_refresh
    global kasp_validity
    global kasp_inceptionoffset
    global kasp_kskalgo
    global kasp_ksksize
    global kasp_zskalgo
    global kasp_zsksize
    global args_recipedescription
    global args_until
    global now

    kasp_refresh = toduration(kasp_refresh)
    kasp_validity = toduration(kasp_validity)
    kasp_inceptionoffset = toduration(kasp_inceptionoffset)

    description = args_recipedescription

    if os.path.exists(inputfile):
        ( origin, keys, expiration ) = readkeyset(inputfile)
    else:
        origin = zone
        keys = { }
        expiration = now()

    # Create a core recipe
    recipe = { 'recipeSpecVersion': "v1.0",
               'preamble': { 'timestamp': tostrtime(now()),
                             'description': description },
               'actions' : [ ] }

    # Each KSK currenly present must be in the HSM
    for key in keys.values():
        if key.isksk():
            # could add configuration/cli parameter to output flags/algo by name
            action = byrefkey(key)
            action['keyAlgo'] = key.keyalgo
            action['keyFlags'] = key.keytypenum()
            recipe['actions'].append({ "actionType": "haveKey", "actionParams": action })

    # In case KSK collover, generate a key for the zone
    key = Record(zone)
    key.type     = 'DNSKEY'
    key.keytype  = 'KSK'
    key.keyalgo  = kasp_kskalgo
    key.keylabel = None
    key.keysize  = kasp_ksksize
    key.keyckaid = "hex " + binascii.b2a_hex(random.getrandbits(128).to_bytes(16,byteorder='big')).decode()
    action = { 'keyAlgo': key.keyalgonum(),
               'keyFlags' : key.keytypenum(),
               'keyID': key.keyckaid,
               'keySize': key.keysize }
    keys[key.keyckaid] = key
    recipe['actions'].append({ "actionType": "generateKey", "actionParams": action })

    # Also introduce ZSK
    key = Record(zone)
    key.type     = 'DNSKEY'
    key.keytype  = 'ZSK'
    key.keyalgo  = kasp_zskalgo
    key.keylabel = None
    key.keysize  = kasp_zsksize
    key.keyckaid = "hex " + binascii.b2a_hex(random.getrandbits(128).to_bytes(16,byteorder='big')).decode()
    action = { 'keyAlgo': key.keyalgonum(),
               'keyFlags' : key.keytypenum(),
               'keyID': key.keyckaid,
               'keySize': key.keysize }
    keys[key.keyckaid] = key
    recipe['actions'].append({ "actionType": "generateKey", "actionParams": action })

    args_until = todatetime(args_until)
    now = now()
    while now < args_until:
        step = None
        if (now >= duration_decr(expiration,kasp_refresh)):
            inception = duration_decr(now, kasp_inceptionoffset);
            expiration = duration_incr(now, kasp_validity)

            keysetall = [ ] # The keyset to be signed
            keysetksk = [ ] # The keys that are signing
            for key in keys.values():
                if key.iszsk():
                    keysetall.append(directkey(key))
                elif not key.isnativeksk():
                    keysetall.append(directkey(key))
                elif key.isksk():
                    keysetall.append(byrefkey(key))
                    keysetksk.append(byrefkey(key))
            action = {'inception': tostrtime(inception), 'expiration': tostrtime(expiration), 'ttl': 60, 'Keyset': keysetall, 'signedBy': keysetksk }
            recipe['actions'].append({ "actionType": "produceSignedKeyset", "actionParams": action })
        else:
            step = duration_decr(expiration,kasp_refresh)
        if(step != None):
            now = step

    for key in keys.values():
        if key.isnativeksk():
            action = { 'key' : byrefkey(key) }
            action['mustExist'] = False
            recipe['actions'].append({ "actionType": "deleteKey", "actionParams": action })   

    with open(outputfile, "w") as file:
        hjson.dump(recipe, file)
        file.write("\n")
        file.close()


def consumerecipe(recipefile):
    global conf_repomodule
    global conf_repolabel
    global conf_repopin
    with open(recipefile, "r") as file:
        recipe = hjson.load(file)
        file.close()


def cookrecipe(recipefile):
    global args_debug
    keys = { }
    with open(recipefile, "r") as file:
        #recipe = json.load(file,ignore_comments=False,preserve_order=True)
        recipe = hjson.load(file)
        file.close()
    recipecomplete = True
    recipecounter = 1
    for action in recipe['actions']:
        action['cooked'] = { }
        try:
            if action['actionType'] == "generateKey":
                key = Record(action['actionParams'].get('owner'))
                key.type = 'DNSKEY'
                key.keytype  = action['actionParams'].get('keyFlags')
                key.keyckaid = action['actionParams'].get('keyID')
                key.keylabel = action['actionParams'].get('keyLabel')
                if action['actionParams'].get('exportable') == True:
                    exportable = True
                else:
                    exportable = False
                key.keyalgo  = action['actionParams']['keyAlgo']
                key.keysize  = action['actionParams']['keySize']
                success = newkey(key=key, exportable=exportable, ontoken=True)
                action['cooked']['generateSuccess'] = success
                action['cooked']['success'] = success
                if args_debug:
                    #action['cooked']['keyTag'] = key.getkeytag()
                    if key.keyckaid != None:
                        action['cooked']['keyID'] = key.keyckaid
                    if key.keylabel != None and key.keylabel != "":
                        action['cooked']['keyLabel'] = key.keylabel
                    action['cooked']['keyData'] = key.keydata
                    if key.keysecretdata != None:
                        action['cooked']['keySecretData'] = key.keysecretdata
            elif action['actionType'] == 'produceSignedKeyset':
                ownername   = action['actionParams']['ownerName']
                signername  = action['actionParams'].get('signerName')
                inception   = action['actionParams']['inception']
                expiration  = action['actionParams']['expiration']
                ttl         = action['actionParams']['ttl']
                keyset = [ ]
                keys = [ ]
                for params in action['actionParams']['keyset']:
                    key = parsekey(params['key'])
                    key.ttl   = ttl
                    key.name = ownername
                    gethsmkeys(key)
                    keyset.append(key)
                for params in action['actionParams']['signedBy']:
                    key = parsekey(params['key'])
                    if key.keydata == None:
                        gethsmkeys(key)
                        getkeydata(key, key.handles['public'])
                    keys.append(key)
                signedset = signkeyset(todatetime(inception), todatetime(expiration), keys, keyset, ttl, ownername, signername)
                action['cooked']['signedKeysetRRs'] = signedset
            elif action['actionType'] == 'haveKey':
                key = parsekey(action['actionParams']['key'])
                if not gethsmkeys(key):
                    action['cooked']['exists'] = False
                    if action['actionParams'].get('relaxed') != True:
                        raise Burned("mandatory key {0} does not exist".format(key.location()))
                else:
                    action['cooked']['exists'] = True
            elif action['actionType'] == 'deleteKey':
                key = parsekey(action['actionParams']['key'])
                if not gethsmkeys(key):
                    if action['actionParams'].get('mustExist') == True:
                        raise Burned("mandatory key {0} does not exist trying to delete".format(key.location()))
                    else:
                        # not able to seperate between key not there and key not deletable
                        action['cooked']['deleteSuccess'] = False
                else:
                    success = deletekeys(key)
                    action['cooked']['deleteSuccess'] = success
                action['cooked']['success'] = success
            elif action['actionType'] in ('importPublicKey', 'importKey', 'importKeypair'):
                if action['actionParams']['key']['keyType'] != "direct":
                    raise Burned("imported key not by direct key reference")
                key = parsekey(action['actionParams']['key'])
                if action['actionParams'].get('exportable') == True:
                    exportable = True
                else:
                    exportable = False
                success = newkey(key, exportable)
                getkeydata(key, key.handles['public'])
                if key.keydata == None:
                    success = False
                if success:
                    symkey = Record(None)
                    symkey.keyckaid = key.keyckaid
                    symkey.keylabel = key.keylabel
                    symkey.keyalgo  = "AES"
                    symkey.keysize  = 1024
                    success = newkey(key=symkey, exportable=True, ontoken=False)
                    if success:
                        action['cooked']['keyBlob'] = wrapkey(symkey, key, True)                
                action['cooked']['success'] = success
                if args_debug:
                    action['cooked']['keyData'] = key.keydata
                    if key.keysecretdata != None:
                        action['cooked']['keySecretData'] = key.keysecretdata
                    if key.keyckaid != None:
                        action['cooked']['keyID'] = key.keyckaid
                    if key.keylabel != None and key.keylabel != "":
                        action['cooked']['keyLabel'] = key.keylabel
            elif action['actionType'] in ('exportKeypair', 'exportKey'):
                if action['actionParams']['key']['keyType'] != "byRef":
                    raise Burned("exported key not by key reference")
                key = parsekey(action['actionParams']['key'])
                if action['actionParams'].get('wrappingKey') == None:
                    gethsmkeys(key)
                    getkeydata(key, key.handles['private'], True, True)
                    if args_debug:
                        if key.keysecretdata != None:
                            action['cooked']['keySecretData'] = key.keysecretdata
                        if key.keydata != None:
                            action['cooked']['keyData'] = key.keydata
                    if key.keysecretdata != None:
                        action['cooked']['keyBlob'] = key.keysecretdata
                        action['cooked']['exportSuccess'] = True 
                    else:
                    if action['actionParams']['wrappingKey']['keyType'] != "byRef":
                        raise Burned("wrapping key not by key reference")
                    wrappingkey = parsekey(action['actionParams']['wrappingKey'])
                    action['cooked']['keyBlob'] = wrapkey(key, wrappingkey)
                    action['cooked']['exportSuccess'] = True
            else:
                raise Burned("unknown action "+action['actionType'])
            recipecounter += 1
        except KeyError as ex:
            print("missing value for field"+ex.args[0]+" in recipe", file=sys.stderr)
            print("recipe step "+recipecounter+" failed")
            recipecomplete = False
            break
        except pkcs11.exceptions.GeneralError as ex:
            print("PKCS11 error", file=sys.stderr)
                print("recipe step "+recipecounter+" failed")
            recipecomplete = False
            break
        except Burned as ex:
            print(ex.message, file=sys.stderr)
                print("recipe step "+recipecounter+" failed")
            recipecomplete = False
            break
    with open(recipefile, "w") as file:
        recipe['preamble']['timestamp'] = tostrtime(now());
        hjson.dump(recipe, file)
        file.write("\n")
        file.close()
    if recipecomplete:
        print("Recipe completed.", file=sys.stderr)


def usage(message=None):
    '''
    Output message to stderr regarding command line usage.
    '''
    print("", file=sys.stderr)
    if message != None:
        print(sys.argv[0] + ": " + message, file=sys.stderr)
        print("", file=sys.stderr)
    print("usage:  oks [ -h -d -c config -f recipe.json -i input -z zone  <command>", file=sys.stderr)
    print("    where command is one of:", file=sys.stderr)
    print("    produce    produce a recipe for the specified zone with the optional", file=sys.stderr)
    print("               initial signed DNSKEY set in the zonefile (-i), a recipe for", file=sys.stderr)
    print("               signed keysets will be created for the specified until date", file=sys.stderr)
    print("               with an additional description in the recipe", file=sys.stderr)
    print("               additional arguments required:")
    print("               produce <zone> <until> <description>")
    print("    cook       process a recipe in a bunker environment executing all the", file=sys.stderr)
    print("               specified steps in the recipe and overwriting the file with", file=sys.stderr)
    print("               the cooked result", file=sys.stderr)
    print("    consume    from a processed recipe, insert generated keys in local HSM", file=sys.stderr)
    print("               and extract DNSKEY sets per period", file=sys.stderr)
    print("    -c config  specify an alternative oks.conf configuration file, otherwise", file=sys.stderr)
    print("               the configuration in the local directory is used", file=sys.stderr)
    print("    -d         operate in debug mode, not for use in production", file=sys.stderr)
    print("    -z zone    zone name to operate on", file=sys.stderr)
    print("    -i input   input filename containing DNSKEY set as initial keyset", file=sys.stderr)
    print("    -f recipe  alternate recipe file to produce or process, when not specified", file=sys.stderr)
    print("               recipe.json is used as filename", file=sys.stderr)
    print("", file=sys.stderr)


def main():
    '''
    Main program that reads the configuration file, command line arguments and then decides between the
    different modes of the program.
    '''
    global kasp_refresh
    global kasp_validity
    global kasp_inceptionoffset
    global kasp_kskalgo
    global kasp_ksksize
    global kasp_zskalgo
    global kasp_zsksize
    global args_debug
    global args_recipedescription
    global args_until
    global sessions
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hdcr:i:", ["help","debug","config","recipe=","input=","now="])
    except getopt.GetoptError as err:
        usage(str(err))
        return 1
    configfile = "oks.conf"
    recipe = "recipe.json"
    inputfile = None
    inputzone = None
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            return 0
        elif o in ("-d", "--debug"):
            args_debug = 1
        elif o in ("-c", "--config"):
            configfile = a
        elif o in ("-r", "--recipe"):
            recipe = a
        elif o in ("-i", "--input"):
            inputfile = a
        elif o in ("--now"):
            args_now = todatetime(a)
        else:
            usage("unhhandled option "+o)
            return 1
    with open(configfile) as file:
        conf = yaml.load(file, Loader=yaml.FullLoader)
        conf_version = conf['version']
        if conf.get('repository') != None:
            conf_reposmodule["default"] = str(conf['repository']['module'])
            conf_reposlabel["default"]  = str(conf['repository']['label'])
            conf_repospin["default"]    = str(conf['repository']['pin'])
        repos = { }
        nrepos = 0
        for confrepo in conf['repositories']:
            if isinstance(confrepo,str):
                repo = confrepo
                module = str(conf['repositories'][confrepo]['module'])
                label  = str(conf['repositories'][confrepo]['label'])
                pin    = str(conf['repositories'][confrepo]['pin'])
            else:
                repo = next(iter(confrepo))
                module = str(confrepo['module'])
                label  = str(confrepo['label'])
                pin    = str(confrepo['pin'])
            if repos.get(module) == None:
                repos[module] = { }
            if repos[module].get(label) == None:
                repos[module][label] = [ ]
            repos[module][label].append({ 'name': repo, 'label': label, 'pin': pin })
            nrepos += 1
        if conf.get('kasp') != None:
            kasp_refresh         = str(conf['kasp'].get('refresh'))
            kasp_validity        = str(conf['kasp'].get('validity'))
            kasp_inceptionoffset = str(conf['kasp'].get('inceptionoffset'))
            kasp_ttl             = str(conf['kasp'].get('ttl'))
            if conf['kasp'].get('ksk') != None:
                kasp_kskalgo         = str(conf['kasp']['ksk'].get('algo'))
                kasp_ksksize         = str(conf['kasp']['ksk'].get('size'))
            if conf['kasp'].get('zsk') != None:
                kasp_zskalgo         = str(conf['kasp']['zsk'].get('algo'))
                kasp_zsksize         = str(conf['kasp']['zsk'].get('size'))
        if conf.get('transport') != None:
            if conf['transport'].get('key') != None:
                conf_exchkeylabel  = conf['transport']['key'].get('label')
                conf_exchkeyckaid  = conf['transport']['key'].get('ckaid')
                conf_exchkeysize   = conf['transport']['key'].get('size')
                if isinstance(conf_exchkeylabel, str):
                    if conf_exchkeylabel == "":
                        conf_exchkeylabel = None
                else:
                    conf_exchkeylabel = str(conf_exchkeylabel)
                if isinstance(conf_exchkeyckaid, str):
                    if conf_exchkeyckaid == "":
                        conf_exchkeyckaid = None
                else:
                    conf_exchkeyckaid = str(conf_exchkeyckaid)
                if isinstance(conf_exchkeysize, str):
                    if conf_exchkeysize == "":
                        conf_exchkeysize = None
                    else:
                        conf_exchkeysize = int(conf_exchkeysize)
                elif not isinstance(conf_exchkeysize, NoneType) and not isinstance(conf_exchkeysize, int):
                    conf_exchkeysize = int(conf_exchkeysize)
    sessions = { }
    for module in repos.keys():
        try:
            lib = pkcs11.lib(module)
            for label in repos[module].keys():
                token = lib.get_token(token_label=label)
            pin = repos[module][label][0]['pin']
            session = token.open(user_pin=pin, rw=True)
            sessions[repo] = session
        except pkcs11.exceptions.NoSuchToken:
            print("Unable to access default token "+conf_repolabel, file=sys.stderr)
            sys.exit(1)
    if nrepos == 1:
        repo = next(iter(sessions.keys()))
        if repo != "default":
            sessions["default"] = sessions[repo]
    if len(args) == 0:
        usage("no argument given")
        return 1
    elif args[0] == "produce":
        if len(args) != 4:
            usage("too few arguments")
            return 1
        inputzone = args[1]
        args_until = args[2]
        args_recipedescription = args[3]
        if inputfile == None:
            inputfile = inputzone
        producerecipe(inputzone, inputfile, recipe)
    elif args[0] == "cook":
        cookrecipe(recipe)
    elif args[0] == "consume":
        consumerecipe(recipe)
    else:
        usage("unrecognized argument " + args[0])
        return 1
    return 0


if __name__ == "__main__":
    result = main()
    if result != 0:
        sys.exit(result)
