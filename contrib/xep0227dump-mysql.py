#!/usr/bin/env python3

"""
Export data from MySQL database backend of jabberd2 to XEP-0227 portable format.
Take special care to _not_ rely on the contents of `authreg` table because
it will be empty if external authentication is used.

It relies on vendor-specific SQL extention(s) (at least function `concat()`),
so it probably needs to be adjusted to work with PostgreSQL or sqlite.

Incoming Subscription Requests are not handled. I do not know where do they
go in the database (maybe into the queue, together with offline messages?)

Result is a single XML file named xep227dump.xml in the current directory.
"""

import sys
import base64
import binascii
import MySQLdb
import xmltodict

mysql_db   = 'jabberd2'
mysql_host = 'localhost'
mysql_user = 'jabberd2'
mysql_pass = None
outfile    = 'xep227dump.xml'
# Workaround for https://github.com/processone/ejabberd/issues/2412:
separate_privacy_iqs = False
# Setting it to True will make "<list>" and "<default>" elements go into
# separate <query> elements (which is not how it is shown in XEP-0227).

if sys.version_info.major == 2:
    def input(*args):
        return raw_input(*args)

if mysql_pass is None:
    mysql_pass = input('Enter password for the database: ')

allusers = {}

dbconn = MySQLdb.connect(host=mysql_host, user=mysql_user,
                         passwd=mysql_pass, db=mysql_db)
dbconn.set_character_set('utf8')
cur = dbconn.cursor()
cur.execute('SET NAMES utf8;')
cur.execute('SET CHARACTER SET utf8;')
cur.execute('SET character_set_connection=utf8;')
# We use SQL `concat()` and then split back in Python, because splitting
# in SQL is more difficult/unportable than concatenation.
cur.execute("select `collection-owner` from active union distinct\
             select `collection-owner` from vcard union distinct\
             select `collection-owner` from `roster-groups` union distinct\
             select `collection-owner` from `roster-items` union distinct\
             select concat(username, '@', realm) as `collection-owner`\
                    from authreg")
for row in cur.fetchall():
    user, realm = row[0].split('@')
    realmusers = allusers.get(realm, set())
    realmusers.add(user)
    allusers[realm]=realmusers

print(allusers)

def getpwd(name, realm):
    ret = {}
    cur.execute("select password from authreg where\
                 username = '%s' and realm = '%s'" %
                (name, realm))
    res = cur.fetchone()
    if res:
        ret = {'@password': res[0]}
    return ret

def getroster(name, realm):
    ret = {}
    cur.execute("select jid, `name`, `to`, `from`, ask\
                 from `roster-items` where\
                 `collection-owner` = '%s@%s'" % (name, realm))
    contacts = cur.fetchall()
    items = []
    for jid, sname, sto, sfrom, ask in contacts:
        gnames = []
        cur.execute("select `group` from `roster-groups` where\
                     `collection-owner` = '%s@%s' and jid = '%s'" %
                     (name, realm, jid))
        for res in cur.fetchall():
            gnames.append(res[0])
        item = {'@jid': jid}
        if sname:
            item['@name'] = sname
        if ask:
            item['@ask'] = 'subscribe'
        if sto or sfrom:
            if sto:
                if sfrom:
                    item['@subscription'] = 'both'
                else:
                    item['@subscription'] = 'to'
            else:
                item['@subscription'] = 'from'
        if gnames:
            item['group'] = gnames
        items.append(item)
        if items:
            ret = {'query': {'@xmlns': 'jabber:iq:roster', 'item': items}}
    return ret

def getvcard(name, realm):
    ret = {}
    vcard = {}
    dropphoto = False
    cur.execute("select * from vcard where\
                 `collection-owner` = '%s@%s'" % (name, realm))
    res = cur.fetchone()
    fields = [d[0].upper() for d in cur.description]
    if res:
        for k, v in zip(fields, res):
            if v is None:
                continue
            if k in ('COLLECTION-OWNER', 'OBJECT-SEQUENCE'):
                continue
            try:
                k1, k2 = k.split('-')
                if not k1 in vcard:
                    vcard[k1] = {}

#                if k1 == 'PHOTO':
#                    if k2 == 'EXTVAL':
#                       vcard[k1]['extref'] = {'@uri': v}
#                    if k2 == 'TYPE':
#                       if 'b64bin' not in vcard[k1]:
#                           vcard[k1]['b64bin'] = {}
#                       vcard[k1]['b64bin']['@fmttype'] = v
#                    elif k2 == 'BINVAL':
#                       if 'b64bin' not in vcard[k1]:
#                           vcard[k1]['b64bin'] = {}
#                       vcard[k1]['b64bin']['#text'] = v
#                else:
                # base64 data may be corrupt (truncated), and import may
                # be picky (in ejabberd it is.). Do not include bad data
                # in the dump.
                if k1 == 'PHOTO' and k2 == 'BINVAL':
                    try:
                        base64.b64decode(v, validate=True)
                    except binascii.Error:
                        dropphoto = True
                vcard[k1][k2] = v
            except ValueError:
                vcard[k] = v
        #print('======== {}@{} ========\n{}\n'.format(name, realm, vcard))
    if vcard:
        if dropphoto:
            print('Bad base64 data dropped for user {}@{}'.format(name, realm))
            del vcard['PHOTO']
        vcard['@xmlns'] = 'vcard-temp'
        #vcard['@xddbns'] = 'vcard-temp'
        vcard['@version'] = '3.0'
        #vcard['@prodid'] = '-//HandGen//NONSGML vGen v1.0//EN'
        ret = {'vCard': vcard}
    return ret

def getplists(name, realm):
    ret = {}
    dflt = None
    lists = {}
    cur.execute("select `default` from `privacy-default` where\
                 `collection-owner` = '%s@%s'" % (name, realm))
    res = cur.fetchone()
    if res:
        dflt = res[0]
    cur.execute("select list, type, value, deny, `order`, block\
                 from `privacy-items` where\
                 `collection-owner` = '%s@%s'" % (name, realm))
    for lname, itype, value, deny, order, block in cur.fetchall():
        lst = lists.get(lname, [])
        lst.append((itype, value, deny, order, block))
        lists[lname] = lst
    lsts = []
    for lname in lists.keys():
        items = []
        for itype, value, deny, order, block in lists[lname]:
            item = {'@action': 'deny' if deny else 'allow',
                    '@order': str(order if order else 0)}
            if itype:
                item['@type'] = itype
            if value:
                item['@value'] = value
            if block:  ## what it that???
                pass
            items.append(item)
        lsts.append({'@name': lname, 'item': items})

    if lsts or dflt:
        if separate_privacy_iqs and lsts and dflt:
            ret = {'query': [{'@xmlns': 'jabber:iq:privacy',
                              'list': lsts},
                             {'@xmlns': 'jabber:iq:privacy',
                              'default': {'@name': dflt}}
                            ]}
        else:
            ret = {'query': {'@xmlns': 'jabber:iq:privacy'}}
            if lsts:
                ret['query']['list'] = lsts
            if dflt:
                ret['query']['default'] = {'@name': dflt}
    #print(xmltodict.unparse({'root': ret}, encoding='utf-8', pretty=True))
    return ret

def getoffmsgs(name, realm):
    ret = {}
    cur.execute("select xml from queue where\
                 `collection-owner` = '%s@%s'" % (name, realm))
    xmsgs = cur.fetchall()
    items = []
    for xmsg, in xmsgs:
        beg=xmsg.find("<")  # value from the database begins with "NAD"
        beg = 0 if beg < 0 else beg
        msg = xmltodict.parse(xmsg[beg:], encoding='utf-8')
        msg = msg['route']
        items.append(msg['message'])
    if items:
        ret = {'offline-messages': {'message': items}}
    return ret

def getprivate(name, realm):

    def extractcontent(dic):
        '''
        very dirty: just extract first non-attribute ("real content") element.
        In reality there will be only one element per row, but we _ought_ to
        have checked...
        '''
        for k, v in dic.items():
           if k[0] not in ('@', '#'):
               return k, v

    ret = {}
    cur.execute("select xml from private where\
                 `collection-owner` = '%s@%s'" % (name, realm))
    xitems = cur.fetchall()
    items = []
    for xitem, in xitems:
        beg=xitem.find("<")  # value from the database begins with "NAD"
        beg = 0 if beg < 0 else beg
        dic = xmltodict.parse(xitem[beg:], encoding='utf-8')
        # The following will raise exception if data is in unexpected form
        dic = dic['route']
        dic = dic['iq']
        if dic['@type'] != 'set':
            raise ValueError(dic)
        dic = dic['query']
        if dic['@xmlns'] != 'jabber:iq:private':
            raise ValueError(dic)
        k, v = extractcontent(dic)
        items.append((k, v))
    if items:
        ret = {'query': {'@xmlns': 'jabber:iq:private'}}
        for k, v in items:
            if k in ret['query']:
                if not isinstance(ret['query'][k], list):
                    ret['query'][k] = [ret['query'][k]]
                ret['query'][k].append(v)
            else:
                ret['query'][k] = v
    return ret

class mdict(dict):
    """
    Extention of `dict` with a "lossless `update`"
    """

    def merge(self, other):
        """
        Warning: shallow operation, only top level dict is merged.
        If an element with the matching name exists in the target,
        convert it to a list containing an extra element taken from
        the source.
        """
        for k, v in other.items():
            if k in self:
                if not isinstance(self[k], list):
                    self[k] = [self[k]]
                if isinstance(v, list):
                    self[k].extend(v)
                else:
                    self[k].append(v)
            else:
                self[k] = v

xep227 = {'server-data': {'@xmlns': 'urn:xmpp:pie:0', 'host': []}}
for realm in allusers.keys():
    ulist = []
    for name in allusers[realm]:
        user = mdict({'@name': name})
        user.merge(getpwd(name, realm))
        user.merge(getroster(name, realm))
        user.merge(getvcard(name, realm))
        user.merge(getplists(name, realm))
        user.merge(getoffmsgs(name, realm))
        user.merge(getprivate(name, realm))
        ulist.append(user)
    xep227['server-data']['host'].append({'@jid': realm, 'user': ulist})
cur.close()
dbconn.close()
with open(outfile, 'w') as out:
    out.write(xmltodict.unparse(xep227, encoding='utf-8', pretty=True))
