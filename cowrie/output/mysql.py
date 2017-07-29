
"""
MySQL output connector. Writes audit logs to MySQL database
"""

from __future__ import division, absolute_import

import MySQLdb
import json
import subprocess
import os
import sys
import urllib
import urllib2
import urlparse
import hashlib
import time
import threading
import sqlite3
import datetime
from time import strftime

from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
from twisted.internet import defer
from twisted.enterprise import adbapi
from twisted.python import log
from twisted.internet.task import LoopingCall
from twisted.internet import reactor
import cowrie.core.output


class ReconnectingConnectionPool(adbapi.ConnectionPool):
    """
    Reconnecting adbapi connection pool for MySQL.

    This class improves on the solution posted at
    http://www.gelens.org/2008/09/12/reinitializing-twisted-connectionpool/
    by checking exceptions by error code and only disconnecting the current
    connection instead of all of them.

    Also see:
    http://twistedmatrix.com/pipermail/twisted-python/2009-July/020007.html
    """
    def _runInteraction(self, interaction, *args, **kw):
        try:
            return adbapi.ConnectionPool._runInteraction(
                self, interaction, *args, **kw)
        except MySQLdb.OperationalError as e:
            if e[0] not in (2003, 2006, 2013):
                raise log.msg("RCP: got error %s, retrying operation" %(e,))
            conn = self.connections.get(self.threadID())
            self.disconnect(conn)
            # Try the interaction again
            return adbapi.ConnectionPool._runInteraction(
                self, interaction, *args, **kw)



class Output(cowrie.core.output.Output):
    """
    docstring here
    """
    debug = False
    db = None

    def __init__(self, cfg):
        self.cfg = cfg
        self.apiKey = cfg.get('output_mysql', 'api_key')
        cowrie.core.output.Output.__init__(self, cfg)


    def start(self):
        """
        docstring here
        """
        self.versions = {}
        if self.cfg.has_option('output_mysql', 'debug'):
            self.debug = self.cfg.getboolean('output_mysql', 'debug')

        if self.cfg.has_option('output_mysql', 'port'):
            port = int(self.cfg.get('output_mysql', 'port'))
        else:
            port = 3306
        try:
            self.db = ReconnectingConnectionPool('MySQLdb',
                host = self.cfg.get('output_mysql', 'host'),
                db = self.cfg.get('output_mysql', 'database'),
                user = self.cfg.get('output_mysql', 'username'),
                passwd = self.cfg.get('output_mysql', 'password'),
                port = port,
                cp_min = 1,
                cp_max = 1)
        except MySQLdb.Error as e:
            log.msg("output_mysql: Error %d: %s" % (e.args[0], e.args[1]))


        self.lc = LoopingCall(self.check_wait)
        self.lc.start(30)

    def stop(self):
        """
        docstring here
        """
        self.lc.stop()
        self.db.close()
        self.versions = {}

    def sqlerror(self, error):
        """
        docstring here
        """
        log.err('output_mysql: MySQL Error: {}'.format(error.value))


    def simpleQuery(self, sql, args):
        """
        Just run a deferred sql query, only care about errors
        """
        if self.debug:
            log.msg("output_mysql: MySQL query: {} {}".format(sql, repr(args)))
        d = self.db.runQuery(sql, args)
        d.addErrback(self.sqlerror)

    def simpleQueryWithCallback(self, callback, sql, args):
        if self.debug:
            log.msg("output_mysql: MySQL query: {} {}".format(sql, repr(args)))
        d = self.db.runQuery(sql, args)
        d.addCallbacks(callback, self.sqlerror)

############################

    def createSession(self, peerIP, peerPort, hostIP, hostPort, timestamp, sessionId=None):
        if sessionId == None:
            sid = uuid.uuid4().hex
        else:
            sid = sessionId

        self.createSessionWhenever(sid, peerIP, hostIP, timestamp)
        return sid

    def createASNForIP(self, sid, peerIP, sensorId, timestamp):
        def addslashes(s):
            l = ["\\", '"', "'", "\0", ]
            for i in l:
                if i in s:
                    s = s.replace(i, '\\'+i)
            return s

        def reverseIP(address):
            temp = address.split(".")
            convertedAddress = str(temp[3]) +'.' + str(temp[2]) + '.' + str(temp[1]) +'.' + str(temp[0])
            return convertedAddress

        def onASNRecordTest(r):
            if r:
                createTheSession(sid, peerIP, sensorId, int(r[0][0]), timestamp)
            else:
               self.simpleQueryWithCallback(onASNRecordInsert, 'INSERT INTO `asinfo` (`asn`, `rir`, `country`, `asname`) VALUES (%s, %s, %s, %s) ', (ASN, registry, country, isp))

        def onASNRecordInsert(r):
            self.simpleQueryWithCallback(onASNRecordReady, 'SELECT `asnid` FROM `asinfo` WHERE `asn` = %s AND `rir` = %s AND `country` = %s AND `asname` = %s ', (ASN, registry, country, isp))

        def onASNRecordReady(r):
            createTheSession(sid, peerIP, sensorId, int(r[0][0]), timestamp)

        def onSessionCreated(r):
            if self.versions.has_key(sid):
                self.simpleQuery(
                    'UPDATE `sessions` SET `client` = %s WHERE `id` = %s',
                    (self.versions[sid], sid))
                del self.versions[sid]
            else:
                self.versions[sid] = 1

        def createTheSession(sid, peerIP, sensorId, asnid, timestamp):
            self.simpleQueryWithCallback(onSessionCreated,
                'INSERT INTO `sessions` (`id`, `starttime`, `sensor`, `ip`, `asnid`)' + \
                ' VALUES (%s, STR_TO_DATE(%s, %s), %s, %s, %s)',
                (sid, timestamp, '%Y-%m-%dT%H:%i:%s.%fZ', sensorId, peerIP, asnid))

        querycmd1 = reverseIP(peerIP) + '.origin.asn.cymru.com'
        response1 = subprocess.Popen(['dig', '-t', 'TXT', querycmd1, '+short'], stdout=subprocess.PIPE).communicate()[0]
        response1List = response1.split('|')
        ASN = response1List[0].strip('" ')
        querycmd2 = 'AS' + ASN + '.asn.cymru.com'
        response2 = subprocess.Popen(['dig', '-t', 'TXT', querycmd2, '+short'], stdout=subprocess.PIPE).communicate()[0]
        response2List = response2.split('|')
        if len(response2List) < 4:
            createTheSession(sid, peerIP, sensorId, 'NULL', timestamp)
        else:
            isp = addslashes(response2List[4].replace('"', ''))
            network = addslashes(response1List[1].strip())
            country = addslashes(response1List[2].strip())
            registry = addslashes(response1List[3].strip())
            isp = network + "-" + isp
            self.simpleQueryWithCallback(onASNRecordTest, 'SELECT `asnid` FROM `asinfo` WHERE `asn` = %s AND `rir` = %s AND `country` = %s AND `asname` = %s ', (ASN, registry, country, isp))

    def createSessionWhenever(self, sid, peerIP, hostIP, timestamp=None):
        def onSensorReady(r):
            id = int(r[0][0])
            self.createASNForIP(sid, peerIP, id, timestamp)

        def onSensorInsert(r):
            self.simpleQueryWithCallback(onSensorReady, 'SELECT LAST_INSERT_ID()')

        def onSensorSelect(r):   
            if r:
                onSensorReady(r)
            else:
                self.simpleQueryWithCallback(onSensorInsert,
                    'INSERT INTO `sensors` (`ip`) VALUES (%s)', (hostIP,))

        self.simpleQueryWithCallback(onSensorSelect,
            'SELECT `id` FROM `sensors` WHERE `ip` = %s', (hostIP,))

    def insert_wait(self, resource, url, scan_id):
        p = self.cfg.get('honeypot', 'log_path') + '/backlogs.sqlite'
        try:
            dbh = sqlite3.connect(p)
            cursor = dbh.cursor()
            dt = datetime.datetime.now()
            timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                INSERT INTO vtwait (scanid, hash, url, time)
                VALUES (?,?,?,?) """, (scan_id, resource, url, timestamp,))

            dbh.commit()
            cursor.close()
        except:
            log.msg("Unexpected error: " + str(sys.exc_info()))

        return True

    def check_wait(self):
        p = self.cfg.get('honeypot', 'log_path') + '/backlogs.sqlite'
        try:
            dbh = sqlite3.connect(p)
            cursor = dbh.cursor()
            r = cursor.execute("""
                SELECT scanid, hash, url, time FROM vtwait""")

            for record in r:
                scanid = format(record[0])
                hash = format(record[1])
                url = format(record[2])
                j, jsonString = self.get_vt_report(scanid)
                if (not j is None) and (j["response_code"] == 1):
                    if "scans" in j.keys():
                        args = {'shasum': hash, 'url': url, 'permalink': j["permalink"], 'positives': j['positives'], 'total': j['total']}
                        args_scan = {'shasum': hash, 'permalink': j['permalink'], 'json': jsonString}
                        self.handleVirustotal(args, args_scan)
                        self.simpleQuery("""
                            DELETE FROM vtwait WHERE scanid = ?""", (scanid,) )

            dbh.commit()
            cursor.close()
        except:
            log.msg("Unexpected error: " + str(sys.exc_info()))

        return True

    def get_vt_report(self, resource):
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        parameters = {"resource": resource, "apikey": self.apiKey}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        jsonString = response.read()
        try:
            j = json.loads(jsonString )
        except:
            j = None

        return j, jsonString

    def post_file(self, aFileName, aUrl=None):
        file_to_send = open(aFileName, "rb").read()
        h = hashlib.sha1()
        h.update(file_to_send)
        j, jsonString = self.get_vt_report(h.hexdigest())
        if j is None:
            response = -2
        else:
            response = j["response_code"]

        if response == 1: # file known
            log.msg("post_file(): file known")
            if "scans" in j.keys():
                args = {'shasum': h.hexdigest(), 'url': aUrl, 'permalink': j['permalink'], 'positives' : j['positives'], 'total' : j['total']}
                args_scan = {'shasum': h.hexdigest(), 'permalink': j['permalink'], 'json': jsonString}
                self.handleVirustotal(args, args_scan)
            else:
                response = 2
        elif response == 0: # file not known
            log.msg("post_file(): sending the file to VT...")
            register_openers()
            datagen, headers = multipart_encode({"file": open(aFileName, "rb")})
            request = urllib2.Request("https://www.virustotal.com/vtapi/v2/file/scan?apikey=" + self.apiKey, datagen, headers)
            jsonString = urllib2.urlopen(request).read()
            log.msg("post_file(): response is " + jsonString)
            j = json.loads(jsonString)
            self.insert_wait(h.hexdigest(), aUrl, j["scan_id"])

        return response

    def make_comment(resource):
        apikey = config().get('virustotal', 'apikey')
        url = "https://www.virustotal.com/vtapi/v2/comments/put"
        parameters = {"resource": resource,
                   "comment": "captured by ssh honeypot",
                   "apikey": apikey}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json = response.read()


    def handleVirustotal(self, args, args2):
        def insert_done(r):
            self.handleVirustotalScan(args2)

        def select_done(r):
            if r:
                id = r[0][0]
            else:
                d = self.db.runQuery('INSERT INTO `virustotals`' + \
                    ' (`shasum`, `url`, `timestamp`, `permalink`, `positives`, `count`)' + \
                    ' VALUES (%s, %s, FROM_UNIXTIME(%s), %s, %s, %s)',
                    (args['shasum'], args['url'], self.nowUnix(), args['permalink'], args['positives'], args['total'],))
                d.addCallbacks(insert_done, self.sqlerror)

        d = self.db.runQuery('SELECT `id` FROM `virustotals` WHERE `permalink` = %s', (args['permalink'],))
        d.addCallbacks(select_done, self.sqlerror)
        
    def handleVirustotalScan(self, args):
        def insert_results(r):
            scan_id = r[0][0]

            jsonData = json.loads(args['json'])
            scans = jsonData['scans']

            for av, val in scans.items():
                res = val['result']
                # not detected = '' -> NULL
                if res == '':
                    res = None

                self.simpleQuery('INSERT INTO `virustotalscans`' + \
                    ' (`scan_id`, `scanner`, `result`)' + \
                   ' VALUES (%s, %s, %s)',
                   (scan_id, av, res, ))

        d = self.db.runQuery('SELECT `id` FROM `virustotals` WHERE `permalink` = %s',  (args['permalink'],))
        d.addCallbacks(insert_results, self.sqlerror)

############################

    @defer.inlineCallbacks
    def write(self, entry):
        """
        docstring here
        """

        if entry["eventid"] == 'cowrie.session.connect':
            self.createSessionWhenever(entry['session'], entry['src_ip'], self.sensor, entry['timestamp'])
        elif entry["eventid"] == 'cowrie.login.success':
            self.simpleQuery('INSERT INTO `auth` (`session`, `success`' + \
                ', `username`, `password`, `timestamp`)' + \
                ' VALUES (%s, %s, %s, %s, STR_TO_DATE(%s, %s))',
                (entry["session"], 1, entry['username'], entry['password'],
                entry["timestamp"], '%Y-%m-%dT%H:%i:%s.%fZ'))

        elif entry["eventid"] == 'cowrie.login.failed':
            self.simpleQuery('INSERT INTO `auth` (`session`, `success`' + \
                ', `username`, `password`, `timestamp`)' + \
                ' VALUES (%s, %s, %s, %s, STR_TO_DATE(%s, %s))',
                (entry["session"], 0, entry['username'], entry['password'],
                entry["timestamp"], '%Y-%m-%dT%H:%i:%s.%fZ'))

        elif entry["eventid"] == 'cowrie.command.success':
            self.simpleQuery('INSERT INTO `input`' + \
                ' (`session`, `timestamp`, `success`, `input`)' + \
                ' VALUES (%s, STR_TO_DATE(%s, %s), %s , %s)',
                (entry["session"], entry["timestamp"], '%Y-%m-%dT%H:%i:%s.%fZ',
                1, entry["input"]))

        elif entry["eventid"] == 'cowrie.command.failed':
            self.simpleQuery('INSERT INTO `input`' + \
                ' (`session`, `timestamp`, `success`, `input`)' + \
                ' VALUES (%s, STR_TO_DATE(%s, %s), %s , %s)',
                (entry["session"], entry["timestamp"], '%Y-%m-%dT%H:%i:%s.%fZ',
                0, entry["input"]))

        elif entry["eventid"] == 'cowrie.session.file_download':
            self.simpleQuery('INSERT INTO `downloads`' + \
                ' (`session`, `timestamp`, `url`, `outfile`, `shasum`)' + \
                ' VALUES (%s, STR_TO_DATE(%s, %s), %s, %s, %s)',
                (entry["session"], entry["timestamp"], '%Y-%m-%dT%H:%i:%s.%fZ',
                entry['url'], entry['outfile'], entry['shasum']))
            self.post_file(entry["outfile"], entry["url"])

        elif entry["eventid"] == 'cowrie.session.file_upload':
            self.simpleQuery('INSERT INTO `downloads`' + \
                ' (`session`, `timestamp`, `url`, `outfile`, `shasum`)' + \
                ' VALUES (%s, STR_TO_DATE(%s, %s), %s, %s)',
                (entry["session"], entry["timestamp"], '%Y-%m-%dT%H:%i:%s.%fZ',
                '', entry['outfile'], entry['shasum']))
            self.post_file(entry["outfile"])

        elif entry["eventid"] == 'cowrie.session.input':
            self.simpleQuery('INSERT INTO `input`' + \
                ' (`session`, `timestamp`, `realm`, `input`)' + \
                ' VALUES (%s, STR_TO_DATE(%s, %s), %s , %s)',
                (entry["session"], entry["timestamp"], '%Y-%m-%dT%H:%i:%s.%fZ',
                entry["realm"], entry["input"]))

        elif entry["eventid"] == 'cowrie.client.version':

            r = yield self.db.runQuery(
                'SELECT `id` FROM `clients` WHERE `version` = %s', \
                (entry['version'],))
            if r:
                id = int(r[0][0])
            else:
                yield self.db.runQuery(
                    'INSERT INTO `clients` (`version`) VALUES (%s)', \
                    (entry['version'],))
                r = yield self.db.runQuery('SELECT LAST_INSERT_ID()')
                id = int(r[0][0])

            if not self.versions.has_key(entry['session']):
                self.versions[entry['session']] = id
            else:
                del self.versions[entry['session']]
                self.simpleQuery(
                    'UPDATE `sessions` SET `client` = %s WHERE `id` = %s',
                    (id, entry["session"]))

        elif entry["eventid"] == 'cowrie.client.size':
            self.simpleQuery(
                'UPDATE `sessions` SET `termsize` = %s WHERE `id` = %s',
                ('%sx%s' % (entry['width'], entry['height']),
                    entry["session"]))

        elif entry["eventid"] == 'cowrie.session.closed':
            self.simpleQuery(
                'UPDATE `sessions` SET `endtime` = STR_TO_DATE(%s, %s)' + \
                ' WHERE `id` = %s', (entry["timestamp"],
                    '%Y-%m-%dT%H:%i:%s.%fZ', entry["session"]))

        elif entry["eventid"] == 'cowrie.log.closed':
            self.simpleQuery(
                'INSERT INTO `ttylog` (`session`, `ttylog`, `size`) VALUES (%s, %s, %s)',
                (entry["session"], entry["ttylog"], entry["size"]))

        elif entry["eventid"] == 'cowrie.client.fingerprint':
            self.simpleQuery(
                'INSERT INTO `keyfingerprints` (`session`, `username`, `fingerprint`) VALUES (%s, %s, %s)',
                (entry["session"], entry["username"], entry["fingerprint"]))

