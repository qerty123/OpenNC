#!/usr/bin/python3

import sqlite3
import requests
import configparser
import logging
import sys
import os
import time
import json
import socket

from dnslib import DNSLabel, QTYPE, RR, dns
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer


version = "0.1.0"
records = []
cache = []
zones = {}


TYPE_LOOKUP = {
    'A': (dns.A, QTYPE.A),
    'AAAA': (dns.AAAA, QTYPE.AAAA),
    'CAA': (dns.CAA, QTYPE.CAA),
    'CNAME': (dns.CNAME, QTYPE.CNAME),
    'DNSKEY': (dns.DNSKEY, QTYPE.DNSKEY),
    'MX': (dns.MX, QTYPE.MX),
    'NAPTR': (dns.NAPTR, QTYPE.NAPTR),
    'NS': (dns.NS, QTYPE.NS),
    'PTR': (dns.PTR, QTYPE.PTR),
    'RRSIG': (dns.RRSIG, QTYPE.RRSIG),
    'SOA': (dns.SOA, QTYPE.SOA),
    'SRV': (dns.SRV, QTYPE.SRV),
    'TXT': (dns.TXT, QTYPE.TXT),
    'SPF': (dns.TXT, QTYPE.TXT),
}


class Record:
    def __init__(self, rname, rtype, args):
        self.rname = DNSLabel(rname)
        rd_cls, self.rtype = TYPE_LOOKUP(rtype)

        self.rr = RR(rname=self.rname, rtype=self.rtype, rdata=rd_cls(*args), ttl=0)

    def match(self, q):
        return q.qname == self.rname and (q.qtype == QTYPE.ANY or q.qtype == self.rtype)


class Resolver(ProxyResolver):
    def __init__(self, mode):
        super().__init__("8.8.8.8", 53, 5)
        self.mode = mode


    def resolve(self, request, handler):
        reply = request.reply()
        #reply.add_answer(RR(rname=DNSLabel("google.com"), rtype=QTYPE.A, rdata=dns.A("8.8.8.8")))
        for i in records:
            if i.match(request.q):
                reply.add_answer(i.rr)
        if self.mode == "authoritative":
            return reply
        else:
            for i in cache:
                if i.match(request.q):
                    reply.add_answer(i.rr)
            if reply.rr:
                return reply
            for i in zones:
                if str(request.q.qname).endswith(i):
                    resp = dnsrequest(request.q.qname, request.q.qtype, zones[i])
                    reply.add_answer(RR(rname=DNSLabel(request.q.qname), rtype=request.q.qtype, rdata=dns.A(str(resp))))
                    return reply
            else:
                if "default" in zones:
                    resp = dnsrequest(request.q.qname, request.q.qtype, zones["default"])
                    reply.add_answer(RR(rname=DNSLabel(request.q.qname), rtype=request.q.qtype, rdata=dns.A(str(resp))))
                    return reply
                else:
                    return super().resolve(request, handler)


# Read config and return params
class Config:
    def __init__(self, path_to_config):
        try:
            conf_str = "[default]\n" + open(path_to_config, "r").read().replace("[", "").replace("]", "")
            self.configparser = configparser.RawConfigParser()
            self.configparser.read_string(conf_str)
        except Exception as e:
            self.configparser = None
    
    def get(self, param_name, replacement=None):
        if self.configparser:
            section="default"
            if self.configparser.has_section(section) and self.configparser.has_option(section, param_name):
                return self.configparser.get(section, param_name)
            else:
                return replacement
        else:
            return replacement


def setlogging(path_to_log, log_level):
    #logging.basicConfig(filename=path_to_log, level=logging._nameToLevel(log_level))
    logger = logging.getLogger()
    logger.setLevel(logging._nameToLevel[log_level])
    lfh = logging.FileHandler(path_to_log)
    lformatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    lfh.setFormatter(lformatter)
    logger.addHandler(lfh)
    return logger


def initdb(path_to_db):
    conn = sqlite3.connect(path_to_db)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS zones(id INT PRIMARY KEY, name TEXT, server TEXT);''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS cache(id INT PRIMARY KEY, name TEXT, type TEXT, args TEXT);''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS servezones(id INT PRIMARY KEY, name TEXT, type TEXT, args TEXT);''')
    conn.commit()
    cursor.execute('''SELECT name, server FROM zones;''')
    result = cursor.fetchall()
    for i in result:
        i = list(i)
        if i[0] == "" or i[0] == "." or i[0] == "default":
            i[0] = "default"
        elif not i[0].endswith("."):
            i[0] += "."
        i[0] = i[0].replace("*.", "")
        zones[i[0]] = i[1]
    cursor.execute('''SELECT name, type, args FROM servezones;''')
    result = cursor.fetchall()
    for i in result:
        i = list(i)
        if not i[0].endswith("."):
            i[0] += "."
        records.append(Record(i[0], i[1], i[2]))
    cursor.execute('''SELECT name, type, args FROM cache;''')
    result = cursor.fetchall()
    for i in result:
        i = list(i)
        if not i[0].endswith("."):
            i[0] += "."
        cache.append(Record(i[0], i[1], i[2]))
    conn.close()


def dnsrequest(rname, rtype, server):
    if "https" in server or "doh" in server:
        client = requests.session()
        params = {"name": rname, "type": rtype, 'ct': 'application/dns-json'}
        try:
            resp = client.get("https://" + server.split("://")[1], params=params, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()["Answer"][0]["data"]
            else:
                logger.warning("Failed to execute DOH request (%s): %s" % (resp.status_code, resp.content))
        except Exception as e:
            logger.warning("Failed to execute DOH request: " + str(e))
    else:
        pass


if __name__ == "__main__":
    # Return help and exit
    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: %s [OPTIONS]" % sys.argv[0])
        print("Start OpenNC DNS server.\n")
        print("-c             path to the configuration file")
        print("-h, --help     display this help and exit")
        print("-v, --version  output version information and exit")
        print("-p, --port     set listening port")
        print()
        print("Full documentation and source code avaluable on https://github.com/qerty123/OpenNC") 
        print("Project distributed under GUN GPLv3 license https://www.gnu.org/licenses/gpl-3.0.html \n")
        exit()


    # Return version and exit
    if "-v" in sys.argv or "--version" in sys.argv:
        print(version)
        exit()

    # Getting settings from config file
    if "-c" in sys.argv:
        path_to_conf = sys.argv[sys.argv.index("-c") + 1]
    else:
        path_to_conf = "/etc/opennc/opennc-dns.conf" 

    if os.path.exists(path_to_conf):
        config = Config(path_to_conf)
    else:
        print("No such file or directory " + path_to_conf)
        exit()

    # Init logging
    path_to_log = config.get("log", "/var/log/opennc/opennc-dns.log")
    log_level = config.get("log_level", "WARNING")
    logger = setlogging(path_to_log, log_level)

    # Init database
    initdb(config.get("database", "/etc/opennc/opennc-dns.db"))

    # Set listening port
    if "-p" in sys.argv:
        port = int(sys.argv[sys.argv.index("-p") + 1])
    elif "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])
    else:
        port = int(config.get("port", "53"))

    timeout = int(config.get("timeout", "5"))

    resolver = Resolver(config.get("mode", "recursive"))
    if "udp" in config.get("protocol", "TCP, UDP").lower():
        udp_server = DNSServer(resolver, port=port)    
        udp_server.start_thread()
    if "tcp" in config.get("protocol", "TCP, UDP").lower():
        tcp_server = DNSServer(resolver, port=port, tcp=True) 
        tcp_server.start_thread()

    logger.info("DNS server started on port %s" % port)

    # Serving DNS requests
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass



