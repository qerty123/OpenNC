#!/usr/bin/python3

import configparser
import logging
import os
import threading
import time
import sys
import subprocess
import ipaddress
import OpenSSL
import openncapi
import sqlite3
import opennclib
import requests

# Global variables
version = "0.1.2"
shedule = []
stat = None
sessions = []
auth_time = None
conn = None
logger = None
queues = []
rules = []
params = []
routes = []

# Class for sheduled tasks storaging
class Task:
    def __init__(self, period, task):
        self.period = period
        self.task = task
        self.lastrun = time.time()


# Collecting statistic
class Stat:
    def __init__(self):
        self.la = {}
        self.avail_mem = {}
        self.free_swap = {}
    
    def get_stat(self):
        resp = []
        uptime = subprocess.run(["uptime"], capture_output=True)
        if uptime.returncode == 0:
            uptime = uptime.stdout.decode("UTF-8").split()
            resp.append(uptime[0])
            resp.append(uptime[7][:-1])
        else:
            resp.append("")
            resp.append("")
        free = subprocess.run(["free"], capture_output=True)
        if free.returncode == 0:
            free = free.stdout.decode("UTF-8").split()
            resp.append(free[7])
            resp.append(free[12])
            resp.append(free[14])
            resp.append(free[16])
        else:
            resp.append()
            resp.append()
            resp.append()
            resp.append()
        # uptime, la_1m, total_mem, alail_mem, total_swap, free_swap
        return resp

    def collect_stat(self):
        stat = self.get_stat()
        self.la[time.time()] = stat[1]
        self.avail_mem[time.time()] = stat[3]
        self.free_swap[time.time()] = stat[5]
        logger.debug("Statisctic collected")
    
    def clear(self):
        pass


# Class for containing auth sessions
class Session:
    def __init__(self, session_id, ip, login, expired, enabled):
        self.session_id = session_id
        self.ip = ip
        self.login = login
        self.expired = expired
        self.enabled = enabled


# Set cycled shedule execution
class Sheduling(threading.Thread):
    def run(self):
        while True:
            for i in shedule:
                if time.time() - i.lastrun > i.period:
                    i.task()
                    i.lastrun = time.time()
            time.sleep(1)


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


# Check is passwd correct
def user_auth(login, passwd):
    shadow = open("/etc/shadow")
    for i in shadow.readlines():
        if i.split(":")[0] == login:
            if i.split(":")[1] != "!" or i.split(":")[1] != "*":
                method = i.split(":")[1].split("$")[1]
                salt = i.split(":")[1].split("$")[2]
                hashline = subprocess.run(["openssl", "passwd", "-%s" % method, "-salt", salt, passwd], capture_output=True)
                if hashline.returncode == 0 and i.split(":")[1] == hashline.stdout.decode("UTF-8").replace("\n", ""):
                    return True
                else:
                    return False
            else:
                return False
    return False


# Create request to database to queue
def getDBData(path_to_db):
    conn = sqlite3.connect(path_to_db)
    cursor = conn.cursor()
    command = '''CREATE TABLE IF NOT EXISTS queues (id INT PRIMARY KEY, ifname TEXT, queue TEXT);'''
    cursor.execute(command)
    command = '''CREATE TABLE IF NOT EXISTS rules (id INT PRIMARY KEY, type TEXT, queueid INT, src TEXT, dst TEXT, proto TEXT, port INT, action INT, rule TEXT);'''
    cursor.execute(command)
    command = '''CREATE TABLE IF NOT EXISTS params (id INT PRIMARY KEY, name TEXT, value TEXT);'''
    cursor.execute(command)
    command = '''CREATE TABLE IF NOT EXISTS routes (id INT PRIMARY KEY, dst TEXT, gateway TEXT, metric INT, dev TEXT);'''
    cursor.execute(command)
    conn.commit()
    cursor.execute('''SELECT * FROM queues;''')
    queues = cursor.fetchall()
    cursor.execute('''SELECT * FROM rules;''')
    rules = cursor.fetchall()
    cursor.execute('''SELECT * FROM params;''')
    params = cursor.fetchall()
    cursor.execute('''SELECT * FROM routes;''')
    routes = cursor.fetchall()
    cursor.close()
    conn.close()


if __name__ == "__main__":
    # Return help and exit
    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: %s [OPTIONS]" % sys.argv[0])
        print("Start OpenNC core controller for web interface and CLI host.\n")
        print("-c             path to the configuration file")
        print("-h, --help     display this help and exit")
        print("-v, --version  output version information and exit")
        print()
        print("Full documentation and source code avaluable on https://github.com/qerty123/OpenNC") 
        print("Project distributed under GUN GPLv3 license https://www.gnu.org/licenses/gpl-3.0.html \n")
        exit()


    # Return version and exit
    if "-v" in sys.argv or "--version" in sys.argv:
        print(version)
        exit()


    # Check is runnging from root
    if os.getegid() != 0:
        print("No permission to run from this user")
        exit()

    # Getting settings from config file
    if "-c" in sys.argv:
        path_to_conf = sys.argv[sys.argv.index("-c") + 1]
    else:
        path_to_conf = "/etc/opennc/opennc-core.conf" 

    if os.path.exists(path_to_conf):
        config = Config(path_to_conf)
    else:
        print("No such file or directory " + path_to_conf)
        exit()

    # Init logging
    path_to_log = config.get("log", "/var/log/opennc/opennc-core.log")
    log_level = config.get("log_level", "WARNING")
    logger = setlogging(path_to_log, log_level)

    logger.info("Core is started")

    # Init sheduling
    sheduling = Sheduling()
    sheduling.start()
    logger.info("Shedule is running")

    # Get settings from DB
    getDBData(config.get("database", "/etc/opennc/opennc.db"))

    # Set firewall rules
    firewall = opennclib.Firewall()
    firewall.flushRules()
    for i in params:
        if i[1] == "natIntID":
            dstInt = None
            for t in queues:
                if t[0] == i[2]:
                    dstInt = t[1]
            firewall.setNat(dstInt)
        elif i[1] == "squidIntID":
            srcInt = None
            for t in queues:
                if t[0] == i[2]:
                    srcInt = t[1]
            toports = ""
            for t in params:
                if t[1] == "squidToPorts":
                    toports = t[2]
            firewall.enableSquid(srcInt, toports)


    # id INT PRIMARY KEY, type TEXT, queueid INT, src TEXT, dst TEXT, proto TEXT, port INT, action INT, rule TEXT
    for i in rules:
        if i[1] == "default":
            srcInt = None
            for t in queues:
                if t[0] == i[2]:
                    srcInt = t[1]
            firewall.addRule("FORWARD", i[7], srcInt, None, i[3], i[4], i[5])
        elif i[1] == "processed":
            if len(i[3]) == 2:
                responce = requests.get("https://stat.ripe.net/data/country-resource-list/data.json?resource=%s" % i[3])
                if responce.status_code == 200:
                    src = []
                    for t in responce.json()["data"]["resources"]["ipv4"]:
                        if not ":" in t:
                            src.append(t)
                else:
                    logger.warning("Failed to get list of networks of %s" % i[3])
                    src = None
            elif i[3][0:2] == "AS":
                responce = requests.get("https://stat.ripe.net/data/as-routing-consistency/data.json?resource=%s" % i[3])
                if responce.status_code == 200:
                    src = []
                    for t in responce.json()["data"]["prefixes"]:
                        if not ":" in t["prefix"]:
                            src.append(t["prefix"])
                else:
                    logger.warning("Failed to get list of networks of %s" % i[3])
                    src = None
            else:
                src = [i[3]]
            if len(i[4]) == 2:
                responce = requests.get("https://stat.ripe.net/data/country-resource-list/data.json?resource=%s" % i[4])
                if responce.status_code == 200:
                    dst = []
                    for t in responce.json()["data"]["resources"]["ipv4"]:
                        if not ":" in t:
                            dst.append(t)
                else:
                    logger.warning("Failed to get list of networks of %s" % i[4])
                    dst = None
            elif i[4][0:2] == "AS":
                responce = requests.get("https://stat.ripe.net/data/as-routing-consistency/data.json?resource=%s" % i[4])
                if responce.status_code == 200:
                    dst = []
                    for t in responce.json()["data"]["prefixes"]:
                        if not ":" in t["prefix"]:
                            dst.append(t["prefix"])
                else:
                    logger.warning("Failed to get list of networks of %s" % i[4])
                    dst = None
            else:
                dst = [i[4]]
            srcInt = None
            for t in queues:
                if t[0] == i[2]:
                    srcInt = t[1]            
            for sr in src:
                for ds in dst:
                    firewall.addRule("FORWARD", i[7], srcInt, None, sr, ds, i[5])           
        elif i[1] == "text":
            subprocess.run([i[7]], capture_output=True)
        else:
            logger.warning("Failed to set firewall rule: %s" % i)
    
    # Init api    
    # Find avaluable subnets for control
    permit_ip = config.get("permit_ip")
    try:
        if permit_ip:
            ips = []
            permit_ip = permit_ip.replace(" ", ",").replace(";", ",").split(",")
            for i in permit_ip:
                if "/" in i:
                    ips.append(ipaddress.ip_network(i))
                else:
                    ips.append(ipaddress.ip_address(i))
            permit_ip = ips
    except Exception as e:
        logger.warn("Failed to read avaluable networks: %s" % e)
        permit_ip = None
    # Find session lifetime
    auth_time = config.get("auth_time", "3600")
    if auth_time.isdigit():
        auth_time = int(auth_time)
    elif auth_time[-1].lower() == "m" and auth_time[:-1].isdigit():
        auth_time = int(auth_time[:-1]) * 60
    elif auth_time[-1].lower() == "s" and auth_time[:-1].isdigit():
        auth_time = int(auth_time[:-1]) * 1
    elif auth_time[-1].lower() == "h" and auth_time[:-1].isdigit():
        auth_time = int(auth_time[:-1]) * 3600
    elif auth_time[-1].lower() == "d" and auth_time[:-1].isdigit():
        auth_time = int(auth_time[:-1]) * 86400
    else:
        auth_time = 3600
        logger.warning("Failed to parse 'auth_time' parametr")
    # Loading SSL certificate and private key for https
    key = config.get("privatekey")
    cert = config.get("certificate")
    if key and cert:
        try:
            context = OpenSSL.SSL.Context(OpenSSL.SSL.PROTOCOL_TLSv1_2)
            context.use_privatekey_file(key)
            context.use_certificate_file(cert)   
        except Exception as e:
            logger.error("Failed to load SSL certificate")
            context = None
    else:
        context = None
    # Creating API workers
    for i in range(int(config.get("api_workers", "1")) - 1):
        api = openncapi.Api()
        api.configure(config.get("api_host", "0.0.0.0"), int(config.get("api_port", "43581")), permit_ip, context)
        api.start()
    logger.info("Api is running")

    # Create statistic collector
    #stat = Stat()

    # Add tasks
    #shedule.append(Task(60, stat.collect_stat))


    ########





