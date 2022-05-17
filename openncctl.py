#!/usr/bin/python3

import requests
import readline
import sys
import subprocess
import configparser
import time
import random
import string
from os import environ


class OpenNCCLICompleter(object):
    def __init__(self, options):
        self.options = options
        self.current_candidates = []
        return

    def complete(self, text, state):
        response = None
        if state == 0:
            origline = readline.get_line_buffer()
            begin = readline.get_begidx()
            end = readline.get_endidx()
            being_completed = origline[begin:end]
            words = origline.split()

            if not words:
                self.current_candidates = sorted(self.options.keys())
            else:
                try:
                    if begin == 0:
                        candidates = self.options.keys()
                    else:
                        first = words[0]
                        candidates = self.options[first]
                    
                    if being_completed:
                        self.current_candidates = [ w for w in candidates
                                                    if w.startswith(being_completed) ]
                    else:
                        self.current_candidates = candidates
                except IndexError as err:
                    self.current_candidates = []
                except KeyError as err:
                    self.current_candidates = []                                
        try:
            response = self.current_candidates[state]
        except IndexError:
            response = None
        return response

    """
    def display_matches(self, substitution, matches, longest_match_length):
        line_buffer = readline.get_line_buffer()
        columns = environ.get("COLUMNS", 80)

        print()

        tpl = "{:<" + str(int(max(map(len, matches)) * 1.2)) + "}"

        buffer = ""
        for match in matches:
            match = tpl.format(match[len(substitution):])
            if len(buffer + match) > columns:
                print(buffer)
                buffer = ""
            buffer += match

        if buffer:
            print(buffer)

        print("> ", end="")
        print(line_buffer, end="")
        sys.stdout.flush()
    """


class Config:
    def __init__(self):
        try:
            conf_str = "[default]\n" + open("/etc/opennc/opennc-core.conf", "r").read().replace("[", "").replace("]", "")
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


def exec(com):
    com = com.split(" ")
    if com[0] == "":
        return
    elif com[0] == "help" or com[0] == "?":
        print("") #TODO: write help
    elif com[0] == "logout":
        exit(0)
    elif com[0] == "exit" or com[0] == "quit":
        if enabled:
            enabled = False
        else:
            requests.post("%s/api/logout" % reqaddr, json={"session_id": session_id}, cookies={"session_id": session_id})
    elif com[0] == "en" or com[0] == "enable":
        pas = input("Password: ")
        responce = requests.post("%s/api/enable" % reqaddr, json={"password": pas})
        if responce.status_code == 200:
            enabled = True
        else:
            print("Wrong password. This incident will be logged")
    elif com[0] == "ssh":
        subprocess.run(com)
    elif com[0] == "resque":
        subprocess.run(["/bin/bash"])
    elif com[0] == "show":
        if len(com) == 1:
            print("Unrecognized command")             
        elif com[1] == "version":
            responce = requests.get("%s/api/check" % reqaddr, cookies={"session_id": session_id})
            if responce.status_code == 200 and responce.json()["status"] == "ok":
                print(responce.json()["hostname"])
                print("OS version: " + responce.json()["os"])
                print("OpenNC controller version: " + responce.json()["version"])
                print("Node uptime: " + responce.json()["uptime"])
                print("Local time: " + responce.json()["date"])
            else:
                print("Node in the warning status")
        elif com[1] == "ports" or com[1] == "int" or com[1] == "port" or com[1] == "interface":
            if len(com) == 2:
                responce = requests.get("%s/api/getint" % reqaddr, cookies={"session_id": session_id})
                if responce.status_code == 200 and responce.json()["status"] == "ok":
                    print("   Interface   Status          MAC           Address")
                    for i in responce.json()["interfaces"]:
                        text = '{0: <15}'.format(i["ifname"])
                        text += '{0: <6}'.format(i["operstate"])
                        text += '{0: <22}'.format(i["address"])
                        if len(i["addr_info"]) != 0:
                            text += i["addr_info"][0]["local"] + "/" + i["addr_info"][0]["prefixlen"]
                        print(text)
            else:
                responce = requests.get("%s/api/getint" % reqaddr, cookies={"session_id": session_id})
                if responce.status_code == 200 and responce.json()["status"] == "ok":                    
                    for i in responce.json()["interfaces"]:
                        if i["ifname"] == com[3].lower():
                            print("   Interface   Status          MAC           Address")
                            text = '{0: <15}'.format(i["ifname"])
                            text += '{0: <6}'.format(i["operstate"])
                            text += '{0: <22}'.format(i["address"])
                            if len(i["addr_info"]) != 0:
                                text += i["addr_info"][0]["local"] + "/" + i["addr_info"][0]["prefixlen"]
                            print(text)
                            return
                    print("No such interface")
        elif com[1] == "cpu":
            responce = requests.get("%s/api/getcpu" % reqaddr, cookies={"session_id": session_id})
            if responce.status_code == 200 and responce.json()["status"] == "ok":
                print(responce.json()["model"])
                print(responce.json()["arch"] + "(%sx%s cores)" % (responce.json()["cores"], responce.json()["freq"]))
                persus = int(responce.json()["la"]) / int(responce.json()["cores"]) * 100
                print("Current load: " + responce.json()["la"] + "(%s%)" % persus)
            else:
                print("Node in the warning status")
        elif com[1] == "mem" or com[1] == "memory":
            responce = requests.get("%s/api/getmemory" % reqaddr, cookies={"session_id": session_id})
            if responce.status_code == 200 and responce.json()["status"] == "ok":
                print("Memory usage: " + (int(responce.json()["total_mem"]) - int(responce.json()["free_mem"])) + "/" + responce.json()["total_mem"])
                print("Swap usage: " + (int(responce.json()["total_swap"]) - int(responce.json()["free_swap"])) + "/" + responce.json()["total_swap"])
            else:
                print("Node in the warning status")
        else:
            print("Unrecognized command")
    elif not enabled:
        print("Unrecognized command")        
    elif com[0] == "reload":
        if len(com) != 3:
            print("When to reboot server?")
        else:
            responce = requests.post("%s/api/reboot" % reqaddr, json={"time": com[3]}, cookies={"session_id": session_id})
    elif com[0] == "shutdown":
        if len(com) != 3:
            print("When to shutdown server?")
        else:
            responce = requests.post("%s/api/shutdown" % reqaddr, json={"time": com[3]}, cookies={"session_id": session_id})
    elif com[0] == "config" or com[0] == "conf":
        pass
    elif com[0] == "delete" or com[0] == "del":
        pass
    else:
        print("Unrecognized command")


def resque():
    com = input("Node in the critical status. Enter the resque mode? [y/N]").lower()
    if com == "y" or com == "yes":
        subprocess.run(["/bin/bash"])
        exit(0)
    else:
        exit(0)


enabled = False
config = Config()
# TODO: change autocomlete
completer = OpenNCCLICompleter({"enable": [], "exit": [], "logout": [], "ssh": [], "resque": [], \
    "reload": ["in"], "shutdown": ["in"], \
    "show": ["version", "interface", "ports", "cpu", "memory"], \
    "config": ["interface", "ip"] \
    })
session_id = ""
expires = 0
prefix = subprocess.run(["hostname"], capture_output=True).stdout.decode("UTF-8")
user = subprocess.run(["id", "-u", "-n"], capture_output=True).stdout.decode("UTF-8")
readline.set_completer(completer.complete)
readline.parse_and_bind('tab: complete')
#readline.set_completion_display_matches_hook(completer.display_matches)
host = config.get("api_host", "0.0.0.0")
if host == "0.0.0.0":
    host = "127.0.0.1"
port = config.get("api_port", "43581")
if config.get("privatekey", None) and config.get("certificate", None):
    proto = "https"
else:
    proto = "http"
reqaddr = "%s://%s:%s" % (proto, host, port)


print("Welcome to local node with OpenNC")
try:
    responce = requests.get("%s://%s:%s/api/check" % (proto, host, port))
except Exception as e:
    resque()
if responce.status_code != 200:
    resque()
else:
    if responce.json()["status"] != "ok":  
        print("Node in the warning status")
    try:
        localkey = ""
        for i in range(50):
            localkey += random.choice(string.ascii_lowercase + "01234567890" + "!@#$%^&*()_-=+")
        with open("/tmp/opennckey", "w") as f:
            f.write(localkey)
        responce = requests.post("%s/api/login" % reqaddr, json={"username": user, "password": "localkey:%s" % localkey, "ip": "127.0.0.1"})
        if responce.status_code != 200:
            resque()
        else:
            session_id = responce.json()["session_id"]
            expires = responce.json()["expires"]
            enabled = responce.json()["enabled"]
    except Exception as e:
        resque()

while True:
    try:
        if enabled:
            com = input(prefix + "# ")
        else:
            com = input(prefix + "$ ")
        if expires > time.time():
            try:
                exec(com.lower())
            except Exception as e:
                print("Error: " + e)
        else:
            break
    except KeyboardInterrupt:
        print("")
print("Goodbuy!")
