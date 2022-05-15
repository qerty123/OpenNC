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

    def complete(self, text, state):
        if state == 0:
            if not text:
                self.matches = self.options[:]
            else:
                self.matches = [s for s in self.options
                                if s and s.startswith(text)]
        try:
            return self.matches[state]
        except IndexError:
            return None

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
    if com[0] == "help" or com[0] == "?":
        print("Help text") #TODO: write help
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
    elif com[0] == "show":
        pass
    elif not enabled:
        print("Unrecognized command")
        return
    elif com[0] == "config":
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
completer = OpenNCCLICompleter([])
session_id = ""
expires = 0
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
            com = input("# ")
        else:
            com = input("$ ")
        if expires > time.time():
            exec(com)
        else:
            break
    except KeyboardInterrupt:
        print("")
print("Goodbuy!")
