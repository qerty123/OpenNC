import flask
import ipaddress
import threading
import subprocess
import random
import time
import string

from logging import DEBUG
from opennccore import user_auth, logger, sessions, auth_time, version, Session, shedule, Task, reboot, shutdown
from opennclib import Firewall, Interfaces, Routes


class Api(threading.Thread):
    def configure(self, host, port, permit_ip, context):
        self.host = host
        self.port = port
        self.permit_ip = permit_ip
        self.app = flask.Flask(__name__)
        self.app.logger.setLevel(DEBUG)
        self.ssl_context = context
        self.set_routes()

    def check_permit_ip(self, func):
        def wrapper(*args, **kwargs):
            if self.permit_ip:
                if not (ipaddress.ip_address(flask.request.remote_addr) in self.permit_ip or ipaddress.ip_address(flask.request.remote_addr).is_loopback):
                    logger.debug("Request from denide ip %s" % flask.request.remote_addr)
                    return flask.make_response("403 Forbidden", 403)
            else:
                if not (ipaddress.ip_address(flask.request.remote_addr).is_private or ipaddress.ip_address(flask.request.remote_addr).is_loopback):
                    logger.debug("Request from denide ip %s" % flask.request.remote_addr)
                    return flask.make_response("403 Forbidden", 403)             
            res = func(*args, **kwargs)
            return res       
        wrapper.__name__ = func.__name__         
        return wrapper
    
    def check_auth(self, func):
        def wrapper(*args, **kwargs):
            session_id = flask.request.cookies.get("session_id")
            if not session_id:
                logger.debug("Unuthorized request from %s" % flask.request.remote_addr)
                return flask.make_response("401 Unauthorized", 401)
            for i in sessions:
                if i.session_id == session_id:
                    if i.expired > time.time():
                        break
                    else:
                        sessions.remove(i)
            else: 
                logger.debug("Unuthorized request from %s" % flask.request.remote_addr)           
                return flask.make_response("401 Unauthorized", 401)
            res = func(*args, **kwargs)
            return res
        wrapper.__name__ = func.__name__
        return wrapper
    
    def run(self):
        if self.ssl_context:
            self.app.run(self.host, self.port, ssl_context=self.ssl_context)
        else:
            self.app.run(self.host, self.port)    
    
    def set_routes(self):
        @self.app.route("/api/check", methods=["GET"])  
        @self.check_permit_ip      
        def check():
            try:
                date = subprocess.run(["date"], capture_output=True).stdout.decode("UTF-8")
                hostname = subprocess.run(["hostname"], capture_output=True).stdout.decode("UTF-8")
                uptime = subprocess.run(["uptime"], capture_output=True).stdout.decode("UTF-8").split(" ")[1]
                osinfo = subprocess.run(["uname", "-a"], capture_output=True).stdout.decode("UTF-8")
                return flask.make_response(flask.jsonify(status="ok", date=date, uptine=uptime, hostname=hostname, version=version, os=osinfo))
            except Exception as e:
                return flask.make_response(flask.jsonify(status="warning"))
        
        @self.app.route("/api/login", methods=["POST"])
        @self.check_permit_ip
        def login():
            content = flask.request.json
            username = content["username"]
            password = content["password"]
            ip = content["ip"]
            if ip == "127.0.0.1" and password.split(":")[0] == "localkey":
                with open("/tmp/opennckey", "r") as f:
                    key = f.read()
                if key == password.split(":")[1]:
                    logger.info("Succesfull authorization for user %s" % username)
                    if username == "root":
                        enabled = True
                    else:
                        enabled = False
                    session_id = ""
                    for i in range(50):
                        session_id += random.choice(string.ascii_lowercase + "01234567890" + "!@#$%^&*()_-=+")
                    expires = time.time() + auth_time
                    sessions.append(Session(session_id, ip, username, expires, enabled))
                    return flask.make_response(flask.jsonify(status="ok", session_id=session_id, expires=expires, enabled=enabled))   
            elif user_auth(username, password):
                logger.info("Succesfull authorization for user %s" % username)
                if username == "root":
                    enabled = True
                else:
                    enabled = False
                session_id = ""
                for i in range(50):
                    session_id += random.choice(string.ascii_lowercase + "01234567890" + "!@#$%^&*()_-=+")
                expires = time.time() + auth_time
                sessions.append(Session(session_id, ip, username, expires, enabled))
                return flask.make_response(flask.jsonify(status="ok", session_id=session_id, expires=expires, enabled=enabled))            
            logger.info("Authorization failed for user %s" % username)
            return flask.make_response(flask.jsonify(status="error"), 401)
        
        @self.app.route("/api/logout", methods=["POST"])
        @self.check_permit_ip
        @self.check_auth
        def logout():
            content = flask.request.json
            session_id = content["session_id"]
            for i in sessions:
                if i.session_id == session_id:
                    sessions.remove(i)
            res = flask.make_response(flask.jsonify(status="ok"))
            return res


        @self.app.route("/", methods=["GET"])
        @self.check_permit_ip
        @self.check_auth
        def root():
            flask.make_response("400 Bad Request", 400) 

        @self.app.route("/api", methods=["GET"])
        @self.check_permit_ip
        @self.check_auth
        def root():
            flask.make_response("400 Bad Request", 400) 
        
        @self.app.route("/api/enable", methods=["POST"])
        @self.check_permit_ip
        @self.check_auth
        def enable():
            content = flask.request.json
            password = content["password"]
            session_id = flask.request.cookies.get("session_id")
            for i in sessions:
                if i.session_id == session_id:
                    session = i                    
            if user_auth("root", password):
                session.enabled = True
                logger.info("User %s enter to the priveledged mode" % session.login)
                res = flask.make_response(flask.jsonify(status="ok"), 200)
            else:
                logger.info("Failed to use priveledged mode for user " % session.login)
                res = flask.make_response(flask.jsonify(status="error"), 401)
            return res
            
        @self.app.route("/api/getint", methods=["GET"])
        @self.check_permit_ip
        @self.check_auth
        def getInt():
            ints = Interfaces.getInt()
            if ints:
                res = flask.make_response(flask.jsonify(status="ok", interfaces=ints), 200)
            else:
                res = flask.make_response(flask.jsonify(status="error"), 500)
                logger.warning("Couldnt get list of interfaces")
            return res

        @self.app.route("/api/confint", methods=["POST"])
        @self.check_permit_ip
        @self.check_auth
        def confInt():
            pass

        @self.app.route("/api/rmint", methods=["POST"])
        @self.check_permit_ip
        @self.check_auth
        def rmInt():
            pass

        @self.app.route("/api/createint", methods=["POST"])
        @self.check_permit_ip
        @self.check_auth
        def createInt():
            pass

        @self.app.route("/api/getcpu", methods=["GET"])  
        @self.check_permit_ip     
        @self.check_auth 
        def getcpu():
            try:
                lscpu = subprocess.run(["lscpu"], capture_output=True).stdout.decode("UTF-8")
                for i in lscpu:
                    if "Architecture" in i:
                        arch = i.split()[1]
                    if "CPU(s)" in i:
                        cores = i.split()[1]
                    if "Model name" in i:
                        model = i.split()[1:]
                    if "CPU max MHz" in i:
                        freq = i.split()[1]
                la = subprocess.run(["uptime"], capture_output=True).stdout.decode("UTF-8").split()[7]
                return flask.make_response(flask.jsonify(status="ok", arch=arch, cores=cores, model=model, freq=freq, la=la))
            except Exception as e:
                return flask.make_response(flask.jsonify(status="warning"))

        @self.app.route("/api/getmemory", methods=["GET"])  
        @self.check_permit_ip     
        @self.check_auth 
        def getmemory():
            try:
                # total_mem, alail_mem, total_swap, free_swap
                free = subprocess.run(["free"], capture_output=True).stdout.decode("UTF-8").split()
                total_mem = free[7]
                free_mem = free[12]
                total_swap = free[14]
                free_swap = free[16]
                return flask.make_response(flask.jsonify(status="ok", total_mem=total_mem, free_mem=free_mem, total_swap=total_swap, free_swap=free_swap))
            except Exception as e:
                return flask.make_response(flask.jsonify(status="warning"))

        @self.app.route("/api/reboot", methods=["POST"])  
        @self.check_permit_ip     
        @self.check_auth 
        def reboot():
            content = flask.request.json
            time = int(content["time"]) * 60
            shedule.append(Task(time, reboot))
            return flask.make_response(flask.jsonify(status="ok"))

        @self.app.route("/api/shutdown", methods=["POST"])  
        @self.check_permit_ip     
        @self.check_auth 
        def reboot():
            content = flask.request.json
            time = int(content["time"]) * 60
            shedule.append(Task(time, shutdown))
            return flask.make_response(flask.jsonify(status="ok"))




    