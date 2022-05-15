import flask
import ipaddress
import threading
import subprocess
import random
import time
import string

from logging import DEBUG
from opennccore import user_auth, logger, sessions, auth_time, version, Session
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
                date = subprocess.run(["date"], capture_output=True).stdout
                hostname = subprocess.run(["hostname"], capture_output=True).stdout
                uptime = subprocess.run(["uptime"], capture_output=True).stdout.split(" ")[1]
                osinfo = subprocess.run(["uname", "-a"], capture_output=True).stdout
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
            if user_auth(username, password):
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
                res = flask.make_response(flask.jsonify(status="ok", session_id=session_id, expires=expires, enabled=enabled))
            else:
                logger.info("Authorization failed for user %s" % username)
                res = flask.make_response(flask.jsonify(status="error"), 401)
            return res
        
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
            

    