import subprocess
import json


# Class for editing /etc/network/interfaces
class Interfaces:
    def __init__(self):
        pass

    def getInt(self):
        ints = subprocess.run(["ip", "--json", "a"], capture_output=True)
        if ints.returncode == 0:
            return json.loads(ints.stdout.hashline.stdout.decode("UTF-8"))
        else:
            return None

    def confInt(self, type, ifname, ip, netmask, gateway, vlanint, bridgeports):
        with open("/etc/network/interfaces") as f:
            lines = f.readlines()
        if type == "dhcp":
            for i in range(len(lines) - 1):
                if "iface %s inet" % ifname in lines[i]:
                    lines[i] = "iface %s inet dhcp" % ifname
                    n = i + 1
                    while lines[n] != "":
                        lines.pop(n)
                        n = n + 1 
                        if n == len(lines) - 1:
                            break  
                    if vlanint:
                        lines.insert(i + 1, "vlan-raw-device %s" % vlanint)
                    if bridgeports:
                        directive = "bridge_ports"
                        for i in bridgeports:
                            directive += " %s" % i
                        lines.insert(i + 1, directive)
                    break                                 
        elif type == "static":
            for i in range(len(lines) - 1):
                if "iface %s inet" % ifname in lines[i]:
                    lines[i] = "iface %s inet static" % ifname
                    n = i + 1
                    while lines[n] != "":
                        lines.pop(n)
                        n = n + 1 
                        if n == len(lines) - 1:
                            break  
                    if ip and netmask and gateway:
                        lines.insert(i + 1, "address %s" % ip)
                        lines.insert(i + 2, "netmask %s" % netmask)
                        lines.insert(i + 3, "gateway %s" % gateway)
                    if vlanint:
                        lines.insert(i + 1, "vlan-raw-device %s" % vlanint)
                    if bridgeports:
                        directive = "bridge_ports"
                        for i in bridgeports:
                            directive += " %s" % i
                        lines.insert(i + 1, directive)
                    break  
        elif type == "manual":
            for i in range(len(lines) - 1):
                if "iface %s inet" % ifname in lines[i]:
                    lines[i] = "iface %s inet dhcp" % ifname
                    n = i + 1
                    while lines[n] != "":
                        lines.pop(n)
                        n = n + 1 
                        if n == len(lines) - 1:
                            break  
                    if vlanint:
                        lines.insert(i + 1, "vlan-raw-device %s" % vlanint)
                    break                     
        with open("/etc/network/interfaces") as f:
            f.write(lines)
        subprocess.run(["systemctl", "restart", "networking"], capture_output=True)

    
    def rmInt(self, ifname):
        with open("/etc/network/interfaces") as f:
            lines = f.readlines()
        for i in range(len(lines) - 1):
            if "iface %s inet static" % ifname in lines[i]:
                while lines[i] != "":
                    lines.pop(i)
                    i = i + 1 
                    if i == len(lines) - 1:
                        break  
                break   
        for i in range(len(lines) - 1):
            if ifname in lines[i]:
                lines.pop(i)                              
        with open("/etc/network/interfaces") as f:
            f.write(lines)
        subprocess.run(["systemctl", "restart", "networking"], capture_output=True)

    
    def createInt(self, type, ifname, ip, netmask, gateway, vlanint, bridgeports):
        with open("/etc/network/interfaces") as f:
            lines = f.readlines()
        lines.append("\n")
        lines.append("auto %s" % ifname)
        if type == "dhcp":   
            lines.append("iface %s inet dhcp" % ifname)
        elif type == "static":
            lines.append("iface %s inet static" % ifname)
            lines.append("address %s" % ip)
            lines.append("netmask %s" % netmask)
            lines.append("gateway %s" % gateway)
        elif type == "manual":
            lines.append("iface %s inet manual" % ifname)
        if bridgeports:
            directive = "bridge_ports"
            for i in bridgeports:
                directive += " %s" % i
            lines.append(directive)
        if vlanint:
            lines.append("vlan-raw-device %s" % vlanint)
        lines.append("\n")                           
        with open("/etc/network/interfaces") as f:
            f.write(lines)
        subprocess.run(["systemctl", "restart", "networking"], capture_output=True)


# Class for adding rules for iptables
class Firewall:
    def __init__(self):
        pass


# Class for configurating routes
class Routes:
    def __init__(self):
        pass

    def getRo(self):
        routes = subprocess.run(["ip", "--json", "route"], capture_output=True)
        if routes.returncode == 0:
            return json.loads(routes.stdout.stdout.decode("UTF-8"))
        else:
            return None

    def addRo(self, dst, gateway, metric, dev):
        command = ["ip", "route", "add", dst]
        if gateway:
            command.append("via")
            command.append(gateway)
        elif not dev:
            return None
        if metric:
            command.append("metric")
            command.append(metric)
        if not gateway:
            command.append("dev")
            command.append(dev)
        res = subprocess.run(command, capture_output=True)
        if res.returncode == 0:
            return True
        else:
            return None

    def rmRo(self, dst):
        command = ["ip", "route", "del", dst]
        subprocess.run(command, capture_output=True)


# Class for configurating vpn clients
class VPN:
    def __init__(self):
        pass




