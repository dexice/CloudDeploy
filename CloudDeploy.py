#!/usr/bin/env python3.5

#CloudDeploy.py v1
#HEPIA 2015-16 
#Stéphane Küng

import argparse         
import os               
import configparser     
import getpass          
import threading         
import time
import hashlib
from queue import Queue
import paramiko
import select
import requests

import datetime

from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver

#Color definition for the color print function (cprint)
class levels:
    reset       = "\x1b[0m"
    danger      = "\x1b[1;38;5;{0}m".format(196)
    error       = "\x1b[38;5;{0}m".format(196)
    warning     = "\x1b[38;5;{0}m".format(208)
    success     = "\x1b[38;5;{0}m".format(154)
    info        = "\x1b[38;5;{0}m".format(39)
    normal      = "\x1b[38;5;{0}m".format(27)
    surprise    = "\x1b[38;5;{0}m".format(207)
    low         = "\x1b[38;5;{0}m".format(244)
    yellow      = "\x1b[38;5;{0}m".format(226)

#color print function
def cprint(color, msg):
    t = str(datetime.datetime.now().strftime("%H%M%S"))
    print(color + t + " | " + msg + levels.reset)

#Test if a file exist and return it's realpath 
def fileExist(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file or folder '{0}' does not exist!".format(arg))
    else:
        return os.path.realpath(arg)

#The Node class, composed of a libcloud node and a configparser section.
class Node:

    staticMutexNodeCreation = threading.Lock()
    
    def __init__(self, config):
        self.config = config
        self.node = None

    def printStatus(self, indent=0):
        indent_str = " "*indent
        if self.node == None:
            cprint(levels.yellow, "{0}Node {1} is just a config file".format(indent_str,self.config.name))
        else:
            cprint(levels.yellow, "{0}Node {1} with config file {2} and IP {3}".format(indent_str,self.config.name, self.node.name, self.ip))

    def createNode(self, driver):
        if not self.node == None:
            cprint(levels.error, "Node {0} already created !!".format(self.config.name))
            return self.node

        cprint(levels.info, "creating node {0}... !!".format(self.config.name))
        
        SIZE_ID = self.config.get("SIZE_ID")
        IMAGE_ID = self.config.get("IMAGE_ID")
        NETWORK_ID = self.config.get("NETWORK_ID")

        SECURITY_GROUPS_NAMES = self.config.get("SECURITY_GROUPS_NAMES").split(",")
        KEYPAIR_NAME = self.config.get("KEYPAIR_NAME", None)

        name = self.config.name

        image = driver.getImageByID(IMAGE_ID)
        if len(image) == 0:
            cprint(levels.error, "No image with ID {0} found !".format(IMAGE_ID))
            os._exit(1)

        size = driver.getSizeByID(SIZE_ID)
        if len(size) == 0:
            cprint(levels.error, "No size with ID {0} found !".format(SIZE_ID))
            os._exit(1)

        security_groups = driver.getSecurityGroupsByNames(SECURITY_GROUPS_NAMES)
        if not len(security_groups) == len(SECURITY_GROUPS_NAMES):
            cprint(levels.error, "Some security groups are missing ! (found {0}, required {1})".format(len(security_groups),len(SECURITY_GROUPS_NAMES)))
            os._exit(1)

        networks = driver.getNetworksByID(NETWORK_ID)
        if len(networks) == 0:
            cprint(levels.error, "No network with ID {0} found !".format(NETWORK_ID))
            os._exit(1)

        cloud_init_config = ""

        cprint(levels.low, "{0}".format((name, SECURITY_GROUPS_NAMES, size[0].name, image[0].name, networks[0].name, KEYPAIR_NAME)))

        with Node.staticMutexNodeCreation:
            self.node = driver.create_node(name=name, 
                            image=image[0], 
                            size=size[0],
                            networks=networks,
                            ex_userdata=cloud_init_config, 
                            ex_config_drive=True,
                            ex_security_groups=security_groups,
                            ex_keyname=KEYPAIR_NAME)
            if not self.node:
                cprint(levels.error, "Unable to create a node... EXIT")
                os._exit(1)

            cprint(levels.success, "Node {0} created !".format(name))
            floating_ip = driver.getUnusedFloatingIP()
            if not floating_ip:
                cprint(levels.error, "Unable to get a floating IP address... EXIT")
                os._exit(1)

            self.ip = floating_ip.ip_address

            cprint(levels.low, "Set floating IP {0} to node {1}".format(self.ip, self.node.name))
            while True:
                if driver.ex_attach_floating_ip_to_node(self.node, floating_ip):
                    break
                else:
                    cprint(levels.low, "Failed setting ip {0} to node {1}, retry in one seconde...".format(self.ip, self.node.name)) 
                    time.sleep(1)

            cprint(levels.info, "IP {0} set to node {1}".format(self.ip, self.node.name))    

        return self.node

    def updateNodeInformations(self, driver, updated_nodes=None):
        cprint(levels.low, "Updating node informations...")

        if updated_nodes == None:
            (self.node,) = [node for node in driver.list_nodes() if node.id == self.node.id]
        else:
            (self.node,) = [node for node in updated_nodes if node.id == self.node.id]

    def updateNodeDNS(self, dnsUpdater):
        domain = self.config.get("DNS_HOSTNAME")
        if not domain:
            cprint(levels.low, "No domain set for {0}. Skipping...".format(self.config.name))
            return True

        try:
            ip = self.node.public_ips[0]
        except:
            cprint(levels.error, "Error, unable to get IP of {0} for DNS Update".format(self.config.name))
            return False

        return dnsUpdater.updateDNS(domain, ip)
    
    def initializeNode(self, driver):
        script = self.config.get('INITIALIZATION_SCRIPT')
        if not script:
            cprint(levels.low, "No initialization script set for {0}. Skipping...".format(self.config.name))
        else:
            self.runSSHCommand(driver, script)

    def runSSHCommand(self, driver, cmd):
        key_filename = self.config.get('KEYPAIR_FILE')
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        private_key = paramiko.RSAKey.from_private_key_file(key_filename)

        username = self.config.get('USERNAME')
        password = self.config.get('PASSWORD')

        RETRIES = 20
        WAITTIME = 5

        for n in range(RETRIES):
            try:
                
                cprint(levels.low, "Trying to connect to {0} on {1}...".format(self.node.name, self.node.public_ips[0]))
                client.connect(self.node.public_ips[0], username=username, password=password, pkey = private_key, timeout=None)

                channel = client.get_transport().open_session()
                cprint(levels.low, "{0} : {1}".format(self.node.name, cmd))
                channel.exec_command(cmd)

                while True:
                    if channel.exit_status_ready():
                        cprint(levels.low, "SSH terminated for node {0}".format(self.node.name))
                        break
                    rl, wl, xl = select.select([channel], [], [], 0.0)
                    if len(rl) > 0:
                        message = channel.recv(1024).decode("utf-8").rstrip().strip()
                        if message:
                            cprint(levels.yellow, "{0} : {1}".format(self.node.name, message))
                        if "a14671c63df56a0bbb514620" in message:
                            break
                client.close()
                break

            except (IndexError, ConnectionRefusedError, OSError) as e:
                if (n+1)>= RETRIES:
                    cprint(levels.error, "Node {0} still not ready to accept SSH connection after {1} seconds, ABORD".format(self.node.name, RETRIES*WAITTIME))
                    break
                
                cprint(levels.low, "Node {0} not ready to accept SSH connection, try {1}/{2}. Next in 5 secs".format(self.node.name,n+1,RETRIES))
                time.sleep(WAITTIME)
                self.updateNodeInformations(driver)

            except Exception as e:
                cprint(levels.error, "{0} : Error {1} : {2}".format(self.node.name, type(e), e))
                time.sleep(WAITTIME)
                self.updateNodeInformations(driver)

            finally:
                client.close()

    def installSSHKey(self, driver):
        for i in range(1,1000):
            keyname = "KEY{0}".format(i)
            key = self.config.get(keyname)
            if not key:
                cprint(levels.low, "keyname {0} not found for node {1} breaking...".format(keyname, self.node.name))
                break
            cprint(levels.info, "SSH KEY installation... {0}".format(keyname))
            self.runSSHCommand(driver, "echo '{0}' >> /home/ubuntu/.ssh/authorized_keys;".format(key.strip('"')))

    def setHostname(self, driver):
        hostname = self.config.name.strip()
        cprint(levels.info, "Setting hostname {0}".format(hostname))
        self.runSSHCommand(driver, "sudo bash -c \"echo '{0}' > /etc/hostname;\"".format(hostname))
        self.runSSHCommand(driver, "sudo bash -c \"echo '127.0.0.1  {0}' >> /etc/hosts;\"".format(hostname))
        self.runSSHCommand(driver, "sudo hostname {0}".format(hostname))


    def sendFile(self, driver, localpath, remotepath):
        if not os.path.isfile(localpath):
            raise Exception('localpath', 'not exist')

        key_filename = self.config.get('KEYPAIR_FILE')
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        private_key = paramiko.RSAKey.from_private_key_file(key_filename)

        username = self.config.get('USERNAME')
        password = self.config.get('PASSWORD')

        self.updateNodeInformations(driver)

        try:
            cprint(levels.low, "Trying to SFTP to {0}...".format(self.node.public_ips[0]))

            client.connect(self.node.public_ips[0], username=username, password=password, pkey = private_key, timeout=None)

            cprint(levels.low, "Connected to {0}...".format(self.node.public_ips[0]))
            sftp = client.open_sftp()
            cprint(levels.low, "Sending file {0} to {1}...".format(localpath, self.node.public_ips[0]))
            sftp.chdir("/home/ubuntu/")
            sftp.put(localpath, remotepath)
            #sftp.get(filepath, localpath)

            cprint(levels.low, "Closing connexion...")
            sftp.close()

        except Exception as e:
            cprint(levels.error, "Error {0} : {1}".format(type(e),e))

        finally:
            client.close()

#Class based on a list of Node
class Nodes(list):

    def createNodes(self, driver):
        self.parallelize(Node.createNode, driver)

    def printStatus(self):
        cprint(levels.yellow, "There are {0} nodes".format(len(self)))
        self.parallelize(Node.printStatus, 4)
        #for n in self:
        #    n.printStatus(indent=4)
    
    def waitUntilNodesAreRunning(self, driver):
        nodes = [n.node for n in self]

        cprint(levels.low, "waiting until {0} nodes are running...".format(len(nodes)))
        result = driver.wait_until_running(nodes, wait_period=1, timeout=60, ssh_interface='public_ips', force_ipv4=True)
        cprint(levels.success, "All {0} nodes are running".format(len(result)))

    def updateNodesInformations(self, driver):
        nodes = [n.node for n in self]
        cprint(levels.low, "updating {0} nodes informations...".format(len(nodes)))
        
        updated_nodes = driver.list_nodes()
        
        for node in [n.node for n in self]:
            node = [u_node for u_node in updated_nodes if u_node.id == node.id][0]
        
        cprint(levels.success, "All {0} nodes are updated".format(len(nodes)))
                
    def initializeNodes(self, driver):
        self.parallelize(Node.initializeNode, driver)

    def runSSHCommand(self, driver, cmd):
        self.parallelize(Node.runSSHCommand, driver, cmd)

    def setHostnames(self, driver):
        self.parallelize(Node.setHostname, driver)

    def installSSHKey(self, driver):
        self.parallelize(Node.installSSHKey, driver)

    def sendFile(self, driver, localpath, remotepath):
        self.parallelize(Node.sendFile, driver, localpath, remotepath)

    def updateNodesDNS(self, dnsUpdater):
        self.parallelize(Node.updateNodeDNS, dnsUpdater)
         
    def parallelize(self, function, *args):
        threads = []
        threads_names = []

        for node in self:
            t_name = "Thread_" + str(node.config.name)
            t_args = (node,*args)
            t = threading.Thread(target=function, name=t_name, args=t_args)
            t.start()
            threads.append(t)
            threads_names.append(t_name)
        for t in threads:
            t.join()
            threads_names.remove(t.name)
            cprint(levels.low, "thread {0} joined. Remaining threads : {1}".format(t.name, ', '.join(threads_names)))

#Class used to udate a DNS record for a node. 
#Specific to OVH Provider !
class DNSUpdater():

    def __init__(self, dnsConfig):
        self.DNS_USERNAME = dnsConfig.get('DNS_USERNAME')
        self.DNS_PASSWORD = dnsConfig.get('DNS_PASSWORD') 
        self.DNS_PROVIDER = dnsConfig.get('DNS_PROVIDER') 

    def updateDNS(self, domain, ip):
        queryArguments = {'system':'dyndns', 'hostname':domain, 'myip':ip}
        response = requests.get("https://www.ovh.com/nic/update", params=queryArguments, auth=(self.DNS_USERNAME, self.DNS_PASSWORD))
        
        txt = response.text.strip(' \t\n\r')

        if response.text.startswith('good'):
            cprint(levels.success, "Update {0} to {1} successful. Answer {2}".format(domain, ip, txt))
            return True
        else:
            cprint(levels.error, "Update {0} to {1} failed. Answer {2} : {3}".format(domain, ip, response.status_code, txt))
            return False

#Libcloud Driver
class Driver:

    mutexDriverAccess = threading.Lock()

    def __init__(self, openStackConfig):
        OPENSTACK_AUTH_URL = openStackConfig.get('OPENSTACK_AUTH_URL')
        OPENSTACK_TENANT = openStackConfig.get('OPENSTACK_TENANT') 
        OPENSTACK_REGION = openStackConfig.get('OPENSTACK_REGION') 
        OPENSTACK_AUTH_V = openStackConfig.get('OPENSTACK_AUTH_V') 

        OpenStack = get_driver(Provider.OPENSTACK)
        
        cprint(levels.info, "Connecting to {0}...".format(OPENSTACK_AUTH_URL))

        if not 'OPENSTACK_USERNAME' in openStackConfig:
            OPENSTACK_USERNAME = input("Username: ")
        else:
            print("username: {0}".format(openStackConfig["OPENSTACK_USERNAME"]))
            OPENSTACK_USERNAME = openStackConfig.get('OPENSTACK_USERNAME')
        
        if not 'OPENSTACK_PASSWORD' in openStackConfig:
            OPENSTACK_PASSWORD = getpass.getpass("Password for username {0}: ".format(OPENSTACK_USERNAME))
        else:
            print("password: *******")
            OPENSTACK_PASSWORD = openStackConfig.get('OPENSTACK_PASSWORD')

        try:
            with Driver.mutexDriverAccess:
                self.driver = OpenStack(OPENSTACK_USERNAME, OPENSTACK_PASSWORD,
                       ex_tenant_name = OPENSTACK_TENANT,
                       ex_force_auth_url= OPENSTACK_AUTH_URL,
                       ex_force_auth_version= OPENSTACK_AUTH_V,
                       ex_force_service_region= OPENSTACK_REGION)
                self.driver.list_sizes()
        except Exception as e:
            cprint(levels.error, "Error : {0}".format(e))
            exit(1)

        cprint(levels.success, "Connected :)")

    def list_sizes(self):
        with Driver.mutexDriverAccess:
            cprint(levels.low, 'list_sizes')
            return self.driver.list_sizes()

    def list_images(self):
        with Driver.mutexDriverAccess:
            cprint(levels.low, 'list_images')
            return self.driver.list_images()

    def list_nodes(self):
        with Driver.mutexDriverAccess:
            cprint(levels.low, 'list_nodes')
            return self.driver.list_nodes()

    def ex_list_networks(self):
        with Driver.mutexDriverAccess:
            cprint(levels.low, 'ex_list_networks')
            return self.driver.ex_list_networks()

    def ex_list_floating_ips(self):
        with Driver.mutexDriverAccess:
            cprint(levels.low, 'ex_list_floating_ips')
            return self.driver.ex_list_floating_ips()

    def ex_list_floating_ip_pools(self):
        with Driver.mutexDriverAccess:
            cprint(levels.low, 'ex_list_floating_ip_pools')
            return self.driver.ex_list_floating_ip_pools()

    def ex_list_security_groups(self):
        with Driver.mutexDriverAccess:
            cprint(levels.low, 'ex_list_security_groups')
            return self.driver.ex_list_security_groups()

    def wait_until_running(self, nodes, wait_period=1, timeout=60, ssh_interface='public_ips', force_ipv4=True):
        with Driver.mutexDriverAccess:
            cprint(levels.low, 'wait_until_running')
            return self.driver.wait_until_running(nodes, wait_period, timeout, ssh_interface, force_ipv4)

    def get_floating_ip_from_pools(self):
        with Driver.mutexDriverAccess:
            pool = self.driver.ex_list_floating_ip_pools()[0]
            cprint(levels.low, 'Asking pool {0} for a new IP...'.format(pool.name))
            try:
                unused_floating_ip = pool.create_floating_ip()
                cprint(levels.low, 'Got new floating IP {0} from pool {1}...'.format(unused_floating_ip.ip_address, pool.name))
                return unused_floating_ip
            except Exception as e:
                cprint(levels.error, "Driver Error {0} : {1}".format(type(e), e))
                return None
            

    def create_node(self, name, image, size, networks, ex_userdata, ex_security_groups, ex_keyname, ex_config_drive=True):
        with Driver.mutexDriverAccess:
            cprint(levels.low, 'create_node')
            try:
                return self.driver.create_node(name=name, image=image, size=size, networks=networks, ex_userdata=ex_userdata, ex_config_drive=ex_config_drive, ex_security_groups=ex_security_groups, ex_keyname=ex_keyname)
            except Exception as e:
                cprint(levels.error, "Driver Error {0} : {1}".format(type(e), e))
                return None

    def getSecurityGroupsByNames(self, names):
        groups = self.ex_list_security_groups()
        
        found = []
        for group in groups:
            if group.name in names:
                found.append(group)
        return found

    def getSizeByID(self, id):
        sizes = self.list_sizes()
        return [s for s in sizes if s.id == id]

    def getImageByID(self, id):
        images = self.list_images()
        return [i for i in images if i.id == id]
        
    def getNetworksByID(self, id):
        networks = self.ex_list_networks()
        return [n for n in networks if n.id == id]

    def getUnusedFloatingIP(self):
        cprint(levels.low, 'Checking for unused Floating IP...')
        unused_floating_ip = None
        
        list_floating_ips = self.ex_list_floating_ips()

        for floating_ip in list_floating_ips:
            if not floating_ip.node_id:
                unused_floating_ip = floating_ip
                break

        if not unused_floating_ip:
            unused_floating_ip = self.get_floating_ip_from_pools()

        return unused_floating_ip

    def ex_attach_floating_ip_to_node(self, node, floating_ip):
        with Driver.mutexDriverAccess:
            cprint(levels.low, 'ex_attach_floating_ip_to_node')
            try:
                self.driver.ex_attach_floating_ip_to_node(node, floating_ip)
                return True
            except Exception as e:
                return False

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Switch Engines Infrastructure Creator")
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    parser.add_argument("filename", help="File or folder to be hashed", metavar="FILE", type=lambda x: fileExist(parser, x))
 
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(args.filename)

    if not "OPENSTACK" in config:
        print("No OPENSTACK section found in config file")
        exit(1)

    openStackConfig = config["OPENSTACK"]
    dnsConfig = config["DNS"]

    dnsUpdater = DNSUpdater(dnsConfig)

    hostsNames = config.sections()
    hostsNames.remove('OPENSTACK')
    hostsNames.remove('DNS')
    nodes = Nodes()
    for name in hostsNames:
        node = Node(config[name])
        nodes.append(node)
    
    openStackDriver = Driver(openStackConfig)

    nodes.printStatus()

    nodes.createNodes(openStackDriver)
    
    nodes.waitUntilNodesAreRunning(openStackDriver)
    nodes.updateNodesInformations(openStackDriver)

    nodes.runSSHCommand(openStackDriver, "date")

    nodes.updateNodesDNS(dnsUpdater)

    nodes.installSSHKey(openStackDriver)

    nodes.setHostnames(openStackDriver)

    nodes.initializeNodes(openStackDriver)

    nodes.printStatus()
