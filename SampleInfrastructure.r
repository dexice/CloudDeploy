[DEFAULT]
#OpenStack Default Image ID
IMAGE_ID = 0bc1f50a-5f6d-493c-925a-2ad56de169f3
#OpenStack Default Size ID
SIZE_ID = 7e7266e5-e0f8-4199-afc5-fe292630d26d
#OpenStack Default Network ID
NETWORK_ID = c34c17a4-341e-463e-ab52-eed4817387ad
#OpenStack Default Security Groups Name
SECURITY_GROUPS_NAMES = ssh
#OpenStack Default Key Name
KEYPAIR_NAME = KeyName
KEYPAIR_FILE = ./KeyName.pem
#Default Login Name
USERNAME = ubuntu
#Default Init Script
INITIALIZATION_SCRIPT = uname -a;
#SSH key to use
KEY1 = "ecdsa-sha2-nistp521 AAAAE2a78sd6fa87sd...Zlg== root@root"

[OPENSTACK]
#OpenStack Default Login informations 
#OPENSTACK_USERNAME = None
#OPENSTACK_PASSWORD = None
OPENSTACK_AUTH_URL = https://keystone.cloud.switch.ch:5000/v2.0/tokens
OPENSTACK_TENANT = Hepia
OPENSTACK_REGION = ZH
OPENSTACK_AUTH_V = 2.0_password

[DNS]
#DynDNS Login informations.
DNS_PROVIDER = NotUsed
DNS_USERNAME = Login
DNS_PASSWORD = Password

#Initialize a single instance named "one" with the default configuration
[One]

#Initialize an instance with other parameters as security groups
[Two]
SECURITY_GROUPS_NAMES = ssh,icmp,shinken,nrpe

#Use a different initialization script
[Three]
INITIALIZATION_SCRIPT = wget -O install.sh https://exemple.com/install.sh && sudo bash install.sh

#Create a web node, set the FQDN to www.exemple.com on the public IP of the node with the DynDNS provider 
[Front]
SECURITY_GROUPS_NAMES = ssh,http
INITIALIZATION_SCRIPT = wget -O install.sh https://exemple.com/install.sh && sudo bash install.sh
DNS_HOSTNAME = www.exemple.com
