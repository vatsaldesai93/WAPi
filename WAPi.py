#!/usr/bin/python -tt

#Author:	Vatsal Ajay Desai
#Contact:	vatsaldesai93@gmail.com
#Version:	1.0

import subprocess,os,sys,netifaces,time,shutil
from pathlib import Path
from netfilter.rule import Rule,Match
from netfilter.table import Table

def getInstallationFiles():
	subprocess.call("apt install -y hostapd dnsmasq", shell=True)
	return

def getHotspotIP():
	eth0_iface = netifaces.ifaddresses('eth0')[netifaces.AF_INET][0]

	if not eth0_iface['addr'].startswith('10.'):
		return '10.0.0.1'
	else:
		return '192.168.1.1'

def configHostapd(apip):
	subprocess.call("update-rc.d -f hostapd remove", shell=True)
	subprocess.call("update-rc.d -f hostapd remove", shell=True)

	with open('/etc/default/hostapd','r') as f:
		data=f.readlines()
	for n,line in enumerate(data):
		if line.startswith('#DAEMON_CONF=') or line.startswith('DAEMON_CONF='):
			data[n] = 'DAEMON_CONF="/etc/hostapd/hostapd.conf"\n'
	with open('/etc/default/hostapd','w') as f:
		f.writelines(data)

	with open('/etc/dhcpcd.conf','r') as f:
		data=f.readlines()
	set_denyiface=False
	for n,line in enumerate(data):
		if (line.startswith('#denyinterfaces ') or line.startswith('denyinterfaces ')) and not set_denyiface:
			data[n] = 'denyinterfaces wlan0\n'
			set_denyiface=True
	if not set_denyiface:
		data.append('denyinterfaces wlan0\n')
	with open('/etc/dhcpcd.conf','w') as f:
		f.writelines(data)

	with open('/etc/dnsmasq.conf','r') as f:
		data=f.readlines()
	set_range=False
	set_dnsserver=False
	for n,line in enumerate(data):
		if line.startswith('#interface=') or line.startswith('interfaces='):
			data[n] = 'interface=wlan0\n'
		elif line.startswith('#listen-address=') or line.startswith('listen-address='):
			data[n] = 'listen-address='+apip+'\n'
		elif line.startswith('#bind-interfaces'):
			data[n] = 'bind-interfaces\n'
		elif line.startswith('#domain-needed'):
			data[n] = 'domain-needed\n'
		elif line.startswith('#bogus-priv'):
			data[n] = 'bogus-priv\n'
		elif line.startswith('#dhcp-range=') and not set_range:
			data[n] = 'dhcp-range='+apip+'0,'+apip+'00,12h\n'
			set_range=True
		elif line.startswith('#server=') and not set_dnsserver:
			data[n] = 'server=8.8.8.8\n'
			set_dnsserver=True
	with open('/etc/dnsmasq.conf','w') as f:
		f.writelines(data)

	ssid_name = raw_input('Enter SSID: ')
	password = raw_input('Enter password: ')

	data = ['interface=wlan0\n',
		'driver=nl80211\n',
		'ssid='+ssid_name+'\n',
		'hw_mode=g\n',
		'channel=6\n',
		'macaddr_acl=0\n',
		'auth_algs=1\n'
		'ignore_broadcast_ssid=0\n'
		'wpa=2\n'
		'wpa_passphrase='+password+'\n'
		'wpa_key_mgmt=WPA-PSK\n'
		'wpa_pairwise=TKIP\n'
		'rsn_pairwise=CCMP\n'
		'ieee80211n=1\n'
		'wmm_enabled=1\n'
		'ht_capab=[HT40][SHORT-GI-20][DSSS_CCK-40]]\n']

	with open('/etc/hostapd/hostapd.conf','w') as f:
		f.writelines(data)

def runHostapd():
	subprocess.call("ifconfig wlan0 " + apip, shell=True)
	time.sleep(2)
	subprocess.call("service dnsmasq restart", shell=True)
	time.sleep(2)
	subprocess.call("nohup hostapd -d /etc/hostapd/hostapd.conf > /dev/null 2>&1 &", shell=True)
	return

def setup_firewall_rules():
	nattable=Table('nat')
	filtable=Table('filter')

	filtable.set_policy('FORWARD','ACCEPT')

	nattable.flush_chain('POSTROUTING')
	filtable.flush_chain('FORWARD')
	filtable.flush_chain('OUTPUT')
	filtable.flush_chain('INPUT')
	#nattable.delete_chain()

	rule1=Rule(
		out_interface='eth0',
		jump='MASQUERADE')
	nattable.append_rule('POSTROUTING',rule1)

	rule2=Rule(
		in_interface='eth0',
		out_interface='wlan0',
		jump='ACCEPT',
		matches=[Match('state','--state RELATED,ESTABLISHED')])
	filtable.append_rule('FORWARD',rule2)

	rule3=Rule(
		in_interface='wlan0',
		out_interface='eth0',
		jump='ACCEPT')
	filtable.append_rule('FORWARD',rule3)

	rule4=Rule(
		out_interface='wlan0',
		jump='ACCEPT')
	filtable.append_rule('OUTPUT',rule4)

	rule5=Rule(
		in_interface='wlan0',
		jump='ACCEPT')
	filtable.append_rule('INPUT',rule5)

	with open('/etc/sysctl.conf','r') as f:
		data=f.readlines()
	for n,line in enumerate(data):
		if line.startswith('#net.ipv4.ip_forward=') or line.startswith('net.ipv4.ip_forward='):
			data[n] = 'net.ipv4.ip_forward=1\n'
	with open('/etc/sysctl.conf','w') as f:
		f.writelines(data)

	with open('/proc/sys/net/ipv4/ip_forward','w') as f:
		f.writelines('1')
	return

def revertFileChanges():
	if os.path.exists("/etc/hostapd"):
		shutil.rmtree("/etc/hostapd/")

	with open('/etc/dhcpcd.conf','r') as f:
		data=f.readlines()
	for n,line in enumerate(data):
		if (line.startswith('#denyinterfaces ') or line.startswith('denyinterfaces ')):
			data[n] = '#denyinterfaces\n'
	with open('/etc/dhcpcd.conf','w') as f:
		f.writelines(data)

	with open('/etc/sysctl.conf','r') as f:
		data=f.readlines()
	for n,line in enumerate(data):
		if line.startswith('#net.ipv4.ip_forward=') or line.startswith('net.ipv4.ip_forward='):
			data[n] = 'net.ipv4.ip_forward=0\n'
	with open('/etc/sysctl.conf','w') as f:
		f.writelines(data)

	with open('/proc/sys/net/ipv4/ip_forward','w') as f:
		f.writelines('0')
	return

def revertFirewall():
	nattable=Table('nat')
	filtable=Table('filter')

	filtable.set_policy('FORWARD','ACCEPT')

	nattable.flush_chain('POSTROUTING')
	filtable.flush_chain('FORWARD')
	filtable.flush_chain('OUTPUT')
	filtable.flush_chain('INPUT')
	#nattable.delete_chain()
	return

def stopServicesDaemons():
	subprocess.call("service hostapd stop", shell = True)
	subprocess.call("service dnsmasq stop", shell = True)
	pid_hostapd = subprocess.Popen("pgrep hostapd", shell=True, stdout=subprocess.PIPE).communicate()[0].split()
	for pid in pid_hostapd:
		subprocess.call("kill -9 "+pid, shell=True)
	return

def removePackages():
	subprocess.call("apt purge -y hostapd* dnsmasq*", shell = True)
	return

def resetInterface():
	subprocess.call("ifdown wlan0", shell = True)
	time.sleep(2)
	subprocess.call("ifup wlan0", shell = True)
	return

if __name__ == "__main__":

	if len(sys.argv) !=2 or sys.argv[1] not in ('install','uninstall'):
		print "Usage:\n"+sys.argv[0]+" install\nOR\n"+sys.argv[0]+" uninstall\n"
		sys.exit()

	if sys.argv[1] == 'install':
		apip=getHotspotIP()
		subprocess.call("ifdown wlan0 "+apip,shell=True)
		time.sleep(2)
		getInstallationFiles()
		configHostapd(apip)
		setup_firewall_rules()
		runHostapd()

	elif sys.argv[1] == 'uninstall':
		revertFileChanges()
		revertFirewall()
		stopServicesDaemons()
		removePackages()
		resetInterface()

	else:
		print 'Something went wrong!'
		sys.exit()
