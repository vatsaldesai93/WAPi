#!/usr/bin/python -tt

import subprocess,os,sys,netifaces,time,shutil
from pathlib import Path
from netfilter.rule import Rule,Match
from netfilter.table import Table
import firewalliot

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
			data[n] = 'interface=wlan0\n' #interface=lo\n'
		elif line.startswith('#listen-address=') or line.startswith('listen-address='):
			data[n] = 'listen-address='+apip+'\n' #listen-address=127.0.0.1\n'
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

	with open('/etc/network/interfaces','r') as f:
		data=f.readlines()
	for n,line in enumerate(data):
		if line.startswith('iface '):
			data[n] = '#'+line
	with open('/etc/network/interfaces','w') as f:
		f.writelines(data)


def runHostapd():
	subprocess.call("ifconfig wlan0 " + apip, shell=True)
	time.sleep(2)
	subprocess.call("service dnsmasq restart", shell=True)
	time.sleep(2)
	subprocess.call("service dhcpcd restart", shell=True)
	time.sleep(2)
	subprocess.call("nohup hostapd -d /etc/hostapd/hostapd.conf > /dev/null 2>&1 &", shell=True)
	return

def setup_ipforward_rules():
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

	set_denyiface=False
	for n,line in enumerate(data):
		if (line.startswith('#denyinterfaces ') or line.startswith('denyinterfaces ')) and not set_denyiface:
			data[n] = '#denyinterfaces \n'
			set_denyiface=True
	if not set_denyiface:
		data.append('#denyinterfaces \n')
	with open('/etc/dhcpcd.conf','w') as f:
		f.writelines(data)

	with open('/etc/sysctl.conf','r') as f:
		data=f.readlines()
	for n,line in enumerate(data):
		if line.startswith('#net.ipv4.ip_forward=') or line.startswith('net.ipv4.ip_forward='):
			data[n] = 'net.ipv4.ip_forward=0\n'
	with open('/etc/sysctl.conf','w') as f:
		f.writelines(data)

	with open('/etc/network/interfaces','r') as f:
		data=f.readlines()
	for n,line in enumerate(data):
		if line.startswith('#iface '):
			data[n] = line[1:]
	with open('/etc/network/interfaces','w') as f:
		f.writelines(data)

	with open('/proc/sys/net/ipv4/ip_forward','w') as f:
		f.writelines('0')
	return

def stopServicesDaemons():
	subprocess.call("service hostapd stop", shell = True)
	subprocess.call("service dnsmasq stop", shell = True)
#	subprocess.call("service dhcpcd stop", shell = True)
	pid_hostapd = subprocess.Popen("pgrep hostapd", shell=True, stdout=subprocess.PIPE).communicate()[0].split()
	for pid in pid_hostapd:
		subprocess.call("kill -9 "+pid, shell=True)
	return

def removePackages():
	subprocess.call("apt purge -y hostapd* dnsmasq*", shell = True)
	return

def resetInterface():
	subprocess.call("ifup wlan0", shell = True)
	time.sleep(2)
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
		firewalliot.allow_rules()
		setup_ipforward_rules()
		runHostapd()

	elif sys.argv[1] == 'uninstall':
		revertFileChanges()
		firewalliot.block_rules()
		stopServicesDaemons()
		removePackages()
		resetInterface()

	else:
		print 'Something went wrong!'
		sys.exit()
