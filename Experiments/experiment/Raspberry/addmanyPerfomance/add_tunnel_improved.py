
import paramiko

import time

class sshInfo:
    def __init__(self ,ip_address , user, password, ID_name):
      self.user = user
      self.ip_address = ip_address
      self.ID_name = ID_name
      self.password = password


name_to_sshInfo = { 
'p1': sshInfo('192.168.1.146','rasp1','reverse', 'rasp1'),
'p2': sshInfo('192.168.1.122','rasp2','reverse', 'rasp2')
}

def exec_ssh_command(sshInfo, command):
      ssh = paramiko.SSHClient()
      ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      ssh.connect(sshInfo.ip_address, username=sshInfo.user, password=sshInfo.password)
      if(command[:3]=='ovs'): command= 'sudo '+command
      stin, out, err = ssh.exec_command(command)
      #print '[exec_ssh_command (in)] %s'%(command)
      #print '[exec_ssh_command (out)] %s'%(out.readlines())
      
      #display_attr(out)
      #display_attr(err)
      if(err.read()): print '[exec_ssh_command (error)] %s !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Error'%(err.readlines())
      ssh.close()
     
exec_ssh_command(name_to_sshInfo['p1'], 'ovs-vsctl add-br foo; ovs-vsctl add-port foo tap -- set interface tap type=internal; ip netns add ns1; ip link set tap netns ns1 ; ip netns exec ns1 ifconfig tap up ; ip netns exec ns1 ifconfig tap inet 11.0.0.1 ; ip netns exec ns1 bash')

exec_ssh_command(name_to_sshInfo['p2'], 'ovs-vsctl add-br foo; ovs-vsctl add-port foo tap -- set interface tap type=internal; ip netns add ns2; ip link set tap netns ns2 ; ip netns exec ns2 ifconfig tap up ; ip netns exec ns2 ifconfig tap inet 11.0.0.2 ; ip netns exec ns2 bash')



for i in range(2,1100):
	newkey= 'secretKey'+str(i)
	newPort= 'ipsecPort'+str(i)
	unixtime= str(time.time())
	print '%s : Change keys to %s'%(unixtime, newkey)
	exec_ssh_command(name_to_sshInfo['p1'], 'ovs-vsctl add-port foo '+newPort+' -- set interface '+newPort+' type=ipsec_gre options:remote_ip=192.168.1.121 options:key='+str(i)+' options:psk=%s'%(newkey))
	exec_ssh_command(name_to_sshInfo['p2'], 'ovs-vsctl add-port foo '+newPort+' -- set interface '+newPort+' type=ipsec_gre options:remote_ip=192.168.1.143 options:key='+str(i)+' options:psk=%s'%(newkey))

	exec_ssh_command(name_to_sshInfo['p1'], 'ovs-ofctl add-flow foo in_port=1,actions:output='+str(i))
	exec_ssh_command(name_to_sshInfo['p1'], 'ovs-ofctl add-flow foo in_port='+str(i)+',actions:output=1')

	
	exec_ssh_command(name_to_sshInfo['p2'], 'ovs-ofctl add-flow foo in_port=1,actions:output='+str(i))
	exec_ssh_command(name_to_sshInfo['p2'], 'ovs-ofctl add-flow foo in_port='+str(i)+',actions:output=1')


	print '%s : Sucsessfully changed keys '%(str(time.time()))
	time.sleep(1)
	#raw_input("Press Enter to add tunnel...")


print 'Done'

