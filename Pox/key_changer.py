
import paramiko

import time

class sshInfo:
    def __init__(self ,ip_address , user, password, ID_name):
      self.user = user
      self.ip_address = ip_address
      self.ID_name = ID_name
      self.password = password


name_to_sshInfo = { 
'endc1': sshInfo('192.168.56.110','ubuntu' ,'reverse', 'endc1'),
'endc2': sshInfo('192.168.56.111','ubuntu' ,'reverse', 'endc2'),
'R1': sshInfo('192.168.56.106','ubuntu' ,'reverse', 'R1'),
'R2': sshInfo('192.168.56.107','ubuntu' ,'reverse', 'R2'),
'R3': sshInfo('192.168.56.108','ubuntu' ,'reverse', 'R3'),
'C1': sshInfo('192.168.56.101','mininet','mininet', 'C1'),
'C2': sshInfo('192.168.56.105','mininet','mininet', 'C2'),
#'p1': sshInfo('129.241.205.110','rasp1','reverse', 'rasp1'),
#'p2': sshInfo('129.241.205.101','rasp2','reverse', 'rasp2'),
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
     


for i in range(100):
	newkey= 'secretKey'+str(i)
	unixtime= str(time.time())
	print '%s : Change keys to %s'%(unixtime, newkey)
	exec_ssh_command(name_to_sshInfo['p1'], 'ovs-vsctl set interface ipsec options:psk=%s'%(newkey))
	exec_ssh_command(name_to_sshInfo['p2'], 'ovs-vsctl set interface ipsec options:psk=%s'%(newkey))

	print '%s : Sucsessfully changed keys '%(unixtime)

	#time.sleep(120)

	raw_input("Press Enter to change key...")


