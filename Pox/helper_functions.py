import paramiko
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.addresses import IPAddr, EthAddr
import time
from pprint import pprint

print '[Import helper_functions.py]'



class sshInfo:
    def __init__(self ,ip_address , user, password, ID_name):
      self.user = user
      self.ip_address = ip_address
      self.ID_name = ID_name
      self.password = password





#dpid_to_name = {16361736327753:'p1', 125497589075277 : 'p2' ,151915759872836:'C2',513:'C1',165681365082191:'R3', 222797522005066:'R1',  257735962336073:'R2', 262471379831110 :'endc1', 103723352516935 : 'endc2'}
#name_to_dpid = {'p1': 16361736327753, 'p2': 125497589075277 ,'C2': 151915759872836, 'C1': 513, 'R3': 165681365082191, 'R1': 222797522005066, 'R2': 257735962336073, 'endc1': 262471379831110, 'endc2':103723352516935 }

dpid_to_name = {16361736327753:'p1', 125497589075277 : 'p2' ,151915759872836:'C2',513:'C1',165681365082191:'R3', 282:'R1',  257735962336073:'R2', 262471379831110 :'endc1', 103723352516935 : 'endc2'}
name_to_dpid = {'p1': 16361736327753, 'p2': 125497589075277 ,'C2': 151915759872836, 'C1': 513, 'R3': 165681365082191, 'R1': 282, 'R2': 257735962336073, 'endc1': 262471379831110, 'endc2':103723352516935 }

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
'p2': sshInfo('191.168.1.122','rasp2','reverse', 'rasp2')
}

connections = {}


def print_connection_ports(connection):
  for p in connection.features.ports:
        print p.name 
        print p.port_no
        #print display_attr(p)

def print_connection_attr(connection):
  for p in connection.features.ports:
        print display_attr(p)

def display_attr(object):
  pprint (vars(object))

def gre_in_gre():
  # Create gre
  print '[Setting gre in gre]'
  create_gre_tunnel_endpoint(name_to_sshInfo['R1'], 'br0', 'gre-r1-r2', '192.168.3.5')
  exec_ssh_command(name_to_sshInfo['R1'], 'ovs-vsctl add-port br0 eth1')

  create_gre_tunnel_endpoint(name_to_sshInfo['R2'], 'br0', 'gre-r2-r1', '192.168.3.3')
  exec_ssh_command(name_to_sshInfo['R2'], 'ovs-vsctl add-port br0 eth1')

  create_gre_tunnel_endpoint(name_to_sshInfo['C1'], 'br0', 'gre-c1-c2', '192.168.2.6')
  #exec_ssh_command(name_to_sshInfo['C1'], 'ovs-vsctl add-port br0 eth1')

  create_gre_tunnel_endpoint(name_to_sshInfo['C2'], 'br0', 'gre-c2-c1', '192.168.1.2')
  
def rasp_gre_in_gre():
  # Create gre
  print '[Setting gre in gre]'
  create_gre_tunnel_endpoint(name_to_sshInfo['R1'], 'br0', 'gre-r1-r2', '192.168.3.5')
  exec_ssh_command(name_to_sshInfo['R1'], 'ovs-vsctl add-port br0 eth1')

  create_gre_tunnel_endpoint(name_to_sshInfo['R2'], 'br0', 'gre-r2-r1', '192.168.3.3')
  exec_ssh_command(name_to_sshInfo['R2'], 'ovs-vsctl add-port br0 eth1')

  create_gre_tunnel_endpoint(name_to_sshInfo['p1'], 'br0', 'gre-p1-r1', '192.168.2.6')
  #exec_ssh_command(name_to_sshInfo['C1'], 'ovs-vsctl add-port br0 eth1')

  create_gre_tunnel_endpoint(name_to_sshInfo['C2'], 'br0', 'gre-c2-c1', '192.168.1.2')
  

def ipsec_connect_gre_in_gre(connection):
  # For this to work the arp table for end-points need to be filled in both to send and  recieve

  # The mininet endswitch can only have one local connection to it
  name = dpid_to_name[connection.dpid].lower()
  print '[connecting ipsec_gre tunnel on %s]'%name
  ports = []
  
  portlist = connection.features.ports
   
  if(name == 'c1'):
    create_flow(connection, get_portnr_from_name(portlist, 'eth3'),get_portnr_from_name(portlist, 'ipsec_gre-c1-c2'))
    create_flow(connection, get_portnr_from_name(portlist, 'ipsec_gre-c1-c2'),get_portnr_from_name(portlist, 'eth3'), dst_dl_mod="08:11:11:11:1e:c1")
    print '[Added static arp entry on c1 > 192.168.2.6 00:00:00:00:01:1a]'
    
    exec_ssh_command(name_to_sshInfo['C1'], 'sudo ip route add 192.168.2.0/24 dev eth1')
    exec_ssh_command(name_to_sshInfo['C1'], 'sudo arp -s 192.168.2.6 00:00:00:00:01:1a')
  
  if(name == 'r1'):
    create_flow(connection, get_portnr_from_name(portlist, 'eth1'),get_portnr_from_name(portlist, 'ipsec_gre-r1-r2'),dst_dl_mod="22:22:22:22:22:2c")
    create_flow(connection, get_portnr_from_name(portlist, 'ipsec_gre-r1-r2'),get_portnr_from_name(portlist, 'eth1'),dst_dl_mod="00:00:00:00:00:c1")
  if(name == 'r2'):
    create_flow(connection, get_portnr_from_name(portlist, 'eth1'),get_portnr_from_name(portlist, 'ipsec_gre-r2-r1'),dst_dl_mod="00:00:00:00:01:1c")
    create_flow(connection, get_portnr_from_name(portlist, 'ipsec_gre-r2-r1'),get_portnr_from_name(portlist, 'eth1'),dst_dl_mod="00:00:00:00:00:c2")

  if(name == 'c2'):
    create_flow(connection, get_portnr_from_name(portlist, 'eth2'),get_portnr_from_name(portlist, 'ipsec_gre-c2-c1'))
    create_flow(connection, get_portnr_from_name(portlist, 'ipsec_gre-c2-c1'),get_portnr_from_name(portlist, 'eth2'),dst_dl_mod="08:22:22:22:2e:c2")
    print '[Added static arp entry on c2 > 192.168.1.2 22:22:22:22:22:2b]'
    exec_ssh_command(name_to_sshInfo['C2'], 'sudo ip route add 192.168.1.0/24 dev eth1')
    exec_ssh_command(name_to_sshInfo['C2'], 'sudo arp -s 192.168.1.2 22:22:22:22:22:2b')

def ipsec_gre_in_gre():
  # Create gre
  print '[Setting gre in gre]'

  create_gre_tunnel_endpoint(name_to_sshInfo['R1'], 'br0', 'ipsec_gre-r1-r2', '192.168.3.5', psk='hello')
  exec_ssh_command(name_to_sshInfo['R1'], 'ovs-vsctl add-port br0 eth1')

  create_gre_tunnel_endpoint(name_to_sshInfo['R2'], 'br0', 'ipsec_gre-r2-r1', '192.168.3.3', psk='hello')
  exec_ssh_command(name_to_sshInfo['R2'], 'ovs-vsctl add-port br0 eth1')

  create_gre_tunnel_endpoint(name_to_sshInfo['C1'], 'br0', 'ipsec_gre-c1-c2', '192.168.2.6', psk='hello')
  #exec_ssh_command(name_to_sshInfo['C1'], 'ovs-vsctl add-port br0 eth1')

 
  create_gre_tunnel_endpoint(name_to_sshInfo['C2'], 'br0', 'ipsec_gre-c2-c1', '192.168.1.2', psk='hello')
  #exec_ssh_command(name_to_sshInfo['C2'], 'ovs-vsctl add-port br0 eth1')

def connect_gre_in_gre(connection):
  # For this to work the arp table for end-points need to be filled in both to send and  recieve

  # The mininet endswitch can only have one local connection to it
  name = dpid_to_name[connection.dpid].lower()
  print '[connecting gre tunnel on %s]'%name
  ports = []
  
  portlist = connection.features.ports
   
  if(name == 'c1'):
    create_flow(connection, get_portnr_from_name(portlist, 'eth3'),get_portnr_from_name(portlist, 'gre-c1-c2'))

    create_flow(connection, get_portnr_from_name(portlist, 'gre-c1-c2'),get_portnr_from_name(portlist, 'eth3'), dst_dl_mod="08:11:11:11:1e:c1")
    print '[Added static arp entry on c1 > 192.168.2.6 00:00:00:00:01:1a]'
    exec_ssh_command(name_to_sshInfo['C1'], 'sudo ip route add 192.168.2.0/24 dev eth1')
    exec_ssh_command(name_to_sshInfo['C1'], 'sudo arp -s 192.168.2.6 00:00:00:00:01:1a')
  
  if(name == 'r1'):
    create_flow(connection, get_portnr_from_name(portlist, 'eth1'),get_portnr_from_name(portlist, 'gre-r1-r2'),dst_dl_mod="22:22:22:22:22:2c")
    create_flow(connection, get_portnr_from_name(portlist, 'gre-r1-r2'),get_portnr_from_name(portlist, 'eth1'),dst_dl_mod="00:00:00:00:00:c1")
  if(name == 'r2'):
    create_flow(connection, get_portnr_from_name(portlist, 'eth1'),get_portnr_from_name(portlist, 'gre-r2-r1'),dst_dl_mod="00:00:00:00:01:1c")
    create_flow(connection, get_portnr_from_name(portlist, 'gre-r2-r1'),get_portnr_from_name(portlist, 'eth1'),dst_dl_mod="00:00:00:00:00:c2")

  if(name == 'c2'):
    create_flow(connection, get_portnr_from_name(portlist, 'eth2'),get_portnr_from_name(portlist, 'gre-c2-c1'))
    create_flow(connection, get_portnr_from_name(portlist, 'gre-c2-c1'),get_portnr_from_name(portlist, 'eth2'),dst_dl_mod="08:22:22:22:2e:c2" )
    print '[Added static arp entry on c2 > 192.168.1.2 22:22:22:22:22:2b]'
    exec_ssh_command(name_to_sshInfo['C2'], 'sudo ip route add 192.168.1.0/24 dev eth1')
    exec_ssh_command(name_to_sshInfo['C2'], 'sudo arp -s 192.168.1.2 22:22:22:22:22:2b')

def connect_gre_tunnels(connection):
  portlist = connection.features.ports
  # The mininet endswitch can only have one local connection to it
  name = dpid_to_name[connection.dpid].lower()
  print '[connecting gre tunner on %s]'%name
  ports = []
  for p in connection.features.ports:
    # Last part of if added to run without mininet
    if( ('gre-%s'%(name) in p.name ) or 'br0-eth' in p.name or name == 'c1' and p.name == 'eth3' or name == 'c2' and p.name == 'eth2'):
      ports.append(p.port_no)

  if(len(ports)==2):      
    if(name== 'c1'):
      create_flow(connection, get_portnr_from_name(portlist, 'gre-c1-r1'),get_portnr_from_name(portlist, 'eth3'),dst_dl_mod="08:11:11:11:1e:c1")
      create_flow(connection, get_portnr_from_name(portlist, 'eth3'), get_portnr_from_name(portlist, 'gre-c1-r1'))
    elif(name == 'c2'):
      create_flow(connection, get_portnr_from_name(portlist, 'gre-c2-r2'),get_portnr_from_name(portlist, 'eth2'),dst_dl_mod="08:22:22:22:2e:c2")
      create_flow(connection, get_portnr_from_name(portlist, 'eth2'), get_portnr_from_name(portlist, 'gre-c2-r2'))

    else:
      create_flow(connection, ports[0],ports[1])
      create_flow(connection, ports[1],ports[0])
      print '[added flows between %s and %s on %s]'%(ports[0],ports[1],name)
  else:
    print '        [ error ] amount of ports %d'%len(ports)

def rasp_connect_gre_tunnels(connection):
  portlist = connection.features.ports
  # The mininet endswitch can only have one local connection to it
  name = dpid_to_name[connection.dpid].lower()
  print '[connecting gre tunner on %s]'%name
  ports = []
  for p in connection.features.ports:
    # Add the in port from c to openflow and the gre ports
    if( ('gre-%s'%(name) in p.name ) or  name == 'r1' and p.name == 'eth1' or name == 'r2' and p.name == 'eth1'):
      ports.append(p.port_no)

  if(len(ports)==2):      
    if(name== 'r1'):
      create_flow(connection, get_portnr_from_name(portlist, 'gre-r1-p1'),get_portnr_from_name(portlist, 'eth1'), dst_dl_mod="00:00:00:00:00:c1")
      create_flow(connection, get_portnr_from_name(portlist, 'eth1'), get_portnr_from_name(portlist, 'gre-r1-p1'))
    elif(name == 'r2'):
      create_flow(connection, get_portnr_from_name(portlist, 'gre-r2-p2'),get_portnr_from_name(portlist, 'eth1'), dst_dl_mod="00:00:00:00:00:c2")
      create_flow(connection, get_portnr_from_name(portlist, 'eth1'), get_portnr_from_name(portlist, 'gre-r2-p2'))

    else:
      create_flow(connection, ports[0],ports[1])
      create_flow(connection, ports[1],ports[0])
      print '[added flows between %s and %s on %s]'%(ports[0],ports[1],name)
  else:
    print '        [ error ] amount of ports %d'%len(ports)

def rasp_connect_ipsec_gre_tunnels(connection):
  portlist = connection.features.ports
  # The mininet endswitch can only have one local connection to it
  name = dpid_to_name[connection.dpid].lower()
  print '[connecting ipsec-gre tunner on %s]'%name
  ports = []
  for p in connection.features.ports:
    # Add the in port from c to openflow and the gre ports
    if( ('ipsec_gre-%s'%(name) in p.name ) or  name == 'r1' and p.name == 'eth1' or name == 'r2' and p.name == 'eth1'):
      ports.append(p.port_no)

  if(len(ports)==2):      
    if(name== 'r1'):
      create_flow(connection, get_portnr_from_name(portlist, 'ipsec_gre-r1-p1'),get_portnr_from_name(portlist, 'eth1'), dst_dl_mod="00:00:00:00:00:c1")
      create_flow(connection, get_portnr_from_name(portlist, 'eth1'), get_portnr_from_name(portlist, 'ipsec_gre-r1-p1'))
    elif(name == 'r2'):
      create_flow(connection, get_portnr_from_name(portlist, 'ipsec_gre-r2-p2'),get_portnr_from_name(portlist, 'eth1'), dst_dl_mod="00:00:00:00:00:c2")
      create_flow(connection, get_portnr_from_name(portlist, 'eth1'), get_portnr_from_name(portlist, 'ipsec_gre-r2-p2'))

    else:
      create_flow(connection, ports[0],ports[1])
      create_flow(connection, ports[1],ports[0])
      print '[added flows between %s and %s on %s]'%(ports[0],ports[1],name)
  else:
    print '        [ error ] amount of ports %d'%len(ports)

def get_portnr_from_name(port_list, in_port):
  
  for port in port_list:
    if(in_port == port.name ):
      return port.port_no



def gre_between_all():

  create_gre_tunnel_endpoint(name_to_sshInfo['R1'], 'br0', 'gre-r1-r2', '192.168.3.5')
  create_gre_tunnel_endpoint(name_to_sshInfo['R1'], 'br0', 'gre-r1-c1', '192.168.1.2')
  create_gre_tunnel_endpoint(name_to_sshInfo['R2'], 'br0', 'gre-r2-r1', '192.168.3.3')
  create_gre_tunnel_endpoint(name_to_sshInfo['R2'], 'br0', 'gre-r2-c2', '192.168.2.6')
  create_gre_tunnel_endpoint(name_to_sshInfo['C1'], 'br0', 'gre-c1-r1', '192.168.1.3')
  create_gre_tunnel_endpoint(name_to_sshInfo['C2'], 'br0', 'gre-c2-r2', '192.168.2.5')

def rasp_gre_between_all():
  create_gre_tunnel_endpoint(name_to_sshInfo['R1'], 'br0', 'gre-r1-p1', '129.241.205.110')
  exec_ssh_command(name_to_sshInfo['R1'], 'ovs-vsctl add-port br0 eth1')

  create_gre_tunnel_endpoint(name_to_sshInfo['R2'], 'br0', 'gre-r2-p2', '129.241.205.101')
  exec_ssh_command(name_to_sshInfo['R2'], 'ovs-vsctl add-port br0 eth1')

  create_gre_tunnel_endpoint(name_to_sshInfo['p1'], 'br0', 'gre-p1-r1', '129.241.205.104')
  create_gre_tunnel_endpoint(name_to_sshInfo['p1'], 'br0', 'gre-p1-p2', '129.241.205.101')

  create_gre_tunnel_endpoint(name_to_sshInfo['p2'], 'br0', 'gre-p2-r2', '129.241.205.108')
  create_gre_tunnel_endpoint(name_to_sshInfo['p2'], 'br0', 'gre-p2-p1', '129.241.205.110')



def rasp_to_rasp_verify_ipsec():
  print 'setting up bridge'
  
  '''
  exec_ssh_command(name_to_sshInfo['p1'], 'ovs-vsctl del-port bridge1 ipsec_gre')
  exec_ssh_command(name_to_sshInfo['p1'], 'ovs-vsctl del-port bridge1 gre')

  exec_ssh_command(name_to_sshInfo['p2'], 'ovs-vsctl del-port bridge2 ipsec_gre')
  exec_ssh_command(name_to_sshInfo['p2'], 'ovs-vsctl del-port bridge2 gre')  
  '''

  #create_gre_tunnel_endpoint(name_to_sshInfo['p1'], 'br0', 'ipsec_gre', '129.241.205.101', psk = '123', key='5647') 
  create_gre_tunnel_endpoint(name_to_sshInfo['p1'], 'br0', 'gre', '129.241.205.101', key='5648')  
  #create_gre_tunnel_endpoint(name_to_sshInfo['p1'], 'bridge1', 'gre', '129.241.205.101' )


  #create_gre_tunnel_endpoint(name_to_sshInfo['p2'], 'br0', 'ipsec_gre', '129.241.205.110',  key = '5647')
  create_gre_tunnel_endpoint(name_to_sshInfo['p2'], 'br0', 'gre', '129.241.205.110',  key = '5648')
  #create_gre_tunnel_endpoint(name_to_sshInfo['p2'], 'bridge2', 'gre', '129.241.205.110')
  print 'done connecting'


def rasp_to_rasp_double_tunnel_key_change():
  # THis setup was used to test the renewal of the keys.
  print 'setting up bridge'
  exec_ssh_command(name_to_sshInfo['p1'], 'ovs-vsctl del-port bridge1 ipsec_gre')
  exec_ssh_command(name_to_sshInfo['p1'], 'ovs-vsctl del-port bridge1 gre')

  exec_ssh_command(name_to_sshInfo['p2'], 'ovs-vsctl del-port bridge2 ipsec_gre')
  exec_ssh_command(name_to_sshInfo['p2'], 'ovs-vsctl del-port bridge2 gre')

  create_gre_tunnel_endpoint(name_to_sshInfo['p1'], 'bridge1', 'ipsec_gre', '129.241.205.101', psk = '123', key='5647') 
  create_gre_tunnel_endpoint(name_to_sshInfo['p1'], 'bridge1', 'ipsec_gre2', '129.241.205.101', psk = '1234', key='5648')  
  #create_gre_tunnel_endpoint(name_to_sshInfo['p1'], 'bridge1', 'gre', '129.241.205.101' )


  create_gre_tunnel_endpoint(name_to_sshInfo['p2'], 'bridge2', 'ipsec_gre', '129.241.205.110', psk = '123', key = '5647')
  create_gre_tunnel_endpoint(name_to_sshInfo['p2'], 'bridge2', 'ipsec_gre2', '129.241.205.110', psk = '1234', key = '5648')
  #create_gre_tunnel_endpoint(name_to_sshInfo['p2'], 'bridge2', 'gre', '129.241.205.110')


def rasp_ipsec_gre_between_all():
  create_gre_tunnel_endpoint(name_to_sshInfo['R1'], 'br0', 'ipsec_gre-r1-p1', '129.241.205.110', psk = 'hello')
  exec_ssh_command(name_to_sshInfo['R1'], 'ovs-vsctl add-port br0 eth1')

  create_gre_tunnel_endpoint(name_to_sshInfo['R2'], 'br0', 'ipsec_gre-r2-p2', '129.241.205.101', psk = 'hello')
  exec_ssh_command(name_to_sshInfo['R2'], 'ovs-vsctl add-port br0 eth1')

  create_gre_tunnel_endpoint(name_to_sshInfo['p1'], 'br0', 'ipsec_gre-p1-r1', '129.241.205.104', psk = 'hello')
  create_gre_tunnel_endpoint(name_to_sshInfo['p1'], 'br0', 'ipsec_gre-p1-p2', '129.241.205.101', psk = 'hello')

  create_gre_tunnel_endpoint(name_to_sshInfo['p2'], 'br0', 'ipsec_gre-p2-r2', '129.241.205.108', psk = 'hello')
  create_gre_tunnel_endpoint(name_to_sshInfo['p2'], 'br0', 'ipsec_gre-p2-p1', '129.241.205.110', psk = 'hello')
  
def ipsec_gre_between_all():
  create_gre_tunnel_endpoint(name_to_sshInfo['R1'], 'br0', 'ipsec_gre-r1-r2', '192.168.3.5', psk = 'hello')
  create_gre_tunnel_endpoint(name_to_sshInfo['R1'], 'br0', 'ipsec_gre-r1-c1', '192.168.1.2', psk = 'hello')
  create_gre_tunnel_endpoint(name_to_sshInfo['R2'], 'br0', 'ipsec_gre-r2-r1', '192.168.3.3', psk = 'hello')
  create_gre_tunnel_endpoint(name_to_sshInfo['R2'], 'br0', 'ipsec_gre-r2-c2', '192.168.2.6', psk = 'hello')
  create_gre_tunnel_endpoint(name_to_sshInfo['C1'], 'br0', 'ipsec_gre-c1-r1', '192.168.1.3', psk = 'hello')
  create_gre_tunnel_endpoint(name_to_sshInfo['C2'], 'br0', 'ipsec_gre-c2-r2', '192.168.2.5', psk = 'hello')
  

def clean_ports(connection, bridge):

  # Cleans out the eth on mininet Cx so it needs to restart
  for p in connection.features.ports:
  	if(p.name != 'br0' and p.name != 'br0-eth1'):
  		exec_ssh_command(name_to_sshInfo[dpid_to_name[connection.dpid]], 'ovs-vsctl del-port %s %s '%(bridge, p.name))
  		print '[        Removed %s on %s        ]'%(p.name, connection)


def clean_flows(connection):
  msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
  connection.send(msg)
  print '[        Cleaned flows on %s      '%connection

def get_mac_from_portname(event, port_name):
      ports = event.connection.ports.values()
      for p in ports:
        if(p.name == port_name):
          return str(p.hw_addr)

def connect_ends():
  # This needs to be run anytime endc1 and endc2 are talking.

    exec_ssh_command(name_to_sshInfo['endc1'], 'sudo ip route add 192.168.7.0/24 dev eth1')
    exec_ssh_command(name_to_sshInfo['endc1'], 'sudo arp -s 192.168.7.2 08:00:27:5a:27:88')
    exec_ssh_command(name_to_sshInfo['C1'], 'sudo ovs-vsctl add-port br0 eth3')


    exec_ssh_command(name_to_sshInfo['endc2'], 'sudo ip route add 192.168.6.0/24 dev eth1')
    exec_ssh_command(name_to_sshInfo['endc2'], 'sudo arp -s 192.168.6.2 08:00:27:d4:d7:2d')
    exec_ssh_command(name_to_sshInfo['C2'], 'sudo ovs-vsctl add-port br0 eth2')

def connect_raspberries():
  print 'Connect rasp'

  # Let R1 know about rasp1
  exec_ssh_command(name_to_sshInfo['R1'], 'sudo ip route add 129.241.205.0/24 dev eth3')
  exec_ssh_command(name_to_sshInfo['R1'], 'sudo arp -s 129.241.205.110 b8:27:eb:9e:77:5e')
  
  # Let R2 know about rasp2
  exec_ssh_command(name_to_sshInfo['R2'], 'sudo ip route add 129.241.205.0/24 dev eth3')
  exec_ssh_command(name_to_sshInfo['R2'], 'sudo arp -s 129.241.205.101 b8:27:eb:59:4d:60')

  # Let R2 now that the path to R1's ip is through rasp2's interface
  exec_ssh_command(name_to_sshInfo['R2'], 'sudo arp -s 129.241.205.104 b8:27:eb:59:4d:60')

  # Let R1 now that the path to R2's ip is through rasp1's interface
  exec_ssh_command(name_to_sshInfo['R1'], 'sudo arp -s 129.241.205.108 b8:27:eb:9e:77:5e')

  # Connect rasp2 to rasp1 
  exec_ssh_command(name_to_sshInfo['p2'], 'sudo arp -s 129.241.205.110 b8:27:eb:9e:77:5e')

  # Connect rasp2 to R2
  exec_ssh_command(name_to_sshInfo['p2'], 'sudo arp -s 129.241.205.108 f0:7d:68:63:b3:de')

  # Connect rasp1 to R1
  exec_ssh_command(name_to_sshInfo['p1'], 'sudo arp -s 129.241.205.104 f0:7d:68:63:b3:de')
  
  # Connect rasp1 to rasp2
  exec_ssh_command(name_to_sshInfo['p1'], 'sudo arp -s 1129.241.205.101 b8:27:eb:59:4d:60')

  # Let c1 know about c2
  exec_ssh_command(name_to_sshInfo['C1'], 'sudo ip route add 192.168.2.0/24 dev eth1')
  exec_ssh_command(name_to_sshInfo['C1'], 'sudo arp -s 192.168.2.6 00:00:00:00:01:1a')

  # Let c1 know about c2
  exec_ssh_command(name_to_sshInfo['C2'], 'sudo ip route add 192.168.1.0/24 dev eth1')
  exec_ssh_command(name_to_sshInfo['C2'], 'sudo arp -s 192.168.1.2 22:22:22:22:22:2b')




def connect_ipsec_gre_tunnels(connection):
  portlist = connection.features.ports
  # The mininet endswitch can only have one local connection to it
  name = dpid_to_name[connection.dpid].lower()
  print '[connecting gre tunner on %s]'%name
  ports = []
  for p in connection.features.ports:

    if( ('ipsec_gre-%s'%(name) in p.name ) or 'br0-eth' in p.name or name == 'c1' and p.name == 'eth3' or name == 'c2' and p.name == 'eth2'):
      ports.append(p.port_no)

  if(len(ports)==2):   
    if(name== 'c1'):
      create_flow(connection, get_portnr_from_name(portlist, 'ipsec_gre-c1-r1'),get_portnr_from_name(portlist, 'eth3'),dst_dl_mod="08:11:11:11:1e:c1")
      create_flow(connection, get_portnr_from_name(portlist, 'eth3'), get_portnr_from_name(portlist, 'ipsec_gre-c1-r1'))
    elif(name == 'c2'):
      create_flow(connection, get_portnr_from_name(portlist, 'ipsec_gre-c2-r2'),get_portnr_from_name(portlist, 'eth2'),dst_dl_mod="08:22:22:22:2e:c2")
      create_flow(connection, get_portnr_from_name(portlist, 'eth2'), get_portnr_from_name(portlist, 'ipsec_gre-c2-r2'))
    else:
      create_flow(connection, ports[0],ports[1])
      create_flow(connection, ports[1],ports[0])
      print '[added flows between %s and %s on %s]'%(ports[0],ports[1],name)
  else:
    print '      [ error ] amount of ports %d'%len(ports)

def exec_ssh_command(sshInfo, command):
      ssh = paramiko.SSHClient()
      ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      ssh.connect(sshInfo.ip_address, username=sshInfo.user, password=sshInfo.password)
      if(command[:3]=='ovs'): command= 'sudo '+command
      stin, out, err = ssh.exec_command(command)
      print '[exec_ssh_command (in)] %s'%(command)
      print '[exec_ssh_command (out)] %s'%(out.readlines())
      
      #display_attr(out)
      #display_attr(err)
      if(err.read()): print '[exec_ssh_command (error)] %s !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Error'%(err.readlines())
      ssh.close()


def create_flow(connection, in_port,out_port, src_dl_mod = None, dst_dl_mod = None, src_ip_mod = None):

        msg = of.ofp_flow_mod()
        #msg.hard_timeout=5
        msg.match = of.ofp_match(in_port = int(in_port))
        if(dst_dl_mod):
          print ' adddding the dst mod for '+dst_dl_mod
          msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(dst_dl_mod)))
        if(src_dl_mod):
          msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(src_dl_mod)))
        if(src_ip_mod):
          msg.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(src_ip_mod)))
        print msg.actions
        msg.actions.append(of.ofp_action_output(port = int(out_port)))
        
        connection.send(msg)
#def del_flows(connection):


def create_bridge(sshInfo, bridgename):
  exec_ssh_command(sshInfo,'ovs-vsctl add-br %s -- set-controller %s tcp:192.168.56.1:6635'%(bridgename,bridgename))
  print '[create_bridge] created bridge %s'%(bridgename)

def delete_bridge(sshInfo, bridgename):
  exec_ssh_command(sshInfo,'ovs-vsctl del-br %s'%(bridgename))
  print '[delete_bridge] deleted bridge %s'%bridgename


def create_gre_tunnel_endpoint(sshInfo, bridge, port_name, remote_ip, psk = None, key= None):

    commandstring= 'ovs-vsctl add-port %s %s -- set interface %s ' %(bridge,port_name,port_name)
    if(psk):
      #Creating ipsec_gre
      #Starting keyingdeamon
      exec_ssh_command(sshInfo,'sudo racoon')
      commandstring +='type=ipsec_gre options:psk=%s '%(psk)
    else:
      #Creating a gre tunnel
      commandstring +='type=gre '

    # Adding the remote ip
    commandstring += 'options:remote_ip=%s '%(remote_ip)

    # Addin a tunnel key if that is specified
    if(key):
      commandstring += 'options:key=%s '%(key)


    print 'Executing command : %s'%(commandstring)
    exec_ssh_command(sshInfo, commandstring )

    

    print '[created tunnel] Created! from %s to %s with psk %s'%(sshInfo.ID_name, remote_ip, psk)

    
def create_arp_entry(mac_reply):

  r = arp()
  #r.hwtype = a.hwtype
  #r.prototype = a.prototype
  #r.hwlen = a.hwlen
  #r.protolen = a.protolen
  r.opcode = arp.REPLY

  #hvor pakken kom fra
  r.hwdst = a.hwsrc
  r.protodst = EthAddr("00:00:00:00:00:c1")
  r.protosrc = IPAddr("192.168.1.2")
  mac = _arp_table[a.protodst].mac
  if mac is True:
    # Special case -- use ourself
    mac = _dpid_to_mac(dpid)
  r.hwsrc = mac
  
  e = ethernet(type=packet.type, src=_dpid_to_mac(dpid),
                dst=a.hwsrc)
  e.payload = r
  

  msg = of.ofp_packet_out()
  msg.data = e.pack()
  msg.actions.append(of.ofp_action_output(port =
                                          of.OFPP_IN_PORT))
  msg.in_port = inport
  event.connection.send(msg)