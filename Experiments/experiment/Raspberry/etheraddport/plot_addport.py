import numpy as np

import matplotlib.pyplot as plt

def list_key_change_time(file):
	timelist = []
	previous = None
	for line in file.readlines():
		try: 
			
			lineList = line.split(' ')
			throughput = float(lineList[-2])
			if(lineList[-1][0] == 'M'):
				throughput = throughput*1000
		
			timelist.append(throughput)
			#print float(timelist[-1])
			
		except ValueError:
			print 'failed on' + line
			previous = None	
	return timelist
'''
file = open('iperfaddport', 'r')
result = list_key_change_time(file)
result = result[:200]
length =len(result)
unique =[]

for r in range(0, length, 1):
	unique.append(r)
#Plots the thoughput when adding ipsec ports

plt.xlabel('Time in seconds')
plt.ylabel('Throughput in Mbits/sec')
plt.plot(unique, result)
plt.show()
'''

file = open('rawFile', 'r')
result = list_key_change_time(file)
#result = result[:200]
length =len(result)
unique =[]

for r in range(0, length, 1):
	unique.append(r)
#Plots the thoughput when switching ipsec ports

fig, ax = plt.subplots()

ax.grid(True)

ax.set_xticks(np.arange(3,103,5))
plt.xlabel('Time in seconds')
plt.ylabel('Throughput in Mbits/sec')
plt.plot(unique, result)
plt.show()

