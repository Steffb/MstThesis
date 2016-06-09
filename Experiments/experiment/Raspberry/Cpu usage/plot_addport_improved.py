import numpy as np

import matplotlib.pyplot as plt

def list_key_change_time(file):
	timelist = []
	previous = None
	for line in file.readlines():
		try: 	
			#print line
			lineList = line.split(' ')
			cpu = float(lineList[-1])
			
		
			timelist.append(cpu)
			print cpu
			
		except ValueError:
			print 'failed on' + line
			previous = None	
	return timelist

file = open('r1IpsecCpu.txt', 'r')
result = list_key_change_time(file)
#result1 = result[:200]
length =len(result)




file = open('r2IpsecCpu.txt', 'r')
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
plt.ylabel('Throughput in Kbits/sec')
plt.plot(unique, result,'r', unique, result1, 'g')
plt.show()

