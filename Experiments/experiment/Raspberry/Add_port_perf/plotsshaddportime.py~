import numpy

import matplotlib.pyplot as plt

def list_key_change_time(file):
	timelist = []
	previous = None
	for line in file.readlines():
		try: 
		
			timestamp=  int(line[:10])
		
			if(previous != None):
				difference =  timestamp - previous
				if(difference>3):
					timelist.append(difference)
		
			previous = timestamp
		except ValueError:
			print 'failed on' + line[:10]
			previous = None	
	return timelist

file = open('change key', 'r')
result = list_key_change_time(file)

# To remove the time the script waited beteen changes
for i in range(len(result)):
	result[i]=result[i]-5

print len(result)
unique =[]
result = sorted(result)
for r in range(0, result[-1], 1):
	unique.append(r)

plt.xlabel('Time in seconds')
plt.ylabel('Number of times used')

plt.hist(result, bins=unique)
plt.show()


