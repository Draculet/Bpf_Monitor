import psutil
import bcc
import sys
import socket
import time
import json
import struct


def getQuery(measurement, num, val):
    return '%s,item=cpu_load,cpu=cpu%d value=%f' %(measurement, num, val)

ip = sys.argv[1]
port = int(sys.argv[2])
measurement = sys.argv[3]
interval = int(sys.argv[4])
s = socket.socket()
print("measurement: %s" %(measurement))
print("cpu connect %s:%d" %(ip, port))
s.connect((ip, port))


while True:
    cpu_percent = psutil.cpu_percent(interval=interval, percpu=True)
    for idx, percent in enumerate(cpu_percent):
        data = getQuery(measurement, idx + 1, percent)
        bytes = struct.pack('>I', len(data))
        s.send(bytes)
        s.send(data.encode('ascii'))
        print(data)
        
s.close()