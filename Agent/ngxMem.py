import psutil
import bcc
import sys
import socket
import time
import json
import struct


def getQuery(measurement, pid, val):
    return '%s,item=ngx_mem,pid=%d value=%f' %(measurement, pid, val)

def getMemSize(pid):
    process = psutil.Process(pid)
    memInfo = process.memory_info()
    return memInfo.rss / 1024 / 1024


ip = sys.argv[1]
port = int(sys.argv[2])
measurement = sys.argv[3]
interval = int(sys.argv[4])
s = socket.socket()
print("measurement: %s" %(measurement))
print("mem connect %s:%d" %(ip, port))
s.connect((ip, port))

while True:
    for i in psutil.process_iter():
        if i.name() == "nginx":
            mem = getMemSize(i.pid)
            data = getQuery(measurement, i.pid, mem)
            bytes = struct.pack('>I', len(data))
            s.send(bytes)
            s.send(data.encode('ascii'))
            print(data)
    print("loop")
    time.sleep(interval)

s.close()