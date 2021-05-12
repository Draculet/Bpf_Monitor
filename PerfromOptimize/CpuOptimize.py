import psutil

def bindCpu():
    cpu_percent = psutil.cpu_percent(interval=None, percpu=True)
    cpunum = len(cpu_percent)
    cpunum = 8
    arr = []
    s = ""
    for i in range(cpunum):
        for j in range(cpunum):
            if len(s) == (cpunum - i - 1):
                s += '1'
            else:
                s += '0'
        arr.append(s)
        s = ""
    #print(arr)
    f = open('nginx.conf','r+')
    flist = f.readlines()
    for index, line in enumerate(flist):
        if line.find("worker_processes") != -1:
            flist[index] = "worker_processes " + str(cpunum) + ";\r\n"
            bindline = "worker_cpu_affinity "
            for idx, s in enumerate(arr):
                if idx == (len(arr) - 1):
                    bindline = bindline + s + ";"
                else:
                    bindline = bindline + s + " "
            print(bindline)
            flist.insert(index + 1, bindline + "\r\n")
    f = open('nginx.conf', 'w+')
    f.writelines(flist)
    