from scapy.all import *
import threading
import os
import csv
f = os.popen('ifconfig wlan0 | grep "inet\ addr" | cut -d: -f2 | cut -d" " -f1')
ip_src=f.read()
print(ip_src)
s=threading.Semaphore(1)
flows={}

def flow_generator(pkt):
    if(pkt[TCP].sport!=22):
        ip=pkt[IP].src
        port=pkt[TCP].sport

    else:
        ip=pkt[IP].dst
        port=pkt[TCP].dport
    
    #print(len(pkt[TCP]),str(pkt[TCP].sport),str(pkt[TCP].dport))
    s.acquire()
    flows.setdefault(str(ip)+str(port), [])
    flows[str(ip)+str(port)].append(pkt)
    s.release()

def flow_processor():
    flow_label=flows.keys()
    print(flow_label)
    with open('dataset.csv', 'ab') as csvfile: 
        spamwriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        if(len(flow_label)!=0):
            for i in flow_label:
                min=0
                attempt=0
                success=0
                flag=0
                ip1=''
                for index,j in enumerate(flows.get(i)):
                    if((len(j[TCP])!=84 or len(j[TCP])!=80)  and j[TCP].sport!=22):
                        continue
                    elif((len(j[TCP])==84 or len(j[TCP])==100 or len(j[TCP])==80) and j[TCP].sport==22 and flag==0 and index < len(flows.get(i))-4):
                        ip1=str(j[IP].dst)
                        k=(flows.get(i))[index+1]
                        time1=k.time
                        m=(flows.get(i))[index+3]
                        time2=m.time
                        min=time2-time1
                        flag=1
                        if(index < len(flows.get(i))-4 and (len((flows.get(i))[index+4][TCP])==68 or len((flows.get(i))[index+4][TCP])==64) ):
                            success=1
                            attempt=attempt+1
                            break
                        else:
                            attempt=attempt+1
                            continue
                    elif(index < len(flows.get(i))-2):
                        if(len((flows.get(i))[index+2][TCP])==68 or len((flows.get(i))[index+2][TCP])==64):
                            success=1
                            attempt=attempt+1
                            break
                        else:
                            attempt=attempt+1
                            continue
                if(ip1!= ''and ip1!=ip_src and attempt!=0 and min!=0):
                    spamwriter.writerow([ip1,min,attempt,success])
                    del flows[i]

while(True):
    sniff(iface="wlan0",filter="tcp and port 22 and greater 76",prn=flow_generator,timeout=30)
    flow_processor()
    
    
  