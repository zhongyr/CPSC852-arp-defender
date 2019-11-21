
import json
import os
import time
from python_arptable import get_arp_table

'''
 data structure:
 
 dictionary
 { ip:{"mac"：mac,"time":time} }

'''


class MyWhiteList:
    data = {}
    expire_time = 20*60                                       # each entry is valid for 20 minutes

    def __init__(self, file_path):
        if not os.path.exists(file_path):
            print("ERROR: FILE NOT EXIST")
            exit(0)
        self.file_path = file_path
        with open(self.file_path) as json_data:
            try:
                self.data = json.load(json_data)
            except ValueError:
                print("ERROR: NOT JSON TYPE")

    def update(self, ip, mac):
        self.data[ip] = {}
        self.data[ip]["mac"] = mac
        self.data[ip]["time"] = time.time()

    def get_mac_by_ip(self, ip):
        if ip in self.data:
            return self.data[ip]["mac"]
        else:
            return -1

    def ip_is_exist(self, ip):
        if ip in self.data:
            return True
        else:
            return False

    def write2file(self):
        with open(self.file_path, 'w') as outfile:
            json.dump(self.data,outfile) 
    
    def updateFromCache(self):
        current_arp_table = get_arp_table()
        for entry in current_arp_table:
             #print(entry["IP address"],entry["HW address"])
             # validation
             self.update(entry["IP address"], entry["HW address"])
        self.write2file() 



