import json
import os
import time
from python_arptable import get_arp_table

import sys

sys.path.append("..")
from utility import arp
from utility.utils import get_iface_info

'''
 data structure:

 dictionary
 { ip:{"mac"：mac,"time":time} }

'''


class MyWhiteList:
    data = {}
    expire_time = 20 * 60  # each entry is valid for 20 minutes

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

    def update_entry(self, ip, mac):
        self.data[ip] = {}
        self.data[ip]["mac"] = mac
        self.data[ip]["time"] = time.time()

    def delete_entry(self, entry):
        self.data.pop(entry["IP address"])

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
            json.dump(self.data, outfile)

    def update_from_cache(self, iface_):
        iface_info = get_iface_info(iface_)
        current_arp_table = get_arp_table()
        for entry in current_arp_table:
            # validation
            if not entry["Device"] == iface_:
                continue
            if arp.validate_entry(iface_info, entry):
                print("Verify entry: {} {}".format(entry["HW address"], entry["IP address"]))
                self.update_entry(entry["IP address"], entry["HW address"])
                arp.add_static_entry(entry)  # add entry to arp-cache
                print('\n')
            else:
                print("Verify entry failed: {} {}".format(entry["HW address"], entry["IP address"]))
                if self.ip_is_exist(entry["IP address"]):
                    print("Delete entry from whitelist")
                    self.delete_entry(entry)
                print("Delete entry from arp cache")
                arp.delete_entry(entry)
                print("\n")
        self.write2file()

    def run(self, iface_):
        # print("update from cache:")
        self.update_from_cache(iface_)
        while 1:
            # print("loop listen:")
            arp.loop_listen_arp_message(iface_, self)
            # print("update from cache:")
            self.update_from_cache(iface_)
