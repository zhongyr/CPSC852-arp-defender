import time
import sys

sys.path.append("..")
from utility import arp


class ArpRespCache:
    container = {}  # cache all incoming arp response messages
    spoof_entries = []  # record all spoof mac entries
    max_count = 5  # Maximum value of the same entry that can be received within duration
    duration = 1

    def add_new_entry(self, entry):
        mac = entry["HW address"]
        ip = entry["IP address"]
        self.container[mac] = {"IP address": ip, "count": 1, "t_start": time.time()}

    def cache_entry(self, entry):
        mac = entry["HW address"]
        if entry not in self.spoof_entries:
            if mac not in self.container:
                self.add_new_entry(entry)
            else:
                self.container[mac]["count"] += 1

    def delete_record(self, mac):
        del self.container[mac]

    def check_spoof(self, WL):
        """
        detect arp response spoof attack by frequency
        """
        for mac in list(self.container):
            if self.duration <= time.time() - self.container[mac]["t_start"]:
                if self.container[mac]["count"] >= self.max_count:
                    # if we receive 5 or more same arp responses within 0.5 seconds
                    # that indicates it is an arp poison attack
                    ip = self.container[mac]["IP address"]
                    spoof_entry = {"HW address": mac, "IP address": ip}
                    if WL.ip_is_exist(ip) and WL.get_mac_by_ip(ip) == mac:
                        WL.delete_entry(spoof_entry)  # delete entry from whitelist
                    self.spoof_entries.append(spoof_entry)
                    arp.delete_entry(spoof_entry)  # delete entry from arp-cache
                    arp.add_to_blacklist(spoof_entry)  # add entry to blacklist
                    print("detect arp respnose spoof: {} {}".format(spoof_entry["HW address"],
                                                                    spoof_entry["IP address"]))
                self.delete_record(mac)
