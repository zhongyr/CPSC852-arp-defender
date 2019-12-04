import time
import sys

sys.path.append("..")
from utility import arp


class ArpRespCache:
    container = {}
    max_count = 5
    duration = 1

    def add_new_entry(self, entry):
        mac = entry["HW address"]
        ip = entry["IP address"]
        self.container[mac] = {"IP address": ip, "count": 1, "t_start": time.time()}

    def cache_entry(self, entry):
        mac = entry["HW address"]
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
        for mac in self.container:
            if self.duration <= time.time() - self.container[mac]["t_start"]:
                if self.container[mac]["count"] >= self.max_count:
                    # if we receive 5 or more same arp responses within 0.5 seconds
                    # that indicates it is an arp poison attack
                    ip = self.container[mac]["IP address"]
                    spoof_entry = {"HW address": mac, "IP address": ip}
                    if WL.ip_is_exist(ip):
                        WL.delete_entry(spoof_entry)  # delete entry from whitelist
                    arp.delete_entry(spoof_entry)  # delete entry from arp-cache
                    arp.add_to_blacklist(spoof_entry)  # add entry to blacklist
                    print("detect arp response spoof: {} {}".format(spoof_entry["HW address"],
                                                                              spoof_entry["IP address"]))
                self.delete_record(mac)
