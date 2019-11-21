#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
import sys

sys.path.append("..")
from src.WhitList import MyWhiteList
from python_arptable import get_arp_table

if __name__ == '__main__':
    white_list = MyWhiteList("text_list.txt")
    for ip, mac in white_list.data.items():
        print(ip, '\t', mac["time"], '\t', mac["mac"])
    iface = 'enp0s8'
    white_list.update_from_cache(iface)
