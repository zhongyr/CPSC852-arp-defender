#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
import sys

sys.path.append("..")
from src.WhitList import MyWhiteList

if __name__ == '__main__':
    white_list = MyWhiteList("text_list.txt")
    iface = 'enp0s8'
    print("Start arp defender")
    white_list.run(iface)
