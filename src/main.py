#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
import sys
import signal

sys.path.append("..")
from src.WhitList import MyWhiteList
from utility.utils import CNTC_Handler

if __name__ == '__main__':
    white_list = MyWhiteList("text_list.txt")
    iface = 'enp0s8'
    signal.signal(signal.SIGINT, CNTC_Handler)
    white_list.run(iface)
