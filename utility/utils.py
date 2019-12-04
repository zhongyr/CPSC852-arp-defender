# -*- encoding: utf-8 -*-
import netifaces
import binascii
import socket
from os import system


def get_iface_info(iface_):
    """
    get interface information
    :param iface_: name of interface
    :return: dict object including mac address and ip address
    """
    info = netifaces.ifaddresses(iface_)
    mac_addr = info[netifaces.AF_LINK][0]["addr"]
    ip_addr = info[netifaces.AF_INET][0]["addr"]
    return {"HW address": mac_addr, "IP address": ip_addr, "iface": iface_}


def mac_str2bin(mac_str_):
    """
    convert string format mac address to binary format
    :param mac_str_: 1a:2b:3c:4d:5e:6f
    :return: b'1a2b3c4d5e6f' (binary data represented by hex str)
    """
    return binascii.unhexlify(mac_str_.replace(':', ''))


def mac_bytes2str(mac_bytes_):
    """
    convert bytes obj to mac address format string
    :param mac_bytes_: bytes obj
    :return: mack address format string
    """
    hex_str = mac_bytes_.hex()  # get hex like string from bytes: 'ffffffffffff'
    return ':'.join(hex_str[i:i + 2] for i in range(0, 12, 2))  # prettify 'ff:ff:ff:ff:ff:ff'


def create_raw_socket(iface_):
    """
    :param iface_: interface
    :return: socket file descriptor
    """
    _ETH_P_ARP = 0x0806
    raw_socket = socket.socket(socket.PF_PACKET,  # use PF_PACKET for low-level networking interface
                               socket.SOCK_RAW,  # set type to raw socket
                               socket.htons(_ETH_P_ARP))  # we are only interested in ARP packets
    raw_socket.bind((iface_, 0))  # bind interface, use reserved port number 0
    return raw_socket


def compare_mac_addr(entry, rx_mac):
    """
    compare the mac address from an entry with the mac address from response
    :param entry:
    :param rx_mac:
    :return:
    """
    if entry["HW address"] == rx_mac:
        return True
    return False


blacklist = []


def add_to_blacklist(entry):
    """
    if an entry failed in validation, add it to blacklist.
    We use arptables as our blacklist
    :param entry: src_mac_address
    :return: None
    """
    blacklist.append(entry)
    system("arptables -A INPUT --src-mac {} -j DROP".format(entry["HW address"]))


def CNTC_Handler(signum, frame):
    """
    Clear all entries from arptables(blacklist) before exit
    :return: None
    """
    print("\nclear blacklist before exit")
    system("arptables -F")
    print("exit arp defender")
    exit(0)
