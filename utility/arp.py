# -*- encoding: utf-8 -*-
import struct
import time
from os import system
import sys

sys.path.append("..")
from utility.utils import *
from struct_.struct_ import *


def eth_header_maker(eth_addr_, type_=0x0806):
    """
    create an Ethernet herder, the padding and CRC is automatically handled by NIC

    :param eth_addr_: Ethernet frame address object: ETHAddr
    :param type_: type of Ethernet data
    :return: packed Ethernet header (binary format string)
    """
    dst = mac_str2bin(eth_addr_.dest_mac)
    src = mac_str2bin(eth_addr_.src_mac)
    return struct.pack('!6s6sH', dst, src, type_)  # packet data in network byte order (big-endian)


def arp_message_maker(arp_addr_, op_):
    """
    create an ARP request or arp response message

    :param arp_addr_: ARP message address object: ARPAddr
    :param op_: 2 bytes ARP message operation code, 0x0001: ARP Request, 0x0002: ARP Response
    :return: packed Ethernet header (binary format string)
    """
    h_type = 0x0001  # hardware type
    p_type = 0x0800  # protocol address type, 0x0800: IPv4
    h_len = 0x06  # hardware address length
    p_len = 0x04  # protocol address length
    s_h_addr = mac_str2bin(arp_addr_.src_mac)  # sender hardware address
    s_p_addr = socket.inet_aton(arp_addr_.src_ip)  # sender protocol address  # test VM1
    t_h_addr = mac_str2bin(arp_addr_.dest_mac)
    t_p_addr = socket.inet_aton(arp_addr_.dest_ip)  # target protocol address  # test VM2
    return struct.pack("!HHBBH6s4s6s4s", h_type, p_type, h_len, p_len, op_,
                       s_h_addr, s_p_addr, t_h_addr, t_p_addr)


def arp_request(iface_info_, entry):
    """
    make an ARP request, get the target mac address

    :param iface_info_: host network interface information
    :param entry: arp entry
    :return: None
    """

    # create Ethernet header
    eth_addr = ETHAddr(dest_mac_=entry["HW address"],
                       src_mac_=iface_info_["HW address"])
    # create Eth header
    eth_header = eth_header_maker(eth_addr)

    # create ARP header for ARP request
    arp_addr = ARPAddr(src_mac_=iface_info_["HW address"],
                       src_ip_=iface_info_["IP address"],
                       dest_mac_="00:00:00:00:00:00",
                       dest_ip_=entry["IP address"])
    # create ARP request message
    arp_req_message = arp_message_maker(arp_addr, op_=0x0001)

    return eth_header + arp_req_message


def unpack_rx(rx_message_):
    # unpack the arp response
    rx_arp_raw = rx_message_[14:42]
    rx_arp = struct.unpack("HHBBH6s4s6s4s", rx_arp_raw)
    rx_mac = mac_bytes2str(rx_arp[5])
    rx_ip = socket.inet_ntoa(rx_arp[6])
    return {"HW address": rx_mac, "IP address": rx_ip}


def rx_arp_message(raw_sock_):
    raw_sock_.settimeout(0.5)  # set listening timeout
    rx_mac = None
    try:
        rx_message = raw_sock_.recv(1024)
    except socket.timeout as e:
        print("listen timeout")
    else:
        rx_mac = unpack_rx(rx_message)["HW address"]
        print("rx mac: ", rx_mac)
    finally:
        return rx_mac


def loop_listen_arp_message(iface_, WL, duration=600):
    iface_info = get_iface_info(iface_)
    raw_socket = create_raw_socket(iface_info["iface"])
    strat_time = time.time()
    iface_info = get_iface_info(iface_)
    while 1:
        rx_message = raw_socket.recv(1024)
        rx_entry = unpack_rx(rx_message)
        if WL.ip_is_exist(rx_entry["IP address"]):
            if rx_entry["HW address"] == WL.get_mac_by_ip(rx_entry["IP address"]):
                continue
        if validate_entry(iface_info, rx_entry):
            WL.update_entry(rx_entry["IP address"], rx_entry["HW address"])
            add_static_entry(rx_entry)
        else:
            add_to_blacklist(rx_entry)
        if duration <= time.time() - strat_time:
            raw_socket.close()
            break


def add_static_entry(entry):
    """
    add a static to arp cache
    :param entry: arp entry
    :return: None
    """
    system("arp -s {} {} ".format(entry["IP address"], entry["HW address"]))


def delete_entry(entry):
    """
    delete an entry from arp cache
    :param entry: arp entry
    :return: None
    """
    system("arp -d {}".format(entry["IP address"]))


def validate_entry(iface_info_, entry):
    """
    Validate an arp entry. Send unique arp request to the IP address of the entry,
    if there is a response, that means the entry is not spoofed. Otherwise it indicates
    that this is a spoofed entry.

    :param iface_info_: host network interface information
    :param entry: arp entry
    :return: Boolean
    """
    # create a raw socket
    raw_socket = create_raw_socket(iface_info_["iface"])
    # send ARP request with raw socket
    raw_socket.send(arp_request(iface_info_, entry))
    # receive the ARP response
    rx_mac = rx_arp_message(raw_socket)
    if rx_mac is not None and compare_mac_addr(entry, rx_mac):
        raw_socket.close()
        return True
    raw_socket.close()
    return False
