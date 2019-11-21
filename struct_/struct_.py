class ETHAddr:
    """
        Ethernet frame header address structure
    """

    def __init__(self, dest_mac_=None, src_mac_=None):
        self.dest_mac = dest_mac_
        self.src_mac = src_mac_


class ARPAddr:
    """
        ARP message address structure
    """

    def __init__(self, src_mac_=None, src_ip_=None, dest_mac_=None, dest_ip_=None):
        self.src_mac = src_mac_
        self.src_ip = src_ip_
        self.dest_mac = dest_mac_
        self.dest_ip = dest_ip_
