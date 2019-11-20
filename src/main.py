from WhitList import MyWhiteList
from python_arptable import get_arp_table

if __name__ == '__main__':
    white_list = MyWhiteList("text_list.txt")
    for ip, mac in white_list.data.items():
        print(ip, mac)

    print(get_arp_table())

