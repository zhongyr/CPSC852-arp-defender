from WhitList import MyWhiteList
from python_arptable import get_arp_table

if __name__ == '__main__':
    white_list = MyWhiteList("text_list.txt")
    for ip, mac in white_list.data.items():
        print(ip, mac)

    current_arp_table = get_arp_table()
    for entry in current_arp_table:
         print(entry["IP address"],entry["HW address"])
         # validation
         white_list.update(entry["IP address"], entry["HW address"])
         white_list.write2file()
