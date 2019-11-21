from WhitList import MyWhiteList
from python_arptable import get_arp_table

def updateFromCache(_white_list):
    current_arp_table = get_arp_table()
    for entry in current_arp_table:
         #print(entry["IP address"],entry["HW address"])
         # validation
         _white_list.update(entry["IP address"], entry["HW address"])
    _white_list.write2file() 


if __name__ == '__main__':
    white_list = MyWhiteList("text_list.txt")
    for ip, mac in white_list.data.items():
        print(ip,'\t', mac["time"],'\t', mac["mac"])

    updateFromCache(white_list)


