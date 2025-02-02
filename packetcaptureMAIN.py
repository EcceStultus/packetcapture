#!/usr/bin/env python3

from scapy.all import *
import logging
import packetHandler

# basic logging formate
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

def start_sniffer(interface):
    try:
        logging.info(f"Starting packet capture on {interface}: Ctrl+C to stop")

        sniff(iface=interface, prn=packetHandler.pkt_handler, store=True)    # scapy sniff function
        
    except KeyboardInterrupt:    # stops with Ctrl+C 
        logging.info("Program stopped by user")
    except Exception as e:       # error handling
        logging.error(f"Error: {e}")

def main():
    interfaces = conf.ifaces    #find interfaces
    print("Interfaces Available: ")
    print(interfaces)

    interface = input("Select interface: ")

    while interface not in interfaces:
        print("Invalid interface")
        interface = input("Select interface: ")

    try:
        # starts thread for save function in packet handler so program can save without loss of packet
        packetHandler.save_thread = threading.Thread(target=packetHandler.save_to_file, daemon=True)
        packetHandler.save_thread.start()

        start_sniffer(interface)

    finally:
        # ensure clean exit and capture of final packets
        packetHandler.stop_program.set()
        packetHandler.save_thread.join()
        logging.info("Final packets saved. Exiting")

if __name__ == "__main__":
    main()
