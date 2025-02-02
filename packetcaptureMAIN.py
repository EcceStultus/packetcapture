#!/usr/bin/env python3

from scapy.all import *
import logging
import packetHandler

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

def start_sniffer(interface):
    try:
        logging.info(f"Interface: {interface}")
        logging.info("Starting packet capture: Ctrl+C to stop")

        sniff(iface=interface, prn=packetHandler.pkt_handler, store=True)
        
    except KeyboardInterrupt:
        logging.info("Program stopped by user")
    except Exception as e:
        logging.error(f"Error: {e}")

def main():
    interfaces = conf.ifaces
    print("Interfaces Available: ")
    print(interfaces)

    interface = input("Select interface: ")

    while interface not in interfaces:
        print("Invalid interface")
        interface = input("Select interface: ")

    try:
        packetHandler.save_thread = threading.Thread(target=packetHandler.save_to_file, daemon=True)
        packetHandler.save_thread.start()

        start_sniffer(interface)

    finally:
        packetHandler.stop_program.set()
        packetHandler.save_thread.join()
        logging.info("Final packets saved. Exiting")

if __name__ == "__main__":
    main()
