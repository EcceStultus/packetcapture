from scapy.all import *
import logging
import time
import queue
from datetime import datetime
import threading
import os

# set basic logging format
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

# setting/creating pcap file output destination
capture_directory = "captures"
os.makedirs(capture_directory, exist_ok=True) # makes said Dir if user hasn't already created one

# interval time for file saves
save_interval = 300 # 5 minutes

# thread safety
packet_queue = queue.Queue()

# creates an event (flag initially set to False)
stop_program = threading.Event()


# logs information about each packet
def log_ip_layer(pkt):
    ip_layer = pkt["IP"]
    logging.info(f"Src IP: {ip_layer.src}, Dst IP: {ip_layer.dst}, Protocol: {ip_layer.proto}")

def log_tcp_layer(pkt):
    tcp_layer = pkt["TCP"]
    logging.info(f"TCP: Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}, Flags: {tcp_layer.flags}, Window: {tcp_layer.window}")

def log_udp_layer(pkt):
    udp_layer = pkt["UDP"]
    logging.info(f"UDP: Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")

def log_dns_layer(pkt):
    dns_layer = pkt["DNS"]
    if dns_layer.qr == 0:
        logging.info(f"DNS Query: {dns_layer.qd.qname.decode()}")

def log_icmp_layer(pkt):
    icmp_layer = pkt["ICMP"]
    logging.info(f"ICMP Type: {icmp_layer.type}, Code: {icmp_layer.code}")

def log_raw_layer(pkt):
    raw_layer = pkt["RAW"].load
    logging.info(f"Raw Payload: {raw_layer[:50]}")

# the packet handler itself
def pkt_handler(pkt):
    if pkt.haslayer("IP"):
        log_ip_layer(pkt)

        if pkt["IP"].proto == 6:  # TCP
            log_tcp_layer(pkt)
                
        elif pkt["IP"].proto == 17:  # UDP
            log_udp_layer(pkt)

    if pkt.haslayer("DNS"):
        log_dns_layer(pkt)

    if pkt.haslayer("ICMP"):
        log_icmp_layer(pkt)

    if pkt.haslayer("RAW"):
        log_raw_layer(pkt)

    # add packet to the queue
    packet_queue.put(pkt)

def save_to_file(): # function to save pcap files at a time interval (multithread)
    time_stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_name = os.path.join(capture_directory, f"{time_stamp}.pcap")

    start_time = time.time()
    
    packets = [] # initialize empty list to store packets in memory until file is saved

    while not stop_program.is_set():    # Check stop_program flag, runs while flag is False (unset)
        try:
            packet = packet_queue.get(timeout=1) # Gets packet from queue
            packets.append(packet) # appends packet to memory
        except queue.Empty:
            continue    # If there is no packet, it tries again

        if time.time() - start_time >= save_interval:   # Check if time limit has been surpassed
            logging.info(f"Time interval surpassed, saving total {len(packets)} packets.")
            wrpcap(file_name, packets) # exports packet list to pcap file

            # reinitialize variables and list
            packets = [] 
            start_time = time.time()
            time_stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            file_name = os.path.join(capture_directory, f"{time_stamp}.pcap")

    if packets:    #flush the remaining packets at program exit to a final pcap file
        final_time_stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        final_file_name = os.path.join(capture_directory, f"{final_time_stamp}_final.pcap")
        wrpcap(final_file_name, packets)

# TO-DO LIST
#   - file compression
#   - max file size limiter e.g either 5 minutes of 50Mb
