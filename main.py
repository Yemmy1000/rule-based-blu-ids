import argparse
from io import StringIO
import os
import sys
from scapy.utils import *
from scapy.layers.bluetooth import *
import time

attacks_t = 0
pakt_no = 1

def rules(packet, pkt):    
    threshold = 1000
    # Check for unusual packet sizes
    threshold_size = 1500  # Define the threshold for packet size
    min_size = 20  # Define the minimum expected packet size
    threshold_packet_length = 200
    global attacks_t
    attacks = 0
    print(">> packet type: ", packet['packet_type'])
    
    if packet['packet_attributes']['direction'] == 0:
        delay_microseconds(500_000)
        print(">> Potential DoS attack: packet_attributes direction is 0. ")
        attacks += 1
    
    #if len(packet) > threshold_packet_length:
        #print("Potential DoS attack: Unusually high packet count")
        
   
    if 'data' in split_string(str(packet['packet_values'])):
        delay_microseconds(500_000)
        print(">> Potential DoS attack: Unknown payload type and size. ")
        attacks += 1
        
    if len(pkt[HCI_PHDR_Hdr].original) > 20:
        delay_microseconds(500_000)
        print(">> Potential DoS attack: Raw data length exceed normal. ")
        attacks += 1
    
    if attacks == 0:
        print(">> Packet ok! ")
    else:
        attacks_t += 1
        
        
def split_string(input_string):
    split_items = str(input_string[1:]).split(' ')
    result_dict = {}    
    for i in split_items:
        if '=' in i:
            gg = i.split("=")
            key = gg[0]
            value = gg[1]
            result_dict[key] = value  
    return result_dict



# Function to draw a rectangle with text in the middle
def print_rectangle_with_text(width, text):
    
    print("\n\t",'*' * width)
    print("\t\t", text)
    print("\t",'*' * width)


def delay_microseconds(microseconds):
    seconds = microseconds / 1_000_000  # Convert microseconds to seconds
    time.sleep(seconds)



# Load the pcap file
def bluetooth_packet_handler(file_name):
    print_rectangle_with_text(60, "DoS attack detection in Bluetooth traffic")
    print('>> Opening {}...'.format(file_name))
    packets = rdpcap(file_name)    

    packet_data_list = []
    global pakt_no
    for packet in packets[0:5]:
        # Dictionary to store attributes and values for the current packet
        if HCI_PHDR_Hdr in packet:
            packet_attributes = {
                "packet_type": type(packet).__name__,
                "packet_attributes": packet.fields,
                "packet_values": packet.getfieldval
            }
            
            print("packet #", pakt_no)
            rules(packet_attributes, packet)  
            pakt_no += 1
            
        # Append the packet attributes and values to the list    
        #packet_data_list.append(packet_attributes)
    summary()
    # Display the list of packet data
    #print(packet_data_list)            
def summary():
    print("\t", "*" * 60)
    print("\t\t", "Summary")
    print("\t\t Total packets: ", pakt_no)
    print("\t\t Total malicious traffic: ", attacks_t)
    print("\t", "*" * 60)
            

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    
    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    bluetooth_packet_handler(file_name)
    print("\n************************ Finished **************************")

    sys.exit(0)