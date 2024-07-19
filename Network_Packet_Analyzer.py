import socket
import struct
import textwrap
import logging

# Set up logging
logging.basicConfig(filename='packet_sniffer.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Tab space for formatting
t1 = '\t  '
t2 = '\t\t    '
t3 = '\t\t\t    '
t4 = '\t\t\t\t    '

def main():

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    #Prints the detail of the packet
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet frame:')
        print('Destination: {}, Source: {}, Protocol:{}'.format(dest_mac, src_mac, eth_proto))
        logging.info('Ethernet frame: Destination: {}, Source: {}, Protocol:{}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:  # IPv4
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(t1 + 'IPV4 Packet:')
            print(t2 + "Version: {}, Header Length: {}, TTL: {}".format(version, header_length, ttl))
            print(t2 + "Protocol: {}, Source: {}, Target: {}".format(proto, src, target))
            logging.info('IPV4 Packet: Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            logging.info('Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1: #icmp
                icmp_type, code, checksum, data = icmp_packet(data)
                print(t1 + 'ICMP Packet:')
                print(t2 + "Type: {}, Code: {}, Checksum: {}".format(icmp_type, code, checksum))
                print(t2 + 'Data: ')
                print(format_multi_line(t3, data))
                logging.info('ICMP Packet: Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))

            elif proto == 6: # tcp
                (src_port, dest_port, seq, ack, f_urg, f_ack, f_psh, f_rst, f_syn, f_fin, data) = tcp_packet(data)
                print(t1 + 'TCP Packet:')
                print(t2 + "Source Port: {}, Destination Port: {}".format(src_port, dest_port))
                print(t2 + "Sequence: {}, Acknowledgement: {}".format(seq, ack))
                print(t2 + 'Flags:')
                print(t3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(f_urg, f_ack, f_psh, f_rst,
                                                                                         f_syn, f_fin))
                print(t2 + 'Data:')
                print(format_multi_line(t3, data))
                print(t2 + 'Human-readable Data:')
                print(format_human_readable(t3, data))
                logging.info('TCP Packet: Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                logging.info('Sequence: {}, Acknowledgement: {}'.format(seq, ack))
                logging.info('Flags: URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(f_urg, f_ack, f_psh, f_rst, f_syn, f_fin))

            elif proto == 17: # udp
                src_port, dest_port, length, data = udp_segment(data)
                print(t1 + 'UDP Packet:')
                print(t2 + "Source Port: {}, Destination Port: {}, Length: {}".format(src_port, dest_port, length))
                print(t2 + 'Data: ')
                print(format_multi_line(t3, data))
                print(t2 + 'Human-readable Data:')
                print(format_human_readable(t3, data))
                logging.info('UDP Packet: Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

            else:
                print(t1 + 'Data: ')
                print(format_multi_line(t3, data))
                print(t1 + 'Human-readable Data:')
                print(format_human_readable(t3, data))
                logging.info('Other Data: {}'.format(format_multi_line('', data)))

#to unpack the ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return get_mac_add(dest_mac), get_mac_add(src_mac), socket.htons(proto), data[14:]

#to get mac address
def get_mac_add(bytes_add):
    bytes_str = map('{:02x}'.format, bytes_add)
    return ':'.join(bytes_str).upper()

#unpack ip packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#get ip address
def ipv4(addr):
    return '.'.join(map(str, addr))

#unpack icmp packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#unpack tcp packet
def tcp_packet(data):
    (src_port, dest_port, seq_num, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, seq_num, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#unpack udp segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

#rteurn the data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join(prefix + line for line in textwrap.wrap(string, size))

#converts hexdump into human readble form
def format_human_readable(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in string)
    return '\n'.join(prefix + line for line in textwrap.wrap(string, size))

if __name__ == '__main__':
    main()
