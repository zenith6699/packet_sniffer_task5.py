
"""
Network Packet Analyzer (Packet Sniffer)
FOR EDUCATIONAL PURPOSES ONLY
"""

import socket
import struct
import textwrap
import time
from datetime import datetime
import os
import sys


def show_ethical_warning():
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                NETWORK PACKET ANALYZER WARNING              ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║  FOR EDUCATIONAL PURPOSES ONLY                              ║")
    print("║  Use only on networks you own or have permission to monitor ║")
    print("║  Unauthorized network monitoring may be illegal             ║")
    print("║  You are responsible for complying with local laws          ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    
    consent = input("Do you understand and agree to these terms? (yes/no): ").strip().lower()
    return consent in ['yes', 'y']


class PacketSniffer:
    def __init__(self, interface=None, log_file="packet_log.txt", max_packets=100):
        self.interface = interface
        self.log_file = log_file
        self.max_packets = max_packets
        self.packet_count = 0
        self.running = False
        
        
        with open(self.log_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("NETWORK PACKET ANALYSIS LOG\n")
            f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n\n")
    
    
    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]
    
  
    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()
    
    
    def ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]
    
   
    def ipv4(self, addr):
        return '.'.join(map(str, addr))
    
    
    def icmp_packet(self, data):
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]
    
    
    def tcp_segment(self, data):
        (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flags = {
            'URG': (offset_reserved_flags & 32) >> 5,
            'ACK': (offset_reserved_flags & 16) >> 4,
            'PSH': (offset_reserved_flags & 8) >> 3,
            'RST': (offset_reserved_flags & 4) >> 2,
            'SYN': (offset_reserved_flags & 2) >> 1,
            'FIN': offset_reserved_flags & 1
        }
        return src_port, dest_port, sequence, acknowledgement, flags, data[offset:]
    
   
    def udp_segment(self, data):
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]
    
  
    def format_multi_line(self, prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
    
   
    def process_packet(self, data):
        self.packet_count += 1
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        
        with open(self.log_file, 'a') as f:
            f.write(f"\n[{timestamp}] Packet #{self.packet_count}\n")
            f.write("-" * 50 + "\n")
        
        dest_mac, src_mac, eth_proto, data = self.ethernet_frame(data)
        
      
        print(f"\n\033[94m[{timestamp}] Packet #{self.packet_count}\033[0m")
        print(f"\033[92mEthernet Frame:\033[0m")
        print(f"  Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")
        
        with open(self.log_file, 'a') as f:
            f.write(f"Ethernet Frame:\n")
            f.write(f"  Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}\n")
        
        
        if eth_proto == 8:
            version, header_length, ttl, proto, src_ip, target_ip, data = self.ipv4_packet(data)
            
            print(f"\033[92mIPv4 Packet:\033[0m")
            print(f"  Version: {version}, Header Length: {header_length}, TTL: {ttl}")
            print(f"  Protocol: {proto}, Source: {src_ip}, Target: {target_ip}")
            
            with open(self.log_file, 'a') as f:
                f.write(f"IPv4 Packet:\n")
                f.write(f"  Version: {version}, Header Length: {header_length}, TTL: {ttl}\n")
                f.write(f"  Protocol: {proto}, Source: {src_ip}, Target: {target_ip}\n")
            
          
            if proto == 1:
                icmp_type, code, checksum, data = self.icmp_packet(data)
                print(f"\033[92mICMP Packet:\033[0m")
                print(f"  Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
                
                with open(self.log_file, 'a') as f:
                    f.write(f"ICMP Packet:\n")
                    f.write(f"  Type: {icmp_type}, Code: {code}, Checksum: {checksum}\n")
            
           
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flags, data = self.tcp_segment(data)
                print(f"\033[92mTCP Segment:\033[0m")
                print(f"  Source Port: {src_port}, Destination Port: {dest_port}")
                print(f"  Sequence: {sequence}, Acknowledgement: {acknowledgement}")
                print(f"  Flags: {flags}")
                
                with open(self.log_file, 'a') as f:
                    f.write(f"TCP Segment:\n")
                    f.write(f"  Source Port: {src_port}, Destination Port: {dest_port}\n")
                    f.write(f"  Sequence: {sequence}, Acknowledgement: {acknowledgement}\n")
                    f.write(f"  Flags: {flags}\n")
                
                
                if data:
                    print(f"\033[92mData:\033[0m")
                    print(self.format_multi_line("  ", data))
                    
                    with open(self.log_file, 'a') as f:
                        f.write(f"Data:\n")
                        f.write(self.format_multi_line("  ", data) + "\n")
            
            
            elif proto == 17:
                src_port, dest_port, length, data = self.udp_segment(data)
                print(f"\033[92mUDP Segment:\033[0m")
                print(f"  Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}")
                
                with open(self.log_file, 'a') as f:
                    f.write(f"UDP Segment:\n")
                    f.write(f"  Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}\n")
            
           
            else:
                print(f"\033[92mOther IPv4 Data:\033[0m")
                print(self.format_multi_line("  ", data))
                
                with open(self.log_file, 'a') as f:
                    f.write(f"Other IPv4 Data:\n")
                    f.write(self.format_multi_line("  ", data) + "\n")
    
   
    def start_sniffing(self):
        if not show_ethical_warning():
            print("Sniffing cancelled.")
            return
        
       
        try:
            if os.name == 'nt':
                sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sniffer.bind(('0.0.0.0', 0))
                sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except PermissionError:
            print("\033[91mError: Permission denied. Run with sudo/administrator privileges.\033[0m")
            return
        except Exception as e:
            print(f"\033[91mError creating socket: {e}\033[0m")
            return
        
        self.running = True
        print(f"\n\033[92mStarting packet sniffer...\033[0m")
        print(f"Press Ctrl+C to stop after capturing {self.max_packets} packets")
        print(f"Logging to: {os.path.abspath(self.log_file)}")
        
        try:
            while self.running and self.packet_count < self.max_packets:
               
                raw_data, addr = sniffer.recvfrom(65535)
                self.process_packet(raw_data)
                
              
                print(f"\rPackets captured: {self.packet_count}/{self.max_packets}", end='')
                
        except KeyboardInterrupt:
            print("\n\nStopped by user.")
        finally:
      
            if os.name == 'nt':
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sniffer.close()
            
           
            with open(self.log_file, 'a') as f:
                f.write(f"\n\nStopped: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total packets captured: {self.packet_count}\n")
                f.write("="*60 + "\n")
            
            print(f"\nSniffing stopped. Captured {self.packet_count} packets.")
            print(f"Log file: {os.path.abspath(self.log_file)}")


def main():
    print("Network Packet Analyzer")
    print("Educational Use Only!")
    print("="*40)
    
    
    try:
        max_packets = int(input("Enter number of packets to capture (default 100): ") or "100")
        if max_packets <= 0:
            max_packets = 100
    except ValueError:
        max_packets = 100
    
    log_file = input("Enter log file name (default packet_log.txt): ") or "packet_log.txt"
    
    
    sniffer = PacketSniffer(log_file=log_file, max_packets=max_packets)
    sniffer.start_sniffing()
    
    
    if os.path.exists(log_file):
        view = input("\nWould you like to view the log file? (yes/no): ").lower().strip()
        if view in ['yes', 'y']:
            print("\n" + "="*60)
            with open(log_file, 'r') as f:
                print(f.read())

if __name__ == "__main__":
   
    if os.name != 'nt' and os.geteuid() != 0:
        print("\033[91mThis program requires root privileges. Run with sudo.\033[0m")
        sys.exit(1)
    
    main()
