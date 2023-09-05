from scapy.all import *
import subprocess
import csv

# Define a mapping of protocol numbers to their names
protocol_names = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

# Define the allowed and blocked IP addresses
allowed_ips = ["192.168.56.101", "192.168.70.98", "169.254.118.88", "169.254.9.237", "127.17.176.1", "172.30.16.1", "172.23.96.1", "192.168.56.1", "169.254.8.212"]
blocked_ips = ["192.168.56.103", "10.0.0.2"]

# Initialize variables to store statistics
total_fwd_packets = 0
total_bwd_packets = 0
total_length_fwd_packets = 0
total_length_bwd_packets = 0
fwd_packet_length_max = float('-inf')
fwd_packet_length_min = float('inf')
fwd_packet_length_sum = 0
bwd_packet_length_max = float('-inf')
bwd_packet_length_min = float('inf')
bwd_packet_length_sum = 0

# Initialize protocol counters
protocol_counters = {proto: 0 for proto in protocol_names.values()}

# Create a CSV file to store packet data
csv_file = "packet_data.csv"

# Open the CSV file in write mode and define column headers
with open(csv_file, mode="w", newline="") as file:
    fieldnames = ["src_ip", "dst_ip", "protocol", "packet_length"]
    writer = csv.DictWriter(file, fieldnames=fieldnames)

    # Write the header row
    writer.writeheader()

    def packet_handler(packet):
        global total_fwd_packets, total_bwd_packets
        global total_length_fwd_packets, total_length_bwd_packets
        global fwd_packet_length_max, fwd_packet_length_min, fwd_packet_length_sum
        global bwd_packet_length_max, bwd_packet_length_min, bwd_packet_length_sum

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol_num = packet[IP].proto
            protocol = protocol_names.get(protocol_num, "Unknown")

            # Increment protocol counter
            protocol_counters[protocol] += 1

            if src_ip in blocked_ips:
                print(f"Blocked packet from {src_ip} using protocol {protocol}")
                block_ip(src_ip)
                return
            elif src_ip in allowed_ips:
                print(f"Allowed packet from {src_ip} using protocol {protocol}")
            else:
                print(f"Unknown packet from {src_ip}, action: default")

            # Packet analysis for statistics
            total_fwd_packets += 1

            if packet.haslayer(UDP) or packet.haslayer(TCP) or packet.haslayer(ICMP):
                # Check if it's any of the three protocols (UDP, TCP, ICMP)
                packet_length = len(packet[IP])  # You can adjust this based on the desired packet length
                total_length_fwd_packets += packet_length
                fwd_packet_length_max = max(fwd_packet_length_max, packet_length)
                fwd_packet_length_min = min(fwd_packet_length_min, packet_length)
                fwd_packet_length_sum += packet_length

                # Write packet data to the CSV file for any of the three protocols
                writer.writerow({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "packet_length": packet_length})

    def block_ip(ip):
        # Define the command to block incoming traffic from the specified IP using iptables
        block_command = f"iptables -A INPUT -s {ip} -j DROP"
        try:
            subprocess.run(block_command, shell=True, check=True)
            print(f"Blocked incoming traffic from {ip}")
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP {ip}: {e}")

    # Start capturing packets
    filter_expression = "ip"
    sniff(filter=filter_expression, iface="eth1", prn=packet_handler)

# Calculate and print statistics after capturing packets
# You can add more statistics printing here based on your needs
print(f"Total Forward Packets: {total_fwd_packets}")
print(f"Total Length of Forward Packets: {total_length_fwd_packets}")
print(f"Forward Packet Length Max: {fwd_packet_length_max}")
print(f"Forward Packet Length Min: {fwd_packet_length_min}")

# Print protocol counters
for protocol, count in protocol_counters.items():
    print(f"Protocol {protocol}: {count} packets")

# Add more statistics printing here as needed
