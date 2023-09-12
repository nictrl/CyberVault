import subprocess
import csv
from scapy.all import *
import time

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
total_length_fwd_packets = 0
fwd_packet_length_max = float('-inf')
fwd_packet_length_min = float('inf')
fwd_packet_length_sum = 0

# Initialize a dictionary to store packet timestamps for each source IP
packet_timestamps = {}

# Create a CSV file to store packet data
csv_file = "packet_data.csv"

# Open the CSV file in write mode and define column headers
with open(csv_file, mode="w", newline="") as file:
    fieldnames = ["src_ip", "dst_ip", "protocol", "packet_length", "packets_per_minute", "status"]
    writer = csv.DictWriter(file, fieldnames=fieldnames)

    # Write the header row
    writer.writeheader()

    running = False

    def calculate_packets_per_minute(ip):
        timestamp = time.time()

        # Check if the source IP is already in the dictionary
        if ip in packet_timestamps:
            # Calculate the time elapsed since the last packet from this IP
            elapsed_time = timestamp - packet_timestamps[ip]

            # Calculate the packets per minute rate
            packets_per_minute = 60 / elapsed_time

            # Update the timestamp for the source IP
            packet_timestamps[ip] = timestamp

            return packets_per_minute

        else:
            # If it's the first packet from this IP, add the timestamp
            packet_timestamps[ip] = timestamp
            return 0  # PPM is 0 for the first packet

    def packet_handler(packet):
        global total_fwd_packets
        global total_length_fwd_packets
        global fwd_packet_length_max, fwd_packet_length_min, fwd_packet_length_sum

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol_num = packet[IP].proto
            protocol = protocol_names.get(protocol_num, "Unknown")

            if src_ip in allowed_ips:
                print(f"Allowed packet from {src_ip} using protocol {protocol}")
            elif src_ip in blocked_ips:
                if dst_ip in allowed_ips:
                    print(f"Blocked packet from {src_ip} to {dst_ip} using protocol {protocol} (Outgoing)")
                    record_blocked_outgoing(src_ip, dst_ip, protocol)
                else:
                    print(f"Blocked packet from {src_ip} to {dst_ip} using protocol {protocol} (Outgoing)")
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

                    # Calculate packets per minute rate for each source IP
                    ppm = calculate_packets_per_minute(src_ip)

                    # Write packet data to the CSV file, including rounded PPM and status
                    writer.writerow({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "packet_length": packet_length, "packets_per_minute": round(ppm), "status": "Blocked, Outgoing" if packet[IP].dst in allowed_ips else "Blocked"})

    def block_ip(ip):
        if ip not in blocked_ips:
            blocked_ips.append(ip)
            if ip in allowed_ips:
                allowed_ips.remove(ip)
            print(f"IP {ip} added to the blocked list.")
        else:
            print(f"IP {ip} is already blocked.")

    def allow_ip(ip):
        if ip not in allowed_ips:
            allowed_ips.append(ip)
            if ip in blocked_ips:
                blocked_ips.remove(ip)
            print(f"IP {ip} added to the allowed list.")
        else:
            print(f"IP {ip} is already allowed.")

    def record_blocked_outgoing(src_ip, dst_ip, protocol):
        writer.writerow({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "packet_length": 0, "packets_per_minute": 0, "status": "Blocked, Outgoing"})

    def display_lists():
        print("Allowed IPs:")
        for ip in allowed_ips:
            print(f"  {ip}")
        print("Blocked IPs:")
        for ip in blocked_ips:
            print(f"  {ip}")

    def display_help():
        print("Commands:")
        print("  start - Start packet capture")
        print("  pause - Pause packet capture")
        print("  q - Quit")
        print("  h - Display help")
        print("  allow <ip> - Allow traffic from the specified IP and remove it from the blocked list")
        print("  block <ip> - Block traffic from the specified IP and remove it from the allowed list")
        print("  show - Display the lists of allowed and blocked IPs")

    display_help()

    while True:
        user_input = input("Enter a command: ")

        if user_input == 'start':
            if not running:
                print("Starting packet capture...")
                running = True
                # Start capturing packets
                # filter_expression = "ip"
                sniff(iface="eth0", prn=packet_handler)
            else:
                print("The capture is already running.")
        elif user_input == 'pause':
            if running:
                print("Pausing packet capture...")
                running = False
            else:
                print("The capture is already paused.")
        elif user_input == 'q':
            print("Quitting...")
            break
        elif user_input == 'h':
            display_help()
        elif user_input.startswith('allow '):
            ip_to_allow = user_input.split(' ')[1]
            allow_ip(ip_to_allow)
        elif user_input.startswith('block '):
            ip_to_block = user_input.split(' ')[1]
            block_ip(ip_to_block)
        elif user_input == 'show':
            display_lists()
        else:
            print("Invalid command. Type 'h' for help.")

# Calculate and print statistics after capturing packets
# You can add more statistics printing here based on your needs
print(f"Total Forward Packets: {total_fwd_packets}")
print(f"Total Length of Forward Packets: {total_length_fwd_packets}")
print(f"Forward Packet Length Max: {fwd_packet_length_max}")
print(f"Forward Packet Length Min: {fwd_packet_length_min}")
