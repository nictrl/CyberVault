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

# Define the allowed and blocked ports
allowed_ports = [80, 8080]
blocked_ports = [22, 23, 443]

allowed_protocols = ["TCP"]
blocked_protocols = ["ICMP"]

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
    fieldnames = [
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_length", "packets_per_minute", "status",
        "flow_duration", "syn_flag", "rst_flag", "psh_flag", "ack_flag",
        "iat_mean", "iat_std", "iat_max", "iat_min",
        "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
        "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
        "down_up_ratio",
        "avg_packet_size", "avg_fwd_segment_size", "avg_bwd_segment_size",
        "fwd_header_length", "bwd_header_length",
        "active_mean", "active_std", "active_max", "active_min",
        "idle_mean", "idle_std", "idle_max", "idle_min"
    ]
    writer = csv.DictWriter(file, fieldnames=fieldnames)

    # Write the header row
    writer.writeheader()

    running = False

    # Initialize a dictionary to store the last packet time for each flow (source IP, destination IP, source port, destination port)
    last_packet_time = {}

    def calculate_inter_arrival_time(packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flow_key = f"{src_ip}:{dst_ip}"

        if flow_key not in last_packet_time:
            last_packet_time[flow_key] = time.time()
            return 0  # No previous packet, IAT is 0

        current_time = time.time()
        iat = current_time - last_packet_time[flow_key]
        last_packet_time[flow_key] = current_time

        return iat

    def calculate_flow_duration(packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flow_key = (src_ip, dst_ip)

        if flow_key in last_packet_time:
            last_time = last_packet_time[flow_key]
            current_time = time.time()
            flow_duration = current_time - last_time
            return flow_duration
        else:
            last_packet_time[flow_key] = time.time()
            return 0  # Return 0 for the first packet in the flow

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

    def get_source_and_dest_ports(packet):
        src_port = None
        dst_port = None

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        return src_port, dst_port

    def is_port_allowed(src_port, dst_port, protocol):
        if (src_port, dst_port) in allowed_ports:
            return True
        elif src_port in allowed_ports or dst_port in allowed_ports:
            return True
        elif protocol == "TCP" and (src_port in blocked_ports or dst_port in blocked_ports):
            return False
        else:
            return True

    def count_tcp_flags(packet):
        syn_flag = packet[TCP].flags & 0x02  # Check if SYN flag is set
        rst_flag = packet[TCP].flags & 0x04  # Check if RST flag is set
        psh_flag = packet[TCP].flags & 0x08  # Check if PSH flag is set
        ack_flag = packet[TCP].flags & 0x10  # Check if ACK flag is set

        return syn_flag, rst_flag, psh_flag, ack_flag

    def calculate_packet_sizes(packet):
        fwd_segment_size = len(packet[IP])
        bwd_segment_size = 0  # Assuming it's the backward direction

        return fwd_segment_size, bwd_segment_size

    def packet_handler(packet):
        global total_fwd_packets
        global total_length_fwd_packets
        global fwd_packet_length_max, fwd_packet_length_min, fwd_packet_length_sum

        src_port = None
        dst_port = None
        syn_flag = 0  # Initialize syn_flag with a default value
        rst_flag = 0  # Initialize rst_flag with a default value
        psh_flag = 0  # Initialize psh_flag with a default value
        ack_flag = 0  # Initialize ack_flag with a default value

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            syn_flag, rst_flag, psh_flag, ack_flag = count_tcp_flags(packet)

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol_num = packet[IP].proto
            protocol = protocol_names.get(protocol_num, "Unknown")
            status = "Default"  # Default status

            if protocol in allowed_protocols:
                if src_ip in allowed_ips:
                    src_port, dst_port = get_source_and_dest_ports(packet)
                    if is_port_allowed(src_port, dst_port, protocol):
                        print(f"Allowed packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} using protocol {protocol}")
                    else:
                        print(f"Blocked packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} using protocol {protocol}")
                        status = "Blocked"
                elif src_ip in blocked_ips:
                    if dst_ip in allowed_ips:
                        src_port, dst_port = get_source_and_dest_ports(packet)
                        if is_port_allowed(src_port, dst_port, protocol):
                            if protocol not in blocked_protocols:
                                print(f"Blocked packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} using protocol {protocol} (Outgoing)")
                                record_blocked_outgoing(src_ip, dst_ip, protocol)
                            else:
                                print(f"Blocked packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} using protocol {protocol} (Outgoing, Blocked Protocol)")
                        else:
                            if protocol not in blocked_protocols:
                                print(f"Blocked packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} using protocol {protocol}")
                            else:
                                print(f"Blocked packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} using protocol {protocol} (Blocked)")
                            status = "Blocked"
                    else:
                        print(f"Blocked packet from {src_ip} to {dst_ip} using protocol {protocol}")
                        status = "Blocked"
                else:
                    src_port, dst_port = get_source_and_dest_ports(packet)
                    if is_port_allowed(src_port, dst_port, protocol):
                        print(f"Packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} using protocol {protocol}, action: default")
                    else:
                        print(f"Blocked packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} using protocol {protocol}")
                        status = "Blocked"
            else:
                print(f"Packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} using protocol {protocol}")
                status = "Default"

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

                writer.writerow({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "packet_length": packet_length,
                    "packets_per_minute": round(calculate_packets_per_minute(src_ip)),
                    "status": status,
                    "flow_duration": calculate_flow_duration(packet),
                    "syn_flag": syn_flag,
                    "rst_flag": rst_flag,
                    "psh_flag": psh_flag,
                    "ack_flag": ack_flag,
                    "iat_mean": calculate_inter_arrival_time(packet),
                    "iat_std": 0,  # Update this based on your calculation
                    "iat_max": 0,  # Update this based on your calculation
                    "iat_min": 0,  # Update this based on your calculation
                    "fwd_iat_total": 0,  # Update this based on your calculation
                    "fwd_iat_mean": 0,  # Update this based on your calculation
                    "fwd_iat_std": 0,  # Update this based on your calculation
                    "fwd_iat_max": 0,  # Update this based on your calculation
                    "fwd_iat_min": 0,  # Update this based on your calculation
                    "bwd_iat_total": 0,  # Update this based on your calculation
                    "bwd_iat_mean": 0,  # Update this based on your calculation
                    "bwd_iat_std": 0,  # Update this based on your calculation
                    "bwd_iat_max": 0,  # Update this based on your calculation
                    "bwd_iat_min": 0,  # Update this based on your calculation
                    "down_up_ratio": 0,  # Update this based on your calculation
                    "avg_packet_size": 0,  # Update this based on your calculation
                    "avg_fwd_segment_size": 0,  # Update this based on your calculation
                    "avg_bwd_segment_size": 0,  # Update this based on your calculation
                    "fwd_header_length": 0,  # Update this based on your calculation
                    "bwd_header_length": 0,  # Update this based on your calculation
                    "active_mean": 0,  # Update this based on your calculation
                    "active_std": 0,  # Update this based on your calculation
                    "active_max": 0,  # Update this based on your calculation
                    "active_min": 0,  # Update this based on your calculation
                    "idle_mean": 0,  # Update this based on your calculation
                    "idle_std": 0,  # Update this based on your calculation
                    "idle_max": 0,  # Update this based on your calculation
                    "idle_min": 0  # Update this based on your calculation
                })

    # Rest of the code remains the same

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

    def allow_port(port):
        if port not in allowed_ports:
            allowed_ports.append(port)
            if port in blocked_ports:
                blocked_ports.remove(port)
            print(f"PORT {port} added to the allowed list.")
        else:
            print(f"PORT {port} is already allowed.")

    def block_port(port):
        if port not in blocked_ports:
            blocked_ports.append(port)
            if port in allowed_ports:
                allowed_ports.remove(port)
            print(f"PORT {port} added to the blocked list.")
        else:
            print(f"PORT {port} is already blocked.")

    def allow_protocol(protocol):
        if protocol not in allowed_protocols:
            allowed_protocols.append(protocol)
            if protocol in blocked_protocols:
                blocked_protocols.remove(protocol)
            print(f"PROTOCOL {protocol} added to the allowed list.")
        else:
            print(f"PROTOCOL {protocol} is already allowed.")

    def block_protocol(protocol):
        if protocol not in blocked_protocols:
            blocked_protocols.append(protocol)
            if protocol in blocked_protocols:
                allowed_protocols.remove(protocol)
            print(f"PROTOCOL {protocol} added to the blocked list.")
        else:
            print(f"PROTOCOL {protocol} is already blocked.")

    def record_blocked_outgoing(src_ip, dst_ip, protocol):
        writer.writerow({"src_ip": src_ip, "dst_ip": dst_ip, "src_port": "", "dst_port": "", "protocol": protocol, "packet_length": 0, "packets_per_minute": 0, "status": "Blocked, Outgoing"})

    def display_lists():
        print("Allowed IPs:")
        for ip in allowed_ips:
            print(f"  {ip}")
        print("Blocked IPs:")
        for ip in blocked_ips:
            print(f"  {ip}")
        print("Allowed PORTs:")
        for port in allowed_ports:
            print(f"  {port}")
        print("Blocked PORTs:")
        for port in blocked_ports:
            print(f"  {port}")
        print("Allowed PROTOCOLs:")
        for protocol in allowed_protocols:
            print(f"  {protocol}")
        print("Blocked PROTOCOLs:")
        for protocol in blocked_protocols:
            print(f"  {protocol}")

    def display_help():
        print("Commands:")
        print("  start - Start packet capture")
        print("  pause - Pause packet capture")
        print("  q - Quit")
        print("  h - Display help")
        print("  allow_ip <ip> - Allow traffic from the specified IP and remove it from the blocked list")
        print("  block_ip <ip> - Block traffic from the specified IP and remove it from the allowed list")
        print("  allow_port <port> - Allow traffic from the specified PORT and remove it from the blocked list")
        print("  block_port <port> - Block traffic from the specified PORT and remove it from the allowed list")
        print("  allow_protocol <port> - Allow traffic from the specified PROTOCOL and remove it from the blocked list")
        print("  block_protocol <port> - Block traffic from the specified PROTOCOL and remove it from the allowed list")
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
        elif user_input.startswith('allow_ip '):
            ip_to_allow = user_input.split(' ')[1]
            allow_ip(ip_to_allow)
        elif user_input.startswith('block_ip '):
            ip_to_block = user_input.split(' ')[1]
            block_ip(ip_to_block)
        elif user_input.startswith('allow_port '):
            port_to_allow = user_input.split(' ')[1]
            allow_port(port_to_allow)
        elif user_input.startswith('block_port '):
            port_to_block = user_input.split(' ')[1]
            block_port(port_to_block)
        elif user_input.startswith('allow_protocol '):
            protocol_to_allow = user_input.split(' ')[1]
            allow_protocol(protocol_to_allow)
        elif user_input.startswith('block_protocol '):
            protocol_to_block = user_input.split(' ')[1]
            block_protocol(protocol_to_block)
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
