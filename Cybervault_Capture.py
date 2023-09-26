#!/usr/bin/env python
# coding: utf-8

# In[ ]:


from scapy.all import *
import numpy as np
from tensorflow import keras
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report
from sklearn.metrics import accuracy_score
import pandas as pd
import socket
import statistics
import time
import joblib

model = keras.models.load_model('/home/kali/CyberVault/CyberVault_IDS_Model/CyberVault_IDS')

scaler = StandardScaler()
scaler.mean_ = np.load('/home/kali/CyberVault/CyberVault_IDS_Model/scaler_mean.npy')
scaler.scale_ = np.load('/home/kali/CyberVault/CyberVault_IDS_Model/scaler_scale.npy')
label_encoder = joblib.load('/home/kali/CyberVault/CyberVault_IDS_Model/label_encoder.pkl')

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind(('0.0.0.0', 12345)) # placeholder values

client_ip, _ = sock.getsockname()


column_names = ["Total Length of Fwd Packets", " Total Length of Bwd Packets", " Fwd Packet Length Max", 
                " Fwd Packet Length Min", " Fwd Packet Length Mean", " Fwd Packet Length Std", "Bwd Packet Length Max", 
                " Bwd Packet Length Min", " Bwd Packet Length Mean", " Bwd Packet Length Std", "Flow Bytes/s", 
                " Flow Packets/s", " Flow IAT Mean", " Flow IAT Std", " Flow IAT Max", " Flow IAT Min", "Fwd IAT Total", 
                " Fwd IAT Mean", " Fwd IAT Std", " Fwd IAT Max", " Fwd IAT Min", "Bwd IAT Total", " Bwd IAT Mean", 
                " Bwd IAT Std", " Bwd IAT Max", " Bwd IAT Min", " SYN Flag Count", " RST Flag Count", " PSH Flag Count", 
                " ACK Flag Count", " Down/Up Ratio", " Average Packet Size"," Avg Fwd Segment Size", " Avg Bwd Segment Size", 
                " Flow Duration", "Active Mean", " Active Std", " Active Max", " Active Min", "Idle Mean", " Idle Std", " Idle Max", " Idle Min"]

df = pd.DataFrame(columns=column_names)

total_fwd_length = 0
total_bwd_length = 0
fwd_lengths = []
bwd_lengths = []

start_time = time.time()
total_bytes = 0
last_pkt_time = start_time

fwd_iat_list = []
bwd_iat_list = []
flow_iat_list = []

fwd_IAT_total = 0
bwd_IAT_total = 0

total_pkts = 0
last_pkt_count_time = start_time

SYN_flag_count = 0
RST_flag_count = 0
PSH_flag_count = 0
ACK_flag_count = 0

down_count = 0
up_count = 0

active_times = []
idle_times = []

def process_packet(packet):
    
    global df, model, label_encoder, scaler, total_fwd_length, total_bwd_length, fwd_lengths, bwd_lengths, start_time, total_bytes, last_pkt_time, total_pkts, last_pkt_count_time, fwd_IAT_total, bwd_IAT_total, SYN_flag_count, RST_flag_count, PSH_flag_count, ACK_flag_count, down_count, up_count, active_times, idle_times 
    
    if TCP in packet:
        flags = packet[TCP].flags
        if flags & 0x02:
            SYN_flag_count += 1
        if flags & 0x04:
            RST_flag_count += 1
        if flags & 0x08:
            PSH_flag_count += 1
        if flags & 0x10:
            ACK_flag_count += 1
    
    if IP in packet and packet[IP].src == client_ip:
        total_fwd_length += packet[IP].len
        fwd_lengths.append(packet[IP].len)
        fwd_iat = time.time() - last_packet_time
        fwd_iat_list.append(fwd_iat)
        flow_iat_list.append(fwd_iat)
        fwd_IAT_total += fwd_iat
        down_count += 1
        active_times.append(fwd_iat)
        
    elif IP in packet and packet[IP].dst == client_ip:
        total_bwd_length += packet[IP].len
        bwd_lengths.append(packet[IP].len)
        bwd_iat = time.time() - last_packet_time
        bwd_iat_list.append(bwd_iat)
        flow_iat_list.append(bwd_iat)
        bwd_IAT_total += bwd_iat
        up_count += 1
        active_times.append(bwd_iat)
        
    if fwd_lengths:
        fwd_length_min = min(fwd_lengths)
        fwd_length_max = max(fwd_lengths)
        fwd_length_mean = statistics.mean(fwd_lengths)
        fwd_length_std = statistics.stdev(fwd_lengths)
    else:
        fwd_length_min = fwd_length_max = fwd_length_mean = fwd_length_std = 0

    if bwd_lengths:
        bwd_length_min = min(bwd_lengths)
        bwd_length_max = max(bwd_lengths)
        bwd_length_mean = statistics.mean(bwd_lengths)
        bwd_length_std = statistics.stdev(bwd_lengths)
    else:
        bwd_length_min = bwd_length_max = bwd_length_mean = bwd_length_std = 0
        
    if IP in packet:
        total_bytes += packet[IP].len
    
    elapsed_time = time.time() - start_time
    if elapsed_time > 0:
        flow_bytes_perSec = total_bytes / elapsed_time
    else: 
    	flow_bytes_perSec = 0    
        
    pkt_count_time = time.time()
    if pkt_count_time - last_pkt_count_time > 1:  # Calculate over a 1-second interval
        flow_pkts_perSec = total_pkts / (pkt_count_time - last_pkt_count_time)
        last_pkt_count_time = pkt_count_time
    else: 
    	flow_pkts_perSec = 0
    	last_pkt_count_time = pkt_count_time
    	    
    
    if flow_iat_list:
        flow_IAT_mean = statistics.mean(flow_iat_list)
        flow_IAT_std = statistics.stdev(flow_iat_list)
        flow_IAT_max = max(flow_iat_list)
        flow_IAT_min = min(flow_iat_list)
    else: 
    	flow_IAT_mean = flow_IAT_std = flow_IAT_max = flow_IAT_min = 0     
	       
    
    if fwd_iat_list:
        fwd_IAT_mean = statistics.mean(fwd_iat_list)
        fwd_IAT_std = statistics.stdev(fwd_iat_list)
        fwd_IAT_max = max(fwd_iat_list)
        fwd_IAT_min = min(fwd_iat_list)
    else:
    	fwd_IAT_mean = fwd_IAT_std = fwd_IAT_max = fwd_IAT_min = 0
        

    if bwd_iat_list:
        bwd_IAT_mean = statistics.mean(bwd_iat_list)
        bwd_IAT_std = statistics.stdev(bwd_iat_list)
        bwd_IAT_max = max(bwd_iat_list)
        bwd_IAT_min = min(bwd_iat_list)
    else:
    	bwd_IAT_mean = bwd_IAT_std = bwd_IAT_max = bwd_IAT_min = 0    
    
    if up_count > 0:
        down_up_ratio = down_count / up_count
    else: 
    	down_up_ratio = 0    
        
    if (len(fwd_lengths)+len(bwd_lengths)) > 0:
    	avg_pkt_size = (total_fwd_length + total_bwd_length) / (len(fwd_lengths) + len(bwd_lengths))
    else:
    	avg_pkt_size = 0	
    
    if fwd_lengths:
        avg_fwd_seg_size = total_fwd_length / len(fwd_lengths)
    else:
    	avg_fwd_seg_size = 0

    if bwd_lengths:
        avg_bwd_seg_size = total_bwd_length / len(bwd_lengths)
    else:
    	avg_bwd_seg_size = 0     
        
    end_time = time.time()
    flow_duration = end_time - start_time
    
    last_packet_time = time.time()
    
    if len(active_times) > 1:
        idle_time = time.time() - last_packet_time
        idle_times.append(idle_time)
    
    if active_times:
        active_mean = statistics.mean(active_times)
        active_std = statistics.stdev(active_times)
        active_max = max(active_times)
        active_min = min(active_times)
    else:
    	active_mean = active_std = active_max = active_min = 0    
   
    if idle_times:
        idle_mean = statistics.mean(idle_times)
        idle_std = statistics.stdev(idle_times)
        idle_max = max(idle_times)
        idle_min = min(idle_times)
    else:
    	idle_mean = idle_std = idle_max = idle_min = 0  
          
    
    packet_dict = {
        "Total Length of Fwd Packets": total_fwd_length,
        " Total Length of Bwd Packets": total_bwd_length,
        " Fwd Packet Length Max": fwd_length_max, 
        " Fwd Packet Length Min": fwd_length_min, 
        " Fwd Packet Length Mean": fwd_length_mean, 
        " Fwd Packet Length Std": fwd_length_std, 
        "Bwd Packet Length Max": bwd_length_max, 
        " Bwd Packet Length Min": bwd_length_min, 
        " Bwd Packet Length Mean": bwd_length_mean, 
        " Bwd Packet Length Std": bwd_length_std, 
        "Flow Bytes/s": flow_bytes_perSec, 
        " Flow Packets/s": flow_pkts_perSec, 
        " Flow IAT Mean": flow_IAT_mean, 
        " Flow IAT Std": flow_IAT_std, 
        " Flow IAT Max": flow_IAT_max, 
        " Flow IAT Min": flow_IAT_min, 
        "Fwd IAT Total": fwd_IAT_total, 
        " Fwd IAT Mean": fwd_IAT_mean, 
        " Fwd IAT Std": fwd_IAT_std, 
        " Fwd IAT Max": fwd_IAT_max, 
        " Fwd IAT Min": fwd_IAT_min, 
        "Bwd IAT Total": bwd_IAT_total, 
        " Bwd IAT Mean": bwd_IAT_mean, 
        " Bwd IAT Std": bwd_IAT_std, 
        " Bwd IAT Max": bwd_IAT_max, 
        " Bwd IAT Min": bwd_IAT_min, 
        " SYN Flag Count": SYN_flag_count, 
        " RST Flag Count": RST_flag_count, 
        " PSH Flag Count": PSH_flag_count, 
        " ACK Flag Count": ACK_flag_count, 
        " Down/Up Ratio": down_up_ratio, 
        " Average Packet Size": avg_pkt_size,
        " Avg Fwd Segment Size": avg_fwd_seg_size, 
        " Avg Bwd Segment Size": avg_bwd_seg_size, 
        " Flow Duration": flow_duration, 
        "Active Mean": active_mean, 
        " Active Std": active_std, 
        " Active Max": active_max, 
        " Active Min": active_min, 
        "Idle Mean": idle_mean, 
        " Idle Std": idle_std, 
        " Idle Max": idle_max, 
        " Idle Min": idle_min
    }
    
    df.loc[len(df)] = packet_dict

    df_scaled = scaler.transform(df[column_names])

    prediction_probs = model.predict(df_scaled)
    predicted_class = np.argmax(prediction_probs, axis=-1)
    
    predicted_label = label_encoder.inverse_transform(predicted_class)
    
    print(f"Predicted Label: {predicted_label}")
    
    with open("IDS_output.txt", "w") as file:
    	file.write(f"Predicted Label: {predicted_label}")

interface = "eth0"  # Change this to the appropriate interface


sniff(iface=interface, prn=process_packet)

