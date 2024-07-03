import tkinter as tk
from tkinter import ttk
from scapy.all import *
import threading
import time

def create_and_send_icmp_packet(destination_ip, count, source_ip=None, icmp_type=8, icmp_code=0, payload=""):
    if source_ip:
        ip_packet = IP(src=source_ip, dst=destination_ip) / ICMP(type=icmp_type, code=icmp_code) / payload
    else:
        ip_packet = IP(dst=destination_ip) / ICMP(type=icmp_type, code=icmp_code) / payload
    send(ip_packet, count=count)
    update_chat(f"Sent ICMP packet to {destination_ip} with payload: {payload}")

def create_and_send_tcp_packet(destination_ip, destination_port, count, source_ip=None, tcp_flags="S", payload="", source_port=None):
    if source_ip and source_port:
        tcp_packet = IP(src=source_ip, dst=destination_ip) / TCP(sport=source_port, dport=destination_port, flags=tcp_flags) / payload
    elif source_ip:
        tcp_packet = IP(src=source_ip, dst=destination_ip) / TCP(dport=destination_port, flags=tcp_flags) / payload
    elif source_port:
        tcp_packet = IP(dst=destination_ip) / TCP(sport=source_port, dport=destination_port, flags=tcp_flags) / payload
    else:
        tcp_packet = IP(dst=destination_ip) / TCP(dport=destination_port, flags=tcp_flags) / payload
    send(tcp_packet, count=count)
    update_chat(f"Sent TCP packet to {destination_ip}:{destination_port} with payload: {payload}")

def create_and_send_udp_packet(destination_ip, destination_port, count, source_ip=None, payload="", source_port=None):
    if source_ip and source_port:
        udp_packet = IP(src=source_ip, dst=destination_ip) / UDP(sport=source_port, dport=destination_port) / payload
    elif source_ip:
        udp_packet = IP(src=source_ip, dst=destination_ip) / UDP(dport=destination_port) / payload
    elif source_port:
        udp_packet = IP(dst=destination_ip) / UDP(sport=source_port, dport=destination_port) / payload
    else:
        udp_packet = IP(dst=destination_ip) / UDP(dport=destination_port) / payload
    send(udp_packet, count=count)
    update_chat(f"Sent UDP packet to {destination_ip}:{destination_port} with payload: {payload}")

def send_packets():
    username = username_entry.get()
    destination_ip = dest_ip_entry.get()
    source_ip = src_ip_entry.get() if src_ip_entry.get() else None
    count = int(count_entry.get()) if count_entry.get().isdigit() else 1
    destination_port = int(tcp_dest_port_entry.get()) if tcp_dest_port_entry.get() and tcp_dest_port_entry.get().isdigit() else None
    source_port = int(tcp_src_port_entry.get()) if tcp_src_port_entry.get() and tcp_src_port_entry.get().isdigit() else None
    payload = payload_entry.get() if payload_entry.get() else ""
    if packet_type.get() == 'ICMP':
        icmp_type = int(icmp_type_entry.get()) if icmp_type_entry.get().isdigit() else 8
        icmp_code = int(icmp_code_entry.get()) if icmp_code_entry.get().isdigit() else 0
        create_and_send_icmp_packet(destination_ip, count, source_ip, icmp_type, icmp_code, payload)
    elif packet_type.get() == 'TCP':
        tcp_flags = tcp_flags_entry.get() if tcp_flags_entry.get() else "S"
        create_and_send_tcp_packet(destination_ip, destination_port, count, source_ip, tcp_flags, payload)
    elif packet_type.get() == 'UDP':
        destination_port = int(udp_dest_port_entry.get()) if udp_dest_port_entry.get() and udp_dest_port_entry.get().isdigit() else None
        source_port = int(udp_src_port_entry.get()) if udp_src_port_entry.get() and udp_src_port_entry.get().isdigit() else None
        create_and_send_udp_packet(destination_ip, destination_port, count, source_ip, payload)
    update_chat(f"{username} sent a packet with payload: {payload}")

def decode_payload(pkt):
    if pkt.haslayer(IP):
        ip_layer = pkt.getlayer(IP)
        if ip_layer.dst == sniff_ip_entry.get():
            if pkt.haslayer(Raw):
                raw_data = pkt.getlayer(Raw).load
                try:
                    decoded_payload = raw_data.decode('utf-8')
                    update_chat(f"Received packet with decoded payload: {decoded_payload}")
                except UnicodeDecodeError:
                    pass

def start_sniffing_thread():
    sniff_ip = sniff_ip_entry.get()
    delay = int(sniff_delay_entry.get()) if sniff_delay_entry.get().isdigit() else 0
    threading.Thread(target=start_sniffing, args=(sniff_ip, delay), daemon=True).start()

def start_sniffing(sniff_ip, delay):
    time.sleep(delay)
    sniff(filter=f"ip dst {sniff_ip}", prn=decode_payload)

def update_chat(message):
    username = username_entry.get()
    chat_text.configure(state='normal')
    chat_text.insert(tk.END, f"{username}: {message}\n")
    chat_text.configure(state='disabled')
    chat_text.see(tk.END)

def update_settings_frame():
    icmp_frame.grid_remove()
    tcp_frame.grid_remove()
    udp_frame.grid_remove()
    if packet_type.get() == 'ICMP':
        icmp_frame.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
    elif packet_type.get() == 'TCP':
        tcp_frame.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
    elif packet_type.get() == 'UDP':
        udp_frame.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

# Create the main window
root = tk.Tk()
root.title("Packet Generator")

# Username and Chat
ttk.Label(root, text="Username:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
username_entry = ttk.Entry(root)
username_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

chat_frame = ttk.LabelFrame(root, text="Chat")
chat_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
chat_text = tk.Text(chat_frame, height=10, state='disabled')
chat_text.pack(fill="both", expand=True, padx=5, pady=5)

# Create a frame for the packet type selection
packet_type_frame = ttk.LabelFrame(root, text="Packet Type")
packet_type_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
packet_type = tk.StringVar(value="ICMP")
icmp_radio = ttk.Radiobutton(packet_type_frame, text="ICMP", variable=packet_type, value="ICMP", command=update_settings_frame)
tcp_radio = ttk.Radiobutton(packet_type_frame, text="TCP", variable=packet_type, value="TCP", command=update_settings_frame)
udp_radio = ttk.Radiobutton(packet_type_frame, text="UDP", variable=packet_type, value="UDP", command=update_settings_frame)
icmp_radio.grid(row=0, column=0, padx=5, pady=5)
tcp_radio.grid(row=0, column=1, padx=5, pady=5)
udp_radio.grid(row=0, column=2, padx=5, pady=5)

# Destination IP
ttk.Label(root, text="Destination IP:").grid(row=3, column=0, padx=10, pady=5, sticky="w")
dest_ip_entry = ttk.Entry(root)
dest_ip_entry.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

# Source IP
ttk.Label(root, text="Source IP (optional):").grid(row=4, column=0, padx=10, pady=5, sticky="w")
src_ip_entry = ttk.Entry(root)
src_ip_entry.grid(row=4, column=1, padx=10, pady=5, sticky="ew")

# Number of Packets
ttk.Label(root, text="Number of Packets:").grid(row=5, column=0, padx=10, pady=5, sticky="w")
count_entry = ttk.Entry(root)
count_entry.grid(row=5, column=1, padx=10, pady=5, sticky="ew")

# ICMP Settings
icmp_frame = ttk.LabelFrame(root, text="ICMP Settings")
ttk.Label(icmp_frame, text="ICMP Type:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
icmp_type_entry = ttk.Entry(icmp_frame)
icmp_type_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
ttk.Label(icmp_frame, text="ICMP Code:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
icmp_code_entry = ttk.Entry(icmp_frame)
icmp_code_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

# TCP Settings
tcp_frame = ttk.LabelFrame(root, text="TCP Settings")
ttk.Label(tcp_frame, text="Source Port (TCP):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
tcp_src_port_entry = ttk.Entry(tcp_frame)
tcp_src_port_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
ttk.Label(tcp_frame, text="Destination Port (TCP):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
tcp_dest_port_entry = ttk.Entry(tcp_frame)
tcp_dest_port_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
ttk.Label(tcp_frame, text="TCP Flags:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
tcp_flags_entry = ttk.Entry(tcp_frame)
tcp_flags_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

# UDP Settings
udp_frame = ttk.LabelFrame(root, text="UDP Settings")
ttk.Label(udp_frame, text="Source Port (UDP):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
udp_src_port_entry = ttk.Entry(udp_frame)
udp_src_port_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
ttk.Label(udp_frame, text="Destination Port (UDP):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
udp_dest_port_entry = ttk.Entry(udp_frame)
udp_dest_port_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

# Payload
ttk.Label(root, text="Payload:").grid(row=7, column=0, padx=10, pady=5, sticky="w")
payload_entry = ttk.Entry(root)
payload_entry.grid(row=7, column=1, padx=10, pady=5, sticky="ew")

# Sniff IP
ttk.Label(root, text="Sniff IP:").grid(row=8, column=0, padx=10, pady=5, sticky="w")
sniff_ip_entry = ttk.Entry(root)
sniff_ip_entry.grid(row=8, column=1, padx=10, pady=5, sticky="ew")

# Sniff Delay
ttk.Label(root, text="Sniff Delay (seconds):").grid(row=9, column=0, padx=10, pady=5, sticky="w")
sniff_delay_entry = ttk.Entry(root)
sniff_delay_entry.grid(row=9, column=1, padx=10, pady=5, sticky="ew")

# Send Button
send_button = ttk.Button(root, text="Send Packets", command=send_packets)
send_button.grid(row=10, column=0, padx=10, pady=10)

# Sniff Button
sniff_button = ttk.Button(root, text="Start Sniffing", command=start_sniffing_thread)
sniff_button.grid(row=10, column=1, padx=10, pady=10)

# Run the application
update_settings_frame() # Update settings frame initially
root.mainloop()
