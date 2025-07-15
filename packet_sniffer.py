import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP
import datetime

# Global control
sniffing = False
sniffer_thread = None

def analyze_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        size = len(packet)
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_line = f"[{timestamp}] {src} -> {dst} | {proto} | Size: {size}\n"
        output_text.insert(tk.END, log_line)
        output_text.see(tk.END)

def start_sniffing():
    global sniffing, sniffer_thread
    if sniffing:
        messagebox.showinfo("Info", "Sniffer is already running.")
        return
    sniffing = True
    filter_str = filter_entry.get().strip()
    output_text.insert(tk.END, f"🔎 Starting capture with filter: '{filter_str or 'none'}'...\n")
    sniffer_thread = threading.Thread(target=run_sniffer, args=(filter_str,), daemon=True)
    sniffer_thread.start()

def run_sniffer(filter_str):
    try:
        sniff(filter=filter_str if filter_str else None, prn=analyze_packet, store=0, stop_filter=lambda x: not sniffing)
    except Exception as e:
        output_text.insert(tk.END, f"❌ Error: {str(e)}\n")

def stop_sniffing():
    global sniffing
    if not sniffing:
        messagebox.showinfo("Info", "Sniffer is not running.")
        return
    sniffing = False
    output_text.insert(tk.END, "⏹️ Capture stopped.\n")

def clear_logs():
    output_text.delete(1.0, tk.END)

def export_logs():
    try:
        with open("packet_logs.txt", "w") as f:
            f.write(output_text.get(1.0, tk.END))
        messagebox.showinfo("Export", "Logs exported to packet_logs.txt")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Setup
root = tk.Tk()
root.title("Network Packet Sniffer")
root.geometry("700x500")

tk.Label(root, text="Filter (e.g. 'tcp', 'udp', or 'host 8.8.8.8'):", font=("Arial", 11)).pack(pady=5)
filter_entry = tk.Entry(root, width=50, font=("Arial", 11))
filter_entry.pack(pady=2)

button_frame = tk.Frame(root)
button_frame.pack(pady=5)

tk.Button(button_frame, text="Start Sniffing", command=start_sniffing, bg="green", fg="white", width=15).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing, bg="red", fg="white", width=15).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Clear Logs", command=clear_logs, bg="gray", fg="white", width=15).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Export Logs", command=export_logs, bg="blue", fg="white", width=15).pack(side=tk.LEFT, padx=5)

output_text = scrolledtext.ScrolledText(root, width=85, height=25, font=("Courier", 10))
output_text.pack(pady=5)

output_text.insert(tk.END, "Ready to capture packets...\n")
root.mainloop()

