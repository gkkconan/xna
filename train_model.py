# eNanalyser - Network analysis tool
# Copyright (c) 2025 Manuel Sarullo
# Licensed under the GNU General Public License v3.0 (GPL-3.0)


import numpy as np
from sklearn.ensemble import IsolationForest
from joblib import dump
import pyshark

# Parameters
iface = str(input("\nSET YOUR INTERFACE (ex. Wi-Fi): "))
interface = iface  

cap_duration = int(input("\nSET THE CAPTURE DURATION (In secs ex. 600 (10 min)): "))
capture_duration_sec = cap_duration  # Capture traffic for 10 minutes

cont_rate = float(input("\nSET THE CONTAMINATION RATE (ex. 0.05): "))
contamination_rate = cont_rate  # Percentage of expected anomalies in training data

# Extract features from packets grouped by source IP
def extract_features_from_packets(packets):
    from collections import defaultdict
    ip_packets = defaultdict(list)
    for pkt in packets:
        if hasattr(pkt, 'ip'):
            ip_packets[pkt.ip.src].append(pkt)

    features_list = []
    for ip, pkts in ip_packets.items():
        count_packets = len(pkts)
        protocols = set(p.highest_layer for p in pkts)
        count_protocols = len(protocols)
        avg_len = np.mean([int(p.length) for p in pkts])
        features_list.append([count_packets, count_protocols, avg_len])
    return features_list

def main():
    print("\n[*] Capturing packets for training...")
    capture = pyshark.LiveCapture(interface=interface)
    packets = []
    start_time = None

    for pkt in capture.sniff_continuously():
        packets.append(pkt)
        if start_time is None:
            start_time = pkt.sniff_time
        elapsed = (pkt.sniff_time - start_time).total_seconds()
        if elapsed > capture_duration_sec:
            break

    print(f"[*] Extracting features from {len(packets)} packets...")
    features = extract_features_from_packets(packets)
    X = np.array(features)

    print(f"[*] Training data contains {len(X)} samples.")
    if len(X) < 10:
        print("[!] WARNING: Not enough training data. Consider increasing capture duration or generating more traffic.")

    print("[*] Training Isolation Forest model...")
    model = IsolationForest(contamination=contamination_rate, random_state=42)
    model.fit(X)

    print("[*] Saving model to 'isoforest_model.pkl'...")
    dump(model, "isoforest_model.pkl")
    print("[*] Done.")

if __name__ == "__main__":
    main()
