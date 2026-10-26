from scapy.all import rdpcap, IP, TCP, Raw
from statistics import mean, median
from datetime import datetime

packets = rdpcap("2024-07-30-traffic-analysis-exercise.pcap")

timestamps = []

for pkt in packets:
    if IP in pkt and TCP in pkt and Raw in pkt:
        if (pkt[IP].src == "172.16.1.66"
            and pkt[IP].dst == "141.98.10.79"):

            payload = bytes(pkt[Raw].load)

            if b"ping|STRRAT" in payload:
                timestamps.append(float(pkt.time))
                print(
                f"Packet {len(timestamps)}: "
                f"{datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}"
                )

intervals = [
    timestamps[i] - timestamps[i - 1]
    for i in range(1, len(timestamps))
]

print("\nMatching packets:", len(timestamps))

if intervals:
    print("Average interval:", round(mean(intervals), 3), "sec")
    print("Median interval:", round(median(intervals), 3), "sec")
    print("Minimum interval:", round(min(intervals), 3), "sec")
    print("Maximum interval:", round(max(intervals), 3), "sec")
    print("Intervals:", [round(x, 3) for x in intervals])
else:
    print("Not enough matching packets to calculate intervals.")
