from scapy.all import rdpcap, IP, TCP, UDP, DNSQR
from collections import Counter

pcap_file = "2024-07-30-traffic-analysis-exercise.pcap"

print("Loading PCAP file...")

packets = rdpcap(pcap_file)

print("Total packets:", len(packets))


# Lists for storing evidence

source_ips = [] 
destination_ips = []
connections = []
domains = []
ports = []


for packet in packets:

    # Extract IP information
    if IP in packet:

        src = packet[IP].src
        dst = packet[IP].dst

        source_ips.append(src)
        destination_ips.append(dst)

        connections.append(f"{src} -> {dst}")


    # Extract TCP ports
    if TCP in packet:

        ports.append(packet[TCP].dport)


    # Extract UDP ports
    elif UDP in packet:

        ports.append(packet[UDP].dport)


    # Extract DNS domains
    if packet.haslayer(DNSQR):

        try:

            domain = packet[DNSQR].qname.decode()

            domains.append(domain)

        except:

            pass


# Count results

source_ip_count = Counter(source_ips)
destination_ip_count = Counter(destination_ips)
connection_count = Counter(connections)
port_count = Counter(ports)
domain_count = Counter(domains)


print("\n==============================")
print("TOP SOURCE IP ADDRESSES")
print("==============================")

for ip, count in source_ip_count.most_common(10):

    print(ip, ":", count)


print("\n==============================")
print("TOP DESTINATION IP ADDRESSES")
print("==============================")

for ip, count in destination_ip_count.most_common(10):
    print(connection, ":", count)

print("\n==============================")
print("MOST USED PORTS")
print("==============================")

for port, count in port_count.most_common(10):

    print("Port", port, ":", count)


print("\n==============================")
print("DNS DOMAINS")
print("==============================")

for domain, count in domain_count.most_common(20):

    print(domain, ":", count)