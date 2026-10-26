# STRRAT Malware Traffic Analysis & Network Threat Hunting

## Project Overview

This project investigates suspected STRRAT malware command-and-control (C2) communication using a publicly available PCAP file. The investigation combines Wireshark and Python (Scapy) to identify suspicious network connections, analyze TCP payloads, extract indicators of compromise (IOCs), and detect periodic beaconing behavior.

## Tools Used

- Wireshark – Network traffic analysis and TCP stream inspection
- Python – Automated PCAP analysis
- Scapy – Packet parsing and timestamp extraction
- Kali Linux – Analysis environment

## Investigation Methodology

1. Analyzed 11,562 packets using Wireshark and Python.
2. Identified frequently communicating IP addresses and destination ports.
3. Investigated suspicious communication between `172.16.1.66` and `141.98.10.79` over TCP port `12132`.
4. Examined TCP streams containing STRRAT-related messages.
5. Calculated the intervals between recurring messages using Python.
6. Extracted network indicators and examined transmitted host information.

## Key Findings

| Finding | Observation |
|---|---|
| Suspected Malware | STRRAT |
| Internal Host | 172.16.1.66 |
| External Host | 141.98.10.79 |
| Destination Port | TCP 12132 |
| Matching Beacon Packets | 102 |
| Average Beaconing Interval | 5.026 seconds |
| Payload Evidence | `ping\|STRRAT` |
| Additional Information | Host information and Base64-encoded window titles |

The findings are consistent with suspected automated malware C2 communication. The analysis does not establish credential theft, file exfiltration, or remote command execution.

## Project Report

See [Investigation Report](report/STRRAT-Investigation-Report.pdf) for methodology, screenshots, findings, and response recommendations.

## Dataset Source

[Malware Traffic Analysis – July 30, 2024 Exercise](https://www.malware-traffic-analysis.net/2024/07/30/index.html)

## Disclaimer

This is an educational network threat hunting project conducted using a publicly available malware traffic capture. No live systems were targeted, and the findings are limited to the available network evidence.
