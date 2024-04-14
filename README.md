# BASIC_NETWORK_SNIFFER


First, install scapy. It's a powerful Python library used for network packet manipulation and sniffing. You can install it using pip:



```
pip install scapy
```

# How the Code Works:
1- Import Libraries: Import necessary classes and functions from Scapy.


2- Define a Callback Function: This function packet_callback is called whenever a packet is captured. It checks if the packet has an IP layer and, if it does, extracts source and destination IP addresses. If the packet also has a TCP layer, it extracts source and destination ports.


3- Start Sniffing: The start_sniffing() function starts the packet sniffing. The sniff() function from Scapy is used, specifying packet_callback as the callback function for each captured packet and store=False to prevent storing all packets in memory.


4- Run the Sniffer: The script runs the sniffer if it's the main module.
# Running the Sniffer
Run the script from a terminal or command prompt with administrative privileges:

```
sudo python network_sniffer.py
```
