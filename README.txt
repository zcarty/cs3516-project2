Zeb Carty and Michael McInerney

Program that outputs statistics for tcpdump files.

To run:
run 'make wireview'
run './wireview <FILENAME>' with pcap file you want statistics for

wireview will output the following statistics in the terminal:
• The start date and time of the packet capture.
• The duration of the packet capture in seconds with microsecond resolution.
• The total number of packets.
• Unique senders and unique recipients, along with the total number of packets associated with each.
• A list of machines participating in ARP, including their associated MAC addresses and, where
possible, the associated IP addresses.
• For UDP, two lists for the unique ports seen: one for the source ports and one for the destination
ports.
• The average, minimum, and maximum packet sizes.