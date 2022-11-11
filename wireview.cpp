// callback function
/*
• Print the start date and time of the packet capture.
• Print the duration of the packet capture in seconds with microsecond resolution.
• Print the total number of packets.
• Create two lists, one for unique senders and one for unique recipients, along with the total number
of packets associated with each. This should be done at two layers: Ethernet and IP. For Ethernet,
represent the addresses in hex-colon notation. For IP addresses, use the standard dotted decimal
notation.
• Create a list of machines participating in ARP, including their associated MAC addresses and, where
possible, the associated IP addresses.
• For UDP, create two lists for the unique ports seen: one for the source ports and one for the destination
ports.
• Report the average, minimum, and maximum packet sizes. The packet size refers to everything beyond
the tcpdump header.
*/

//  Open an input file using function pcap open offline().

// Check that the data you are provided has been captured from Ethernet using function pcap datalink().

//  Read packets from the file using function pcap loop().

// Close the file using function pcap close().