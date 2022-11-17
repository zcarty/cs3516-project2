#include "include.h"
#include "callback.h"
using namespace std;

/*
 * callback.cpp
 * Zeb Carty and Michael McInerney
 *
 * Functions to produce packet statistics from tcpdump
 */

time_t min_time = 2e9; // should work for the next ~31 years
suseconds_t min_us;
time_t max_time = 0;
suseconds_t max_us;

unsigned total_packets = 0;
unsigned avg_size = 0;
unsigned min_size = 65535;
unsigned max_size = 0;

/* Linked lists are defined to store packet statistics*/

typedef struct linkedlist
{
    unsigned char address[6];
    unsigned packet_count;
    struct linkedlist *next;
} linkedlist;

typedef struct listarp
{
    unsigned char macaddr[6];
    unsigned char ipaddr[4];
    struct listarp *next;
} listarp;

typedef struct listip
{
    unsigned char ipaddress[4];
    unsigned packets;
    struct listip *next;
} listip;

typedef struct listport
{
    u_int16_t port;
    unsigned port_count;
    struct listport *next;
} listport;

typedef struct sizes
{
    unsigned size;
    struct sizes *next;
} sizes;

linkedlist *senders = NULL;
linkedlist *recipients = NULL;
listarp *participants = NULL;
listip *ip_senders = NULL;
listip *ip_recipients = NULL;
listport *port_senders = NULL;
listport *port_recipients = NULL;
sizes *packet_sizes = NULL;

linkedlist *check_addr(u_char *address, linkedlist *list)
{
    for (; list != NULL; list = list->next)
    {
        bool same = true;
        for (int i = 0; i < 6; i++)
        {
            if (address[i] != list->address[i])
            {
                same = false;
            }
        }
        if (same == true)
            return list;
    }
    return NULL;
}

listarp *check_arp(u_char *address, listarp *list)
{
    for (; list != NULL; list = list->next)
    {
        bool same = true;
        for (int i = 0; i < 6; i++)
        {
            if (address[i] != list->macaddr[i])
            {
                same = false;
            }
        }
        if (same == true)
            return list;
    }
    return NULL;
}

listip *check_ip(u_char *address, listip *list)
{
    for (; list != NULL; list = list->next)
    {
        bool same = true;
        for (int i = 0; i < 4; i++)
        {
            if (address[i] != list->ipaddress[i])
            {
                same = false;
            }
        }
        if (same == true)
            return list;
    }
    return NULL;
}

listport *check_port(u_int16_t port, listport *list)
{
    for (; list != NULL; list = list->next)
    {
        if (port == list->port)
            return list;
    }
    return NULL;
}

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /* Assigns data from packet to linked lists using ethernet header struct*/

    if (header->ts.tv_sec < min_time || ((header->ts.tv_sec == min_time) && (header->ts.tv_usec < min_us)))
    {
        min_time = header->ts.tv_sec;
        min_us = header->ts.tv_usec;
    }
    if (header->ts.tv_sec > max_time || ((header->ts.tv_sec == max_time) && (header->ts.tv_usec > max_us)))
    {
        max_time = header->ts.tv_sec;
        max_us = header->ts.tv_usec;
    }
    total_packets++;

    struct ether_header header_eth = *((struct ether_header *)packet);
    linkedlist *sender = check_addr(header_eth.ether_shost, senders);
    linkedlist *recipient = check_addr(header_eth.ether_dhost, recipients);

    /* If sender/recipient has same address, increase packet count*/
    if (sender != NULL)
    {
        (sender->packet_count)++;
    }
    else
    {
        sender = (linkedlist *)malloc(sizeof(linkedlist));
        sender->packet_count = 1;
        for (int i = 0; i < 6; i++)
        {
            sender->address[i] = header_eth.ether_shost[i];
        }
        sender->next = senders;
        senders = sender;
    }

    if (recipient != NULL)
    {
        (recipient->packet_count)++;
    }
    else
    {
        recipient = (linkedlist *)malloc(sizeof(linkedlist));
        recipient->packet_count = 1;
        for (int i = 0; i < 6; i++)
        {
            recipient->address[i] = header_eth.ether_dhost[i];
        }
        recipient->next = recipients;
        recipients = recipient;
    }

    if (ntohs(header_eth.ether_type) == ETHERTYPE_ARP)
    {

        struct ether_arp arphead = *((struct ether_arp *)(packet + 14)); // ethernet headers are 14 bytes long, exclude these
        listarp *participant = check_arp(arphead.arp_sha, participants);

        if (participant == NULL)
        {
            participant = (listarp *)malloc(sizeof(listarp));
            for (int i = 0; i < 6; i++)
            {
                participant->macaddr[i] = arphead.arp_sha[i];
            }
            for (int i = 0; i < 4; i++)
            {
                participant->ipaddr[i] = arphead.arp_spa[i];
            }
            participant->next = participants;
            participants = participant;
        }

        participant = check_arp(arphead.arp_tha, participants);

        if (participant == NULL)
        {
            participant = (listarp *)malloc(sizeof(listarp));
            for (int i = 0; i < 6; i++)
            {
                participant->macaddr[i] = arphead.arp_tha[i];
            }
            for (int i = 0; i < 4; i++)
            {
                participant->ipaddr[i] = arphead.arp_tpa[i];
            }
            participant->next = participants;
            participants = participant;
        }
    }
    else if (ntohs(header_eth.ether_type) == ETHERTYPE_IP)
    {

        struct ip iphead = *((struct ip *)(packet + 14)); // exclude ethernet header, CHANGE TO iphdr WHEN MIGRATING TO LINUX
        u_char *sender_ip = (u_char *)&iphead.ip_src.s_addr;
        listip *sender = check_ip(sender_ip, ip_senders);
        u_char *rec_ip = (u_char *)&iphead.ip_dst.s_addr;
        listip *recipient = check_ip(rec_ip, ip_recipients);

        if (sender != NULL)
        {
            (sender->packets)++;
        }
        else
        {
            sender = (listip *)malloc(sizeof(listip));
            sender->packets = 1;
            for (int i = 0; i < 4; i++)
            {
                sender->ipaddress[i] = sender_ip[i];
            }
            sender->next = ip_senders;
            ip_senders = sender;
        }

        if (recipient != NULL)
        {
            (recipient->packets)++;
        }
        else
        {
            recipient = (listip *)malloc(sizeof(listip));
            recipient->packets = 1;
            for (int i = 0; i < 4; i++)
            {
                recipient->ipaddress[i] = rec_ip[i];
            }
            recipient->next = ip_recipients;
            ip_recipients = recipient;
        }

        if (iphead.ip_p == IPPROTO_UDP)
        {
            struct udphdr udpstuff = *((struct udphdr *)(packet + 14 + sizeof(struct ip))); // excludes ip and ethernet headers for udp inclusion
            u_int16_t sender_port = udpstuff.uh_sport;
            listport *sender = check_port(sender_port, port_senders);
            u_int16_t rec_port = udpstuff.uh_dport;
            listport *recipient = check_port(rec_port, port_recipients);

            /* If sender/recipient has same port, increase port count*/
            if (sender != NULL)
            {
                (sender->port_count)++;
            }
            else
            {
                sender = (listport *)malloc(sizeof(listport));
                sender->port_count = 1;
                sender->port = sender_port;
                sender->next = port_senders;
                port_senders = sender;
            }

            if (recipient != NULL)
            {
                (recipient->port_count)++;
            }
            else
            {
                recipient = (listport *)malloc(sizeof(listport));
                recipient->port_count = 1;
                recipient->port = rec_port;
                recipient->next = port_recipients;
                port_recipients = recipient;
            }
        }
    }

    /* Track packet stats */
    sizes *packet_size = NULL;
    packet_size = (sizes *)malloc(sizeof(sizes));
    packet_size->size = header->len;
    packet_size->next = packet_sizes;
    packet_sizes = packet_size;
}

void print_output()
{
    /* Prints each statistic using previous linked lists*/

    time_t time_diff = max_time - min_time;
    int micro_diff = (int)max_us - (int)min_us;
    if (micro_diff < 0)
    {
        time_diff--;
        micro_diff += 1e6;
    }
    cout << endl
         << "Date of packet capture: " << ctime(&min_time) << endl;
    cout << "Packet capture duration: " << time_diff << " seconds and " << micro_diff << " microseconds." << endl;
    cout << "Total packets: " << total_packets << endl;

    cout << "------------------------------------------------" << endl
         << "SENDER MAC ADDRESSES LOGGED BELOW" << endl
         << "------------------------------------------------" << endl;
    while (senders != NULL)
    {
        for (int i = 0; i < 5; i++)
        {
            printf("%.2x:", senders->address[i]);
        }
        printf("%.2x,  ", senders->address[5]);
        cout << senders->packet_count << " packets" << endl;

        linkedlist *list1 = senders;
        senders = senders->next;
        free(list1);
    }

    cout << "------------------------------------------------" << endl
         << "RECIPIENT MAC ADDRESSES LOGGED BELOW" << endl
         << "------------------------------------------------" << endl;
    while (recipients != NULL)
    {
        for (int i = 0; i < 5; i++)
        {
            printf("%.2x:", recipients->address[i]);
        }
        printf("%.2x,  ", recipients->address[5]);
        cout << recipients->packet_count << " packets" << endl;

        linkedlist *list1 = recipients;
        recipients = recipients->next;
        free(list1);
    }

    if (participants != NULL)
    {
        cout << "------------------------------------------------" << endl
             << "ARP PARTICIPANTS LOGGED BELOW" << endl
             << "------------------------------------------------" << endl;
        while (participants != NULL)
        {
            printf("MAC: ");
            for (int i = 0; i < 5; i++)
            {
                printf("%.2x:", participants->macaddr[i]);
            }
            printf("%.2x,  IP: ", participants->macaddr[5]);
            for (int i = 0; i < 3; i++)
            {
                printf("%d.", participants->ipaddr[i]);
            }
            printf("%d\n", participants->ipaddr[3]);

            listarp *list1 = participants;
            participants = participants->next;
            free(list1);
        }
    }

    if (ip_senders != NULL)
    {
        cout << "------------------------------------------------" << endl
             << "SENDER IP ADDRESSES LOGGED BELOW" << endl
             << "------------------------------------------------" << endl;
        while (ip_senders != NULL)
        {
            for (int i = 0; i < 3; i++)
            {
                printf("%d.", ip_senders->ipaddress[i]);
            }
            printf("%d,  ", ip_senders->ipaddress[3]);

            printf("%2d", ip_senders->packets);
            cout << " packets" << endl;

            listip *list1 = ip_senders;
            ip_senders = ip_senders->next;
            free(list1);
        }
    }

    if (ip_recipients != NULL)
    {
        cout << "------------------------------------------------" << endl
             << "RECIPIENT IP ADDRESSES LOGGED BELOW" << endl
             << "------------------------------------------------" << endl;
        while (ip_recipients != NULL)
        {
            for (int i = 0; i < 3; i++)
            {
                printf("%d.", ip_recipients->ipaddress[i]);
            }
            printf("%d,  ", ip_recipients->ipaddress[3]);
            printf("%-2d", ip_recipients->packets);
            cout << " packets" << endl;

            listip *list1 = ip_recipients;
            ip_recipients = ip_recipients->next;
            free(list1);
        }
    }

    if (port_senders != NULL)
    {
        cout << "------------------------------------------------" << endl
             << "SENDER PORTS LOGGED BELOW" << endl
             << "------------------------------------------------" << endl;
        while (port_senders != NULL)
        {
            printf("%d\n", port_senders->port);

            listport *list1 = port_senders;
            port_senders = port_senders->next;
            free(list1);
        }
    }

    if (port_recipients != NULL)
    {
        cout << "------------------------------------------------" << endl
             << "RECIPIENT PORTS LOGGED BELOW" << endl
             << "------------------------------------------------" << endl;
        while (port_recipients != NULL)
        {
            printf("%d\n", port_recipients->port);

            listport *list1 = port_recipients;
            port_recipients = port_recipients->next;
            free(list1);
        }
    }

    cout << "------------------------------------------------" << endl
         << "PACKET STATISTICS" << endl
         << "------------------------------------------------" << endl;
    unsigned total = 0;
    while (packet_sizes != NULL)
    {
        unsigned size = packet_sizes->size;
        total += size;
        if (size < min_size)
        {
            min_size = size;
        }
        if (size > max_size)
        {
            max_size = size;
        }

        sizes *list1 = packet_sizes;
        packet_sizes = packet_sizes->next;
        free(list1);
    }
    avg_size = total / total_packets;
    cout << "Average Size: " << avg_size << " bytes" << endl;
    cout << "Minimum Size: " << min_size << " bytes" << endl;
    cout << "Maximum Size: " << max_size << " bytes" << endl;
}
