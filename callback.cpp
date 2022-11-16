#include "include.h"
#include "callback.h"
using namespace std;

time_t min_time = 2e9; // should work for the next ~31 years
suseconds_t min_us;
time_t max_time = 0;
suseconds_t max_us;

unsigned total_packets = 0;

typedef struct linkedlist {
    unsigned char address[6];
    unsigned packet_count;
    struct linkedlist* next;
} linkedlist;

typedef struct listarp {
    unsigned char macaddr[6];
    unsigned char ipaddr[4];
    struct listarp* next;
} listarp;

typedef struct listip {
    unsigned char ipaddress[4];
    unsigned packets;
    struct listip* next;
} listip;

linkedlist* senders = NULL;
linkedlist* recipients = NULL;
listarp* participants = NULL;
listip* ip_senders = NULL;
listip* ip_recipients = NULL;

linkedlist* check_addr(u_char* address, linkedlist* list) {
    for(;list!=NULL;list=list->next) {
        bool same = true;
        for(int i = 0; i < 6; i++) {
            if(address[i] != list->address[i]) {
                same = false;
            }
        } if(same == true) return list;
    } return NULL;
}

listarp* check_arp(u_char* address, listarp* list) {
    for(;list!=NULL;list=list->next) {
        bool same = true;
        for(int i = 0; i < 6; i++) {
            if(address[i] != list->macaddr[i]) {
                same = false;
            }
        } if(same == true) return list;
    } return NULL;
}

listip* check_ip(u_char* address, listip* list) {
    for(;list!=NULL;list=list->next) {
        bool same = true;
        for(int i = 0; i < 4; i++) {
            if(address[i] != list->ipaddress[i]) {
                same = false;
            }
        } if(same == true) return list;
    } return NULL;
}

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    // cout << "Length of packet: " << header->len << endl;
    // cout << "Length of portion present: " << header->caplen << endl;
    // cout << "Timestamp: " << header->ts.tv_sec << "." << header->ts.tv_usec << endl;

    if(header->ts.tv_sec < min_time || ((header->ts.tv_sec == min_time) && (header->ts.tv_usec < min_us))) {
        min_time = header->ts.tv_sec;
        min_us = header-> ts.tv_usec;
    } if(header->ts.tv_sec > max_time || ((header->ts.tv_sec == max_time) && (header->ts.tv_usec > max_us))) {
        max_time = header->ts.tv_sec;
        max_us = header-> ts.tv_usec;
    } total_packets++;

    struct ether_header header_eth = *((struct ether_header*) packet);
    linkedlist* sender = check_addr(header_eth.ether_shost, senders);
    linkedlist* recipient = check_addr(header_eth.ether_dhost, recipients);

    if(sender != NULL) {
        (sender->packet_count)++;
    } else {
        sender = (linkedlist*) malloc(sizeof(linkedlist));
        sender->packet_count = 1;
        for(int i = 0; i < 6; i++) {
            sender->address[i] = header_eth.ether_shost[i];
        } sender->next = senders;
        senders = sender;
    }

    if(recipient != NULL) {
        (recipient->packet_count)++;
    } else {
        recipient = (linkedlist*) malloc(sizeof(linkedlist));
        recipient->packet_count = 1;
        for(int i = 0; i < 6; i++) {
            recipient->address[i] = header_eth.ether_dhost[i];
        } recipient->next = recipients;
        recipients = recipient;
    }

    if(ntohs(header_eth.ether_type) == ETHERTYPE_ARP) {

        struct ether_arp arphead = *((struct ether_arp*) (packet+14)); // ethernet headers are 14 bytes long, exclude these
        listarp* participant = check_arp(arphead.arp_sha,participants);

        if(participant == NULL) {
            participant = (listarp*) malloc(sizeof(listarp));
            for(int i = 0; i < 6; i++) {
                participant->macaddr[i] = arphead.arp_sha[i];
            } for(int i = 0; i < 4; i++) {
                participant->ipaddr[i] = arphead.arp_spa[i];
            } participant->next = participants;
            participants = participant;
        }

        participant = check_arp(arphead.arp_tha,participants);

        if(participant == NULL) {
            participant = (listarp*) malloc(sizeof(listarp));
            for(int i = 0; i < 6; i++) {
                participant->macaddr[i] = arphead.arp_tha[i];
            } for(int i = 0; i < 4; i++) {
                participant->ipaddr[i] = arphead.arp_tpa[i];
            } participant->next = participants;
            participants = participant;
        }

    } else if(ntohs(header_eth.ether_type) == ETHERTYPE_IP) {

        struct ip iphead = *((struct ip*) (packet+14)); // exclude ethernet header, CHANGE TO iphdr WHEN MIGRATING TO LINUX
        u_char* sender_ip = (u_char*) &iphead.ip_src.s_addr;
        listip* sender = check_ip(sender_ip, ip_senders);
        u_char* rec_ip = (u_char*) &iphead.ip_dst.s_addr;
        listip* recipient = check_ip(rec_ip, ip_recipients);

        if(sender != NULL) {
            (sender->packets)++;
        } else {
            sender = (listip*) malloc(sizeof(listip));
            sender->packets = 1;
            for(int i = 0; i < 4; i++) {
                sender->ipaddress[i] = sender_ip[i];
            } sender->next = ip_senders;
            ip_senders = sender;
        }

        if(recipient != NULL) {
            (recipient->packets)++;
        } else {
            recipient = (listip*) malloc(sizeof(listip));
            recipient->packets = 1;
            for(int i = 0; i < 4; i++) {
                recipient->ipaddress[i] = rec_ip[i];
            } recipient->next = ip_recipients;
            ip_recipients = recipient;
        }

    }

}

void print_output() {

    time_t time_diff = max_time - min_time;
    int micro_diff = (int) max_us - (int) min_us;
    if(micro_diff < 0) {
        time_diff--; micro_diff += 1e6;
    } cout << endl << "Date of packet capture: " << ctime(&min_time) << endl;
    cout << "Packet capture duration: " << time_diff << " seconds and " << micro_diff << " microseconds." << endl;
    cout << "Total packets: " << total_packets << endl;
    
    linkedlist* list1 = senders;
    linkedlist* list2 = recipients;
    linkedlist* temp;

    listarp* list3 = participants;
    listarp* temporary;

    listip* list4 = ip_senders;
    listip* list5 = ip_recipients;
    listip* moretemp;

    cout << "------------------------------------------------" << endl
    << "SENDER MAC ADDRESSES LOGGED BELOW"  << endl 
    << "------------------------------------------------" << endl;
    while(list1 != NULL) {
        for(int i = 0; i < 5; i++) {
            printf("%.2x:", list1->address[i]);
        } printf("%.2x,  ", list1->address[5]);
        cout << list1->packet_count << endl;

        temp = list1;
        list1 = list1->next;
        free(temp);
    }

    cout << "------------------------------------------------" << endl 
    << "RECIPIENT MAC ADDRESSES LOGGED BELOW" << endl 
    << "------------------------------------------------" << endl;
    while(list2 != NULL) {
        for(int i = 0; i < 5; i++) {
            printf("%.2x:", list2->address[i]);
        } printf("%.2x,  ", list2->address[5]);
        cout << list2->packet_count << endl;

        temp = list2;
        list2 = list2->next;
        free(temp);
    }

    cout << "------------------------------------------------" << endl 
    << "ARP PARTICIPANTS LOGGED BELOW" << endl 
    << "------------------------------------------------" << endl;
    while(list3 != NULL) {
        for(int i = 0; i < 5; i++) {
            printf("%.2x:", list3->macaddr[i]);
        } printf("%.2x,  ", list3->macaddr[5]);
        for(int i = 0; i < 3; i++) {
            printf("%d.", list3->ipaddr[i]);
        } printf("%d\n", list3->ipaddr[3]);

        temporary = list3;
        list3 = list3->next;
        free(temporary);
    }

    cout << "------------------------------------------------" << endl
    << "SENDER IP ADDRESSES LOGGED BELOW"  << endl 
    << "------------------------------------------------" << endl;
    while(list4 != NULL) {
        for(int i = 0; i < 3; i++) {
            printf("%d.", list4->ipaddress[i]);
        } printf("%d,  ", list4->ipaddress[3]);
        cout << list4->packets << endl;

        moretemp = list4;
        list4 = list4->next;
        free(moretemp);
    }

    cout << "------------------------------------------------" << endl
    << "RECIPIENT IP ADDRESSES LOGGED BELOW"  << endl 
    << "------------------------------------------------" << endl;
    while(list5 != NULL) {
        for(int i = 0; i < 3; i++) {
            printf("%d.", list5->ipaddress[i]);
        } printf("%d,  ", list5->ipaddress[3]);
        cout << list5->packets << endl;

        moretemp = list5;
        list5 = list5->next;
        free(moretemp);
    }
}
