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

linkedlist* senders = NULL;
linkedlist* recipients = NULL;

linkedlist* check_addr(u_char* address, linkedlist* list) {
    for(;list!=NULL;list=list->next) {
        bool same = true;
        for(int i = 0; i < 6; i++) {
            if(address[i] != list->address[i]) {
                same = false;
            }
        } if(same = true) return list;
    } return NULL;
}

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    cout << "Length of packet: " << header->len << endl;
    cout << "Length of portion present: " << header->caplen << endl;
    cout << "Timestamp: " << header->ts.tv_sec << "." << header->ts.tv_usec << endl;

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
    }

    if(recipient != NULL) {
        (recipient->packet_count)++;
    } else {
        recipient = (linkedlist*) malloc(sizeof(linkedlist));
        recipient->packet_count = 1;
        for(int i = 0; i < 6; i++) {
            recipient->address[i] = header_eth.ether_dhost[i];
        } recipient->next = recipients;
    }

    // remember to write function to free linkedlist mallocs to avoid possible memory leaks
    // make sure to parse list items so that each can be printed in proper notations
}

void print_output() {

    time_t time_diff = max_time - min_time;
    int micro_diff = (int) max_us - (int) min_us;
    if(micro_diff < 0) {
        time_diff--; micro_diff += 1e6;
    } cout << endl << "Date of packet capture: " << ctime(&min_time) << endl;
    cout << "Packet capture duration: " << time_diff << " seconds and " << micro_diff << " microseconds." << endl;
    cout << "Total packets: " << total_packets << endl;

}
