#include "include.h"
#include "callback.h"

using namespace std;

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    cout << "Length of packet: " << header->len << endl;
    cout << "Length of portion present: " << header->caplen << endl;
    cout << "Timestamp: " << header->ts.tv_sec << "." << header->ts.tv_usec << endl;

}
