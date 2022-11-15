#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include "include.h"
#include "callback.h"
using namespace std;

/* define PCAP_BUF_SIZE on non-linux or windows machines */
#ifndef PCAP_BUF_SIZE 
#define PCAP_BUF_SIZE 1024
#endif

/*
 * wireview.cpp
 * Zeb Carty and Michael McInerney
 *
 * Opens a tcpdump file and produces packet statistics
 */

int main(int argc, char **argv)
{
    pcap_t *fp;
    char error_buff[PCAP_ERRBUF_SIZE];
    char source_buff[PCAP_BUF_SIZE];
    char *file;

    if (argc == 2) {
        file = argv[1];
    }
    else {
        cout << "Please supply filename" << endl;
        exit(1);
    }

    cout << "Opening file...";
    //  Open an input file using function pcap open offline().
    fp = pcap_open_offline(file, error_buff);
    if (fp == NULL)
    {
        cout << "failed" << endl;
    }
    cout << "done" << endl;

    cout << "Checking if Ethernet...";
    // Check that the data you are provided has been captured from Ethernet using function pcap datalink().
    if (pcap_datalink(fp) != DLT_EN10MB) {
        cout << "failed" << endl;
    }
    cout << "done" << endl;

    //  Read packets from the file using function pcap loop().
    pcap_loop(fp, -1, callback, NULL);
    print_output();
    // Close the file using function pcap close().
    pcap_close(fp);
    return 0;
}