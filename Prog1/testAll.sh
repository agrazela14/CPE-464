#!/bin/bash

clear

echo "Testing every given case"

./trace ./TraceFiles/ArpTest.pcap > ARPout
diff -B ARPout ./TraceFiles/ArpTest.out > ARPdiff

if [ -s ARPdiff ]
    then
        echo "Error in ARP test"
fi

./trace ./TraceFiles/Http.pcap > HTTPout
diff -B HTTPout ./TraceFiles/Http.out > HTTPdiff

if [ -s HTTPdiff ]
    then
        echo "Error in HTTP test"
fi

./trace ./TraceFiles/IP_bad_checksum.pcap > IPBadCheckout
diff -B IPBadCheckout ./TraceFiles/IP_bad_checksum.out > IPBadCheckdiff

if [ -s IPBadCheckdiff ]
    then
        echo "Error in IP Bad Checksum test"
fi

./trace ./TraceFiles/PingTest.pcap > Pingout
diff -B Pingout ./TraceFiles/PingTest.out > Pingdiff

if [ -s Pingdiff ]
    then
        echo "Error in Ping test"
fi

./trace ./TraceFiles/TCP_bad_checksum.pcap > TCPBadCheckout
diff -B TCPBadCheckout ./TraceFiles/TCP_bad_checksum.out > TCPBadCheckdiff

if [ -s TCPBadCheckdiff ]
    then
        echo "Error in TCP Bad Checksum test"
fi

./trace ./TraceFiles/UDPfile.pcap > UDPout
diff -B UDPout ./TraceFiles/UDPfile.out > UDPdiff

if [ -s UDPdiff ]
    then
        echo "Error in UDP test"
fi

./trace ./TraceFiles/largeMix.pcap > Largeout
diff -B Largeout ./TraceFiles/largeMix.out > Largediff

if [ -s Largediff ]
    then
        echo "Error in Large Mix test"
fi

./trace ./TraceFiles/largeMix2.pcap > Large2out
diff -B Large2out ./TraceFiles/largeMix2.out > Large2diff

if [ -s Large2diff ]
    then
        echo "Error in Large Mix 2 test"
fi
./trace ./TraceFiles/smallTCP.pcap > Smallout
diff -B Smallout ./TraceFiles/smallTCP.out > Smalldiff

if [ -s Smalldiff ]
    then
        echo "Error in Small TCP test"
fi

