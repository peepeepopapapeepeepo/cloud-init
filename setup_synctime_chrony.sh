#!/bin/bash

if [ "${1}" == "TLS" -o "${1}" == "SILA" ]
then
    yum -y install chrony
    cp /etc/chrony.conf{,.org}
	echo -e 'server time.navy.mi.th iburst\nserver time2.navy.mi.th iburst' > /etc/chrony.conf
    /bin/systemctl start chronyd
    /bin/systemctl enable chronyd
fi
