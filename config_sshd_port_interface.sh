#!/bin/bash

if [ "`echo ${1} | grep '[0-9]\+'`" ]
then
    PORT=${1}
    yum -y install policycoreutils-{python,devel}
    sed -i.org -e 's/^#*PermitRootLogin\s.*/PermitRootLogin no/g' /etc/ssh/sshd_config  
    
    if [ "`ss -Hltn sport = :${PORT}`" == "" ]
    then
        semanage port -a -t ssh_port_t -p tcp ${PORT}
        sed -i.org "/<port protocol=\"tcp\" port=\"22\"\/>/a <port protocol=\"tcp\" port=\"${PORT}\"\/>" /usr/lib/firewalld/services/ssh.xml
        sed -i -e "s/^#*Port\s.*$/Port ${PORT}/g" /etc/ssh/sshd_config
    fi
    /bin/systemctl restart sshd
fi
