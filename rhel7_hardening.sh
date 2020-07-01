#!/bin/bash

# Put file in REPO => http://10.233.225.10/repos/cloud-init/rhel7_hardening.sh
# REF: CS-BSL-035-Redhat7_Security_Baseline_V1.6.pdf

# Skip the following tasks
# ----
# 1.1.5. Create Separate Partition for /var
#   Reason: Normally cloud image don't separate any slice except a specific purpose disk
# 1.1.8. Create Separate Parition for /var/log/audit
#   Reason: Normally cloud image don't separate any slice except a specific purpose disk
# 1.1.9. Create Separate Partition for /home
#   Reason: Normally cloud image don't separate any slice except a specific purpose disk
# 1.1.10. Add nodev Option to /home
#   Reason: Normally cloud image don't separate any slice except a specific purpose disk
# 7.4. Set Default umask for Users
#   Reason: need other mask 022 to install software
# 8.3. Set GNOME Warning Banner
#   Reason: No GUI

function remove_services() {
    services=("$@")
    for service in ${services[@]}
    do
        _RES=`yum list installed ${service} 2>/dev/null`
        if [ "${_RES}" != "" ]
        then
            yum remove -y ${service}
        fi
    done
}

function disable_services() {
    services=("$@")
    for service in ${services[@]}
    do
    systemctl is-enabled ${service} 2>/dev/null \
        && systemctl disable ${service} \
            && systemctl mask ${service}
    done
}

echo "----------------------------------------------------------------------------------------------------"
echo 
echo "1 - Install Updates, Patches and Addition Security Software"


# 1.1.1 - 1.1.4
sed -i 's;^Options=.*;Options=mode=1777,strictatime,nosuid,nodev,noexec;' /usr/lib/systemd/system/tmp.mount
systemctl daemon-reload
systemctl unmask tmp.mount
systemctl start tmp.mount
systemctl enable tmp.mount

# 1.1.6
cat > /usr/lib/systemd/system/var-tmp.mount << EOF
[Unit]
Description=Temporary Directory (/var/tmp)
Documentation=man:hier(7)
Documentation=https://www.freedesktop.org/wiki/Software/systemd/APIFileSystems
ConditionPathIsSymbolicLink=!/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
After=tmp.mount

[Mount]
What=/tmp
Where=/var/tmp
Type=none
Options=bind

# Make 'systemctl enable var-tmp.mount' work:
[Install]
WantedBy=local-fs.target
EOF
systemctl daemon-reload
systemctl start var-tmp.mount
systemctl enable var-tmp.mount

echo 'mount -o remount,noexec /dev/shm' >> /etc/rc.d/rc.local
chmod +x /etc/rc.d/rc.local

# 1.1.14
LIST=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null`
if [ "${LIST}" != "" ]
then
    echo "${LIST}" | xargs chmod a+t
fi

# 1.1.15 - 1.1.21
cat > /etc/modprobe.d/CIS.conf << EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF

# 1.2.1 - 1.2.2
test -s /boot/grub2/grub.cfg \
    && ( chown root:root /boot/grub2/grub.cfg; chmod og-rwx /boot/grub2/grub.cfg )
test -s /boot/efi/EFI/redhat/grub.cfg \
    && ( chown root:root /boot/efi/EFI/redhat/grub.cfg; chmod og-rwx /boot/efi/EFI/redhat/grub.cfg )

# 1.3.1 
if [ "`grep 'hard core' /etc/security/limits.conf`" == "" ]
then
    sed -i 's;# End of file;# Hardening\n*                hard    core            0\n# End of file;' /etc/security/limits.conf
fi
echo 'fs.suid_dumpable = 0' >> /etc/sysctl.conf

echo "----------------------------------------------------------------------------------------------------"
echo 
echo "2 - OS Service"

# 2.1 - 2.11
list=(telnet-server telnet rsh-server rsh ypbind ypserv tftp tftp-server talk talk-server xinetd)
remove_services "${list[@]}"

# 2.12 - 2.18
list=(chargen-dgram chargen-stream daytime-dgram daytime-stream echo-dgram echo-stream tcpmux-server)
disable_services "${list[@]}"

echo "----------------------------------------------------------------------------------------------------"
echo 
echo "3 - Special Purpose Services"

# 3.1
echo 'umask 027' >> /etc/sysconfig/init

# 3.2
systemctl set-default multi-user.target
list=(xorg-x11-server-common)
remove_services "${list[@]}"

# 3.3 - 3.4
list=(avahi-daemon cups)
disable_services "${list[@]}"

# 3.5
list=(dhcp)
remove_services "${list[@]}"

# 3.6 - use chrony instead of ntp
yum install -y chrony
cp /etc/chrony.conf{,.org}
if [ "${1}" == "TLS" ]
then

cat > /etc/chrony.conf << EOF
server 10.235.155.5 iburst
server 10.232.95.5 iburst
allow 127.0.0.1
allow ::1
cmddeny all
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
keyfile /etc/chrony.keys
leapsectz right/UTC
logdir /var/log/chrony
EOF

elif [ "${1}" == "SILA" ]
then

cat > /etc/chrony.conf << EOF
server 10.232.95.5 iburst
server 10.235.155.5 iburst
allow 127.0.0.1
allow ::1
cmddeny all
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
keyfile /etc/chrony.keys
leapsectz right/UTC
logdir /var/log/chrony
EOF

fi

systemctl restart chronyd

# 3.7
list=(openldap-servers openldap-clients)
remove_services "${list[@]}"

# 3.8 
list=(nfslock rpcgssd rpcbind rpcidmapd rpcsvcgssd)
disable_services "${list[@]}"

# 3.9 - 3.15 
list=(bind vsftpd httpd dovecot samba squid net-snmp)
remove_services "${list[@]}"

# 3.16
test -s /etc/postfix/main.cf \
    && ( cp -f /etc/postfix/main.cf{,.before_hardening} \
            && ( sed -i 's;^inet_interfaces.*;inet_interfaces = localhost;' /etc/postfix/main.cf \
                    && systemctl restart postfix \
                    || echo "Error: cannot modify /etc/postfix/main.cf"
            ) || echo "Error: cannot backup /etc/postfix/main.cf"
    )

echo "----------------------------------------------------------------------------------------------------"
echo 
echo "4 - Network Configuration and Firewalls"

# 4.1.1 - 4.2.8
cat >> /etc/sysctl.conf << EOF
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
EOF

sysctl -w net.ipv4.route.flush=1
sysctl -p

echo "----------------------------------------------------------------------------------------------------"
echo 
echo "5 - Logging and Auditing"

# 5.1.1 - 5.1.5
yum install -y rsyslog
systemctl start rsyslog 
systemctl enable rsyslog 
cat >> /etc/rsyslog.conf << EOF
auth,user.* /var/log/messages
kern.*      /var/log/kern.log
daemon.*    /var/log/daemon.log
syslog.*    /var/log/syslog
lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log
*.*         @@logservername
EOF

for log in `cat /etc/rsyslog.conf | grep '/var/log/' | grep -v ^# | awk '{print $2}' | sed 's;^-;;g'`
do
    touch ${log}
    chown root:root ${log}
    chmod og-rwx ${log}
done

pkill -HUP rsyslogd 

# 5.2.1 - 5.2.2
systemctl enable auditd
cp -f /etc/default/grub{,.before_hardening}
sed -i 's;GRUB_CMDLINE_LINUX="\(.*\)";GRUB_CMDLINE_LINUX="\1 audit=1";' /etc/default/grub
test -s /boot/grub2/grub.cfg \
    && grub2-mkconfig -o /boot/grub2/grub.cfg 
test -s /boot/efi/EFI/redhat/grub.cfg \
    && grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg

# 5.2.3 - 5.2.16
cp -f /etc/audit/audit.rules{,.before_hardening}
cat >> /etc/audit/audit.rules << EOF
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

-w /etc/selinux/ -p wa -k MAC-policy

-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

-w /etc/sudoers -p wa -k scope

-w /var/log/sudo.log -p wa -k actions

-w /sbin/insmod -p x -k modules 
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit arch=b64 -S init_module -S delete_module -k modules

-e 2
EOF

pkill -P 1 -HUP auditd

echo "----------------------------------------------------------------------------------------------------"
echo 
echo "6 - System Access, Authentication and Authorization"

# 6.1.1 - 6.1.8
systemctl enable crond
chown root:root /etc/crontab
chmod og-rwx /etc/crontab 
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily 
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
test -s /etc/at.deny && rm /etc/at.deny
touch /etc/at.allow
chown root:root /etc/at.allow
chmod og-rwx /etc/at.allow
test -s /etc/cron.deny && rm /etc/cron.deny
touch /etc/cron.allow
chown root:root /etc/cron.allow 
chmod og-rwx /etc/cron.allow

# 6.2.1 - 6.2.13
cp -f /etc/ssh/sshd_config{,.before_hardening}
cat >> /etc/ssh/sshd_config << EOF

Protocol 2
LogLevel INFO
MaxAuthTries 5
IgnoreRhosts yes
HostbasedAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
PermitUserEnvironment no
Ciphers aes128-ctr,aes192-ctr,aes256-ctr
MACs hmac-sha2-512,hmac-sha2-256
KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
ClientAliveInterval 300
ClientAliveCountMax 0
Banner \/etc\/issue.net
EOF

# 6.3.1
authconfig --passalgo=sha512 --update

# 6.3.2
cp -f /etc/pam.d/system-auth{,.before_hardening}
sed -i 's;\(.*\)pam_pwquality.so\(.*\);\1pam_pwquality.so\2retry=3 authtok_type=;' /etc/pam.d/system-auth
cp -f /etc/security/pwquality.conf{,.before_hardening}
cat >> /etc/security/pwquality.conf << EOF
minlen = 8
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF

# 6.3.3 - 6.3.4
cp /etc/pam.d/system-auth{,.before_hardening}
cat > /etc/pam.d/system-auth << EOF
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required                    pam_env.so
auth        required                    pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth        [success=1 default=bad]     pam_unix.so
auth        [default=die]               pam_faillock.so authfail audit deny=5 unlock_time=900
auth        sufficient                  pam_faillock.so authsucc audit deny=5 unlock_time=900
auth        required                    pam_faildelay.so delay=2000000
auth        sufficient                  pam_unix.so nullok try_first_pass
auth        requisite                   pam_succeed_if.so uid >= 1000 quiet_success
auth        required                    pam_deny.so

account     required                    pam_unix.so
account     sufficient                  pam_localuser.so
account     sufficient                  pam_succeed_if.so uid < 1000 quiet
account     required                    pam_permit.so

password    requisite                   pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient                  pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5


password    required                    pam_deny.so

session     optional                    pam_keyinit.so revoke
session     required                    pam_limits.so
-session     optional                   pam_systemd.so
session     [success=1 default=ignore]  pam_succeed_if.so service in crond quiet use_uid
session     required                    pam_unix.so
EOF

cp /etc/pam.d/password-auth{,.before_hardening}
cat > /etc/pam.d/password-auth << EOF
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required                    pam_env.so
auth        required                    pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth        [success=1 default=bad]     pam_unix.so
auth        [default=die]               pam_faillock.so authfail audit deny=5 unlock_time=900
auth        sufficient                  pam_faillock.so authsucc audit deny=5 unlock_time=900
auth        required                    pam_faildelay.so delay=2000000
auth        sufficient                  pam_unix.so nullok try_first_pass
auth        requisite                   pam_succeed_if.so uid >= 1000 quiet_success
auth        required                    pam_deny.so

account     required                    pam_unix.so
account     sufficient                  pam_localuser.so
account     sufficient                  pam_succeed_if.so uid < 1000 quiet
account     required                    pam_permit.so

password    requisite                   pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient                  pam_unix.so sha512 shadow nullok try_first_pass use_authtok 


password    required                    pam_deny.so

session     optional                    pam_keyinit.so revoke
session     required                    pam_limits.so
-session     optional                   pam_systemd.so
session     [success=1 default=ignore]  pam_succeed_if.so service in crond quiet use_uid
session     required                    pam_unix.so
EOF

echo "----------------------------------------------------------------------------------------------------"
echo 
echo "7 - User Accounts and Environment"

# 7.1.1 - 7.1.3
cp -f /etc/login.defs{,.before_hardening}
sed -i 's;PASS_MAX_DAYS.*;PASS_MAX_DAYS\t90;' /etc/login.defs
sed -i 's;PASS_MIN_DAYS.*;PASS_MIN_DAYS\t7;' /etc/login.defs
sed -i 's;PASS_WARN_AGE.*;PASS_WARN_AGE\t7;' /etc/login.defs

# 7.2
for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`
do
    if [ $user != "root" ]
    then
        /usr/sbin/usermod -L $user 
        if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]
        then
            /usr/sbin/usermod -s /sbin/nologin $user
        fi
    fi
done 

# 7.3
usermod -g 0 root 

echo "----------------------------------------------------------------------------------------------------"
echo 
echo "8 - Warning Banners"

# 8.1
cp -f /etc/motd{,.before_hardening}
cp -f /etc/issue{,.before_hardening}
cp -f /etc/issue.net{,.before_hardening}

cat > /etc/motd << EOF

This computer system is property of Advanced Info Service Public Company Limited (AIS) and
must be accessed only by authorized users. Any unauthorized use of this system is strictly prohibited
and deemed as violation to AIS'­s regulation on Information Technology and Computer System
Security of Telecommunication and Wireless Business (Regulation). The unauthorized user or any
person who breaches AIS'­s Regulation, policy, criteria and/or memorandums regarding IT Security
will be punished by AIS and may be subject to criminal prosecution.
All data contained within the systems is owned by AIS. The data may be monitored, intercepted,
recorded, read, copied, or captured and disclosed in any manner by authorized personnel for
prosecutions and other purposes according to AIS's Regulation.
Any communication on or information stored within the system, including information stored locally
on the hard drive or other media in use with this unit (e.g., floppy disks, PDAs and other hand-held
peripherals, Handy drives, CD-ROMs, etc.), is also owned by AIS. AIS have all rights to manage such
information.
Please contact IT Support if you encounter any computer problem.
EOF

cat > /etc/issue << EOF

This computer system is property of Advanced Info Service Public Company Limited (AIS) and
must be accessed only by authorized users. Any unauthorized use of this system is strictly prohibited
and deemed as violation to AIS'­s regulation on Information Technology and Computer System
Security of Telecommunication and Wireless Business (Regulation). The unauthorized user or any
person who breaches AIS'­s Regulation, policy, criteria and/or memorandums regarding IT Security
will be punished by AIS and may be subject to criminal prosecution.
All data contained within the systems is owned by AIS. The data may be monitored, intercepted,
recorded, read, copied, or captured and disclosed in any manner by authorized personnel for
prosecutions and other purposes according to AIS's Regulation.
Any communication on or information stored within the system, including information stored locally
on the hard drive or other media in use with this unit (e.g., floppy disks, PDAs and other hand-held
peripherals, Handy drives, CD-ROMs, etc.), is also owned by AIS. AIS have all rights to manage such
information.
Please contact IT Support if you encounter any computer problem.
EOF

cat > /etc/issue.net << EOF

This computer system is property of Advanced Info Service Public Company Limited (AIS) and
must be accessed only by authorized users. Any unauthorized use of this system is strictly prohibited
and deemed as violation to AIS'­s regulation on Information Technology and Computer System
Security of Telecommunication and Wireless Business (Regulation). The unauthorized user or any
person who breaches AIS'­s Regulation, policy, criteria and/or memorandums regarding IT Security
will be punished by AIS and may be subject to criminal prosecution.
All data contained within the systems is owned by AIS. The data may be monitored, intercepted,
recorded, read, copied, or captured and disclosed in any manner by authorized personnel for
prosecutions and other purposes according to AIS's Regulation.
Any communication on or information stored within the system, including information stored locally
on the hard drive or other media in use with this unit (e.g., floppy disks, PDAs and other hand-held
peripherals, Handy drives, CD-ROMs, etc.), is also owned by AIS. AIS have all rights to manage such
information.
Please contact IT Support if you encounter any computer problem.
EOF

chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue
chmod 644 /etc/issue
chown root:root /etc/issue.net
chmod 644 /etc/issue.net 

echo "----------------------------------------------------------------------------------------------------"
echo 
echo "9 - System Maintenance"

# 9.1.1 - 9.1.8
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 000 /etc/gshadow
chmod 644 /etc/group
chown root:root /etc/passwd
chown root:root /etc/shadow
chown root:root /etc/gshadow
chown root:root /etc/group 

# 9.1.9
LIST=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null`
if [ "${LIST}" != "" ]
then
    echo "${LIST}" | xargs chmod o-w
fi

# 9.1.10
RES=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls`
if [ "${RES}" != "" ]
then
    echo "Found Un-owned File and Directories"
    echo "${RES}"
fi

# 9.1.11
RES=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls`
if [ "${RES}" != "" ]
then
    echo "Found Un-grouped File and Directories"
    echo "${RES}"
fi

# 9.2.1
LIST=`cat /etc/shadow | awk -F: '($2 == "" ) { print $1 "does not have a password "}' 2>/dev/null`
if [ "${LIST}" != "" ]
then
    echo "${LIST}" | xargs passwd -l
fi

# 9.2.2
LIST=`grep '^+:' /etc/passwd 2>/dev/null | awk -F':' '{print $1}'`
if [ "${LIST}" != "" ]
then
    echo "${LIST}" | xargs userdel -r
fi

# 9.2.3 
LIST=`grep '^+:' /etc/shadow 2>/dev/null | awk -F':' '{print $1}'`
if [ "${LIST}" != "" ]
then
    echo "${LIST}" | xargs userdel -r
fi

# 9.2.4
LIST=`grep '^+:' /etc/group 2>/dev/null | awk -F':' '{print $1}'`
if [ "${LIST}" != "" ]
then
    echo "${LIST}" | xargs userdel -r
fi

# 9.2.5
LIST=`cat /etc/passwd 2>/dev/null | /bin/awk -F: '($3 == 0) { print $1 }' | grep -v ^root$ | awk -F':' '{print $1}'`
if [ "${LIST}" != "" ]
then
    echo "${LIST}" | xargs userdel -r
fi

# 9.2.6 - 9.2.10
sed -i -e 's;^PATH=.*;;' -e 's;export PATH;;' /etc/skel/.bashrc 
sed -i -e 's;^PATH=.*;;' -e 's;export PATH;;' /root/.bash_profile

for dir in `cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin") { print $6 }'`
do
    sed -i -e 's;^PATH=.*;;' -e 's;export PATH;;' ${dir}/.bashrc
    chmod 700 ${dir}
    for file in `find ${dir}/.[A-Za-z0-9]* -perm /o=w`
    do
        chmod o-w ${file}
    done
    test -s $dir/.netrc && chmod 600 $dir/.netrc
    test -s $dir/.rhosts && mv $dir/.rhosts $dir/.rhosts.hardening
done

# 9.2.11
cut -s -d: -f1,4 /etc/passwd | sed 's/:/ /g' | \
while read u i
do
    grep -q -P "^.*?:x:${i}:" /etc/group
    if [ $? -ne 0 ]
    then
        passwd -l ${u}
    fi
done

# 9.2.12
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | \
while read user uid dir
do
    if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]
    then
        ug=`id -a ${user} | sed 's;uid=[0-9]\+(\(.*\)) gid=[0-9]\+(\(.*\)) .*;\1:\2;'`
        mkdir ${dir}
        chown ${ug} ${dir}
        chmod 700 ${dir}
    fi
done 

# 9.2.13
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | \
while read user uid dir
do
    if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" -a "$dir" != "/" ]
    then
        owner=$(stat -L -c "%U" "$dir")
        if [ "$owner" != "$user" ]
        then
            ug=`id -a ${user} | sed 's;uid=[0-9]\+(\(.*\)) gid=[0-9]\+(\(.*\)) .*;\1:\2;'`
            chown ${ug} ${dir}
            chmod 700 ${dir}
        fi
    fi
done 

# 9.2.14
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | grep -v ' 1 ' | \
while read c x
do
    cat /etc/passwd | awk -F: -v u=$x '{if($3==u){print "Duplicate UID:",$0}'
done

# 9.2.15
cat /etc/group | awk -F':' '{print $3}' | sort | uniq -c | grep -v ' 1 ' | \
while read c x
do
    cat /etc/group | awk -F: -v u=$x '{if($3==u){print "Duplicate GID:",$0}'
done

# 9.2.16
cat /etc/passwd | awk -F: '{print $1}' | sort | uniq -c | grep -v ' 1 ' | \
while read c x
do
    cat /etc/passwd | awk -F: -v u=$x '{if($1==u){print "Duplicate USERNAME:",$0}'
done

# 9.2.17
cat /etc/group | awk -F':' '{print $1}' | sort | uniq -c | grep -v ' 1 ' | \
while read c x
do
    cat /etc/group | awk -F: -v u=$x '{if($1==u){print "Duplicate GROUP:",$0}'
done

# 9.2.18
for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`
do
    test -s $dir/.netrc && mv $dir/.netrc $dir/.netrc.hardening
done
