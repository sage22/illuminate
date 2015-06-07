#!/bin/bash
# init
clear
echo "This will harden an Amazon Linux server|Centos|Redhat version 6+ ec2-instance"
echo "I wrote this script to comply with CIS Red Hat Enterprise Linux 6 Benchmark v1.2.0"
echo "   


       ----WARNING----           ----WARNING-----        ----WARNING----      ----WARNING----
          This is a highly advanced script written to meet federal government security
      guidelines for passing ATO. This script is owned and licensed to (Matthew L. Trotter)
  DO NOT attempt to run this script without direct permission and/or explanation from (Matthew L. Trotter)
                                as it will destroy your server/machine"
echo "

                                         Press Enter To Begin:"
read

# Reading writes and creation date
echo"
Written by Matthew Trotter
Date: 28 April 2014
Revision 3
"
sleep 4
clear

echo "You must be root to perform this operation"
sleep 3
if [ "$(id -u)" != "0" ]; then
	echo "Sorry, you are not root."
	exit 1
fi


# Redirect stdout ( > ) into a named pipe ( >() ) running "tee"
echo "Redirecting errors error.txt which will be in the directory you are running this script from" 
exec > >(tee redhat.txt)

echo "Check for updates"
yum check-update

echo "Installing updates"
yum update -y
sleep 5

echo "Installing SNMP"
yum install net-snmp -y

echo "Setting nodev,nosuid,noexec for the tmp file system"
perl -i -npe 's/tmpfs   defaults/tmpfs   defaults,nodev,nosuid,noexec/' /etc/fstab
grep tmpfs /etc/fstab | grep nodev | grep nosuid | grep noexec
mount | grep tmpfs | grep nodev | grep nosuid | grep noexec
sleep 5

echo "Disable unneeded filesystems"
echo "install cramfs /bin/true" > /etc/modprobe.d/CIS.conf
echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install hfsplus /bin/true" >>/etc/modprobe.d/CIS.conf
echo "install squashfs /bin/true" >>/etc/modprobe.d/CIS.conf
echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf

echo "Verify GPG KEY is installed"
rpm -q -queryformat "%{SUMMARY}\n" gpg-pubkey
sleep 5

echo "Verify gpgcheck is Globally Activated"
grep gpgcheck /etc/yum.conf
echo "A value of zero indicates this is not activated"
sleep 2

echo "Shutting down the RHNSD daemon"
service rhnsd stop
sleep 2

echo "Disable RHNSD daemon"
chkconfig rhnsd off
sleep 2

echo "Verify the integrity off installed packages"
rpm -qVa | awk '$2 != "c" { print $0}'
sleep 2

echo "Installing AIDE"
yum -y install aide
sleep 2

echo "Initializing AIDE"
/usr/sbin/aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz'
sleep 2

echo "Setting up periodic AIDE checking"
#write out current crontab
crontab -l > mycron
#echo new cron into cron file
echo "0 5 * * * /usr/sbin/aide --check" >> mycron
#install new cron file
crontab mycron
rm mycron

echo "SELinux is not supported in an Amazon Linux"
sleep 2

echo "Check for Unconfined Daemons"
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{print $NF }'
sleep 2

echo "Set User/Group Owner to Root on /etc/grub.conf"
chown root:root /etc/grub.conf

echo "Set Permissions on /etc/grub.conf"
chmod og-rwx /boot/grub/grub.conf

echo "Disable Interactive Boot"
perl -i -npe 's\PROMPT=yes\PROMPT=no\' /etc/sysconfig/init
grep "^PROMPT=" /etc/sysconfig/init
sleep 2

echo "Restrict Core Dumps"
echo "* hard core 0" >> /etc/security/limits.conf
grep "hard core" /etc/security/limits.conf  
sleep 2
sysctl fs.suid_dumpable
sleep 2

echo "Configure ExecShield to protect against buffer overflow attacks"
echo "# Configure Execshield" >> /etc/sysctl.conf
echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
sleep 2

echo "Enabling Randomized Virtual Memory Region Placement to make it difficult to write memory page exploits"
echo "# Randomized Virtual Memory Region Placement" >> /etc/sysctl.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
sleep 2

echo "Set Daemon umask"
echo "umask 027" >> /etc/sysconfig/init
grep umask /etc/sysconfig/init
sleep 2

echo "Disable Print server"
service cups stop
chkconfig cups off

echo "Configure NTP"
sed -i '22,26d' /etc/ntp.conf
sed -i '22a\server time-a.nist.gov' /etc/ntp.conf
sed -i '23a\server time-b.nist.gov' /etc/ntp.conf
grep "^server" /etc/ntp.conf
sleep 2
echo "Check the NTP Daemon is running under ntp"
ps -ef | grep ntp
sleep 2

echo "Disable IP Forwarding"
/sbin/sysctl -w net.ipv4.route.flush=1
/sbin/sysctl -w net.ipv4.ip_forward=0
sleep 2

echo "Disable Send Packet Redirects"
/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0
/sbin/sysctl -w net.ipv4.default.all.send_redirects=0
/sbin/sysctl -w net.ipv4.route.flush=1
sleep 2

echo "Disable Source Routed Packet Acceptance"
/sbin/sysctl -w net.ipv4.conf.all.accept_source_route=0 
/sbin/sysctl -w net.ipv4.conf.default.accept_source_route=0
/sbin/sysctl -w net.ipv4.route.flush=1
sleep 2

echo "Disable ICMP Redirect Acceptance"
/sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0
/sbin/sysctl -w net.ipv4.conf.default.accept_redirects=0
/sbin/sysctl -w net.ipv4.route.flush=1
sleep 2

echo "Disable Secure ICMP Redirect Acceptance"
/sbin/sysctl -w net.ipv4.conf.all.secure_redirects=0
/sbin/sysctl -w net.ipv4.conf.default.secure_redirects=0
/sbin/sysctl -w net.ipv4.route.flush=1
sleep 2

echo "Log Suspicious Packets"
/sbin/sysctl -w net.ipv4.conf.all.log_martians=1
/sbin/sysctl -w net.ipv4.conf.default.log_martians=1
/sbin/sysctl -w net.ipv4.route.flush=1
sleep 2

echo "Enable Ignore Broadcast Requests"
/sbin/sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
/sbin/sysctl -w net.ipv4.route.flush=1
sleep 2

echo "Enable Bad Error Message Protection"
/sbin/sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sleep 2

echo "Enable RFC-recommended Source Route Validation"
/sbin/sysctl -w net.ipv4.conf.all.rp_filter=1
/sbin/sysctl -w net.ipv4.conf.default.rp_filter=1
sleep 2

echo "Enable TCP SYN Cookies" 
/sbin/sysctl -w net.ipv4.tcp_syncookies=1
sleep 2

echo "Disable IPv6 Router Advertisements"
/sbin/sysctl -w net.ipv6.conf.all.accept_ra=0
/sbin/sysctl -w net.ipv6.conf.default.accept_ra=0
/sbin/sysctl -w net.ipv6.route.flush=1
sleep 2

echo "Disable IPv6 Redirect Acceptance"
/sbin/sysctl -w net.ipv6.conf.all.accept_redirects=0
/sbin/sysctl -w net.ipv6.conf.default.accept_redirects=0
/sbin/sysctl -w net.ipv6.route.flush=1
sleep 2

#echo "Disable IPv6"
#echo "options ipv6 disable=1" >> /etc/modprobe.d/CIS.conf
#sleep 2

echo "Verify Permissions on /etc/hosts.allow"
chmod 644 /etc/hosts.allow
chown root:root /etc/hosts.allow
sleep 2

echo "Verify Permissions on /etc/hosts.deny"
chmod 644 /etc/hosts.deny
chown root:root /etc/hosts.deny
sleep 2

echo "Disable DCCP"
echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
sleep 2

echo "Disable SCTP"
echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
sleep 2

echo "Disable RDS"
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
sleep 2

echo "Disable TIPC"
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
sleep 2

#echo "Enable IPtables"
#chkconfig iptables on
#service iptables restart
#sleep 2

echo "Check that rsyslog is on"
chkconfig rsyslog on
chkconfig --list rsyslog
sleep 2

echo "Auditing"
sleep 2
echo "Configure Audit Log Storage Size"
sed -i "/max_log_file/s/6/12/" /etc/audit/auditd.conf
sleep 2

echo "Disable System on Audit Log Full"
sed -i "/space_left_action/s/SYSLOG/email/" /etc/audit/auditd.conf
sed -i "/admin_space_left_action/s/SUSPEND/halt/" /etc/audit/auditd.conf
sleep 2

echo "Enable auditd service"
chkconfig auditd on

echo "Keep All Auditing Information"
perl -i -npe 's/max_log_file_action = ROTATE/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
grep max_log_file_action /etc/audit/auditd.conf
sleep 3

echo "Enable auditing for Processes that start prior to auditd"
ed /etc/grub.conf << END
g/audit=1/s///g
g/kernel/s/$/ audit=1/
w
q
END
grep "kernel" /etc/grub.conf
sleep 5

echo "Record Events That Modify Date and Time Information"
echo "" >> /etc/audit/audit.rules
echo "# Record Events That Modify Date and Time Information" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules
sleep 2

echo "Record Events That Modify User/Group Information"
echo "" >> /etc/audit/audit.rules
echo "# Record Events That Modify User/Group Information" >> /etc/audit/audit.rules
echo "-w /etc/group -p wa -k identity" >> /etc/audit/audit.rules 
echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/audit.rules
sleep 2

echo "Record Events That Modify the System's Network Environment"
echo "" >> /etc/audit/audit.rules
echo "# Record Events That Modify the System's Network Environment" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/audit.rules
echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/audit.rules
echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/audit.rules
echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/audit.rules
sleep 2

echo "Record Events That Modify the System's Mandatory Access Controls"
echo "" >> /etc/audit/audit.rules
echo "# Record Events That Modify the System's Mandatory Access Controls" >> /etc/audit/audit.rules
echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/audit.rules
sleep 2

echo "Collect Login and Logout Events"
echo "" >> /etc/audit/audit.rules
echo "# Collect Login and Logout Events" >> /etc/audit/audit.rules
echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/audit.rules
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/audit.rules
echo "-w /var/log/tallylog -p -wa -k logins" >> /etc/audit/audit.rules
sleep 2

echo "Collect Session Initiation Information"
echo "" >> /etc/audit/audit.rules
echo "# Collect Session Initiation Information" >> /etc/audit/audit.rules
echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/audit.rules
echo "-w /var/log/wtmp -p wa -k session" >> /etc/audit/audit.rules
echo "-w /var/log/btmp -p wa -k session" >> /etc/audit/audit.rules
sleep 2

echo "Collect Discretionary Access Control Permission Modification Events"
echo "" >> /etc/audit/audit.rules
echo "# Collect Discretionary Access Control Permission Modification Events" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
sleep 2

echo "Collect Unsuccessful Unauthorized Access Attempts to Files"
echo "" >> /etc/audit/audit.rules
echo "# Collect Unsuccessful Unauthorized Access Attempts to Files" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
sleep 2

echo "Collect Successful File System Mounts"
echo "" >> /etc/audit/audit.rules
echo "# Collect Successful File System Mounts" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
sleep 2

echo "Collect File Deletion Events by User"
echo "" >> /etc/audit/audit.rules
echo "# Collect File Deletion Events by User" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
sleep 2

echo "Collect Changes to System Administration Scope"
echo "" >> /etc/audit/audit.rules
echo "# Collect Changes to System Administration Scope" >> /etc/audit/audit.rules
echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/audit.rules
sleep 2

echo "Collect System Administrator Actions"
echo "" >> /etc/audit/audit.rules
echo "# Collect System Administrator Actions" >> /etc/audit/audit.rules
echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/audit.rules
sleep 2

echo "Collect Kernel Module Loading and Unloading"
echo "" >> /etc/audit/audit.rules
echo "# Collect Kernel Module Loading and Unloading" >> /etc/audit/audit.rules
echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rules
echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rules
echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/audit.rules
echo "-a always,exit arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules
sleep 2

echo "Make the Audit Configuration Immutable"
echo "" >> /etc/audit/audit.rules
echo "# Make the Audit Configuration Immutable" >> /etc/audit/audit.rules
echo "-e 2" >> /etc/audit/audit.rules
sleep 2

echo "Configure logrotate"
echo -e "/var/log/boot.log\n$(cat /etc/logrotate.d/syslog)" > /etc/logrotate.d/syslog
grep /var/log /etc/logrotate.d/syslog
sleep 2
echo "Make sure messages/secure/maillog/spooler/boot.log/cron are in the output above"
sleep 5

echo "Enable crond"
chkconfig crond on
sleep 2

echo "Set User/Group Owner and Permission on /etc/crontab"
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
sleep 2

echo "Set User/Group Owner and Permission on /etc/cron.hourly"
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
sleep 2
echo "Set User/Group Owner and Permission on /etc/cron.daily"
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
sleep 2

echo "Set User/Group Owner and Permission on /etc/cron.weekly"
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
sleep 2

echo "Set User/Group Owner and Permission on /etc/cron.monthly"
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
sleep 2

echo "Set User/Group Owner and Permission on /etc/cron.d"
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
sleep 2

echo "Restrict at Daemon"
rm -rf /etc/at.deny
touch /etc/at.allow
chown root:root /etc/at.allow
chmod og-rwx /etc/at.allow
sleep 2

echo "Restrict at/cron to Authorized Users"
rm -rf /etc/cron.deny
touch /etc/cron.allow
chown root:root /etc/cron.allow
chmod og-rwx /etc/cron.allow
sleep 2

# Commenting this line out for verionsing reasons, uncommented breaks SSH on certain versions - matt trotter 
#echo "Set SSH Protocol to 2"
#perl -i -npe 's/#Protocol 2/Protocol 2/' /etc/ssh/sshd_config
#grep "^Protocol" /etc/ssh/sshd_config
#sleep 2

echo "Set Permissions on /etc/ssh/sshd_config"
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
sleep 2

echo "Set SSH Log Level to Info"
perl -i -npe 's/#LogLevel INFO/LogLevel INFO/' /etc/ssh/sshd_config
grep "^LogLevel" /etc/ssh/sshd_config
sleep 2

echo "Disable X11 forwarding"
sed -i "/X11Forwarding/s/yes/no/" /etc/ssh/sshd_config
grep "^X11Forwarding" /etc/ssh/sshd_config
sleep 2

echo "SSH MaxAuthTries 4 or less"
perl -i -npe 's/#MaxAuthTries 6/MaxAuthTries 4/' /etc/ssh/sshd_config
grep "MaxAuthTries" /etc/ssh/sshd_config
sleep 3

echo "Disable SSH Root Login"
perl -i -npe 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
perl -i -npe 's/PermitRootLogin forced-commands-only/#PermitRootLogin forced-commands-only/' /etc/ssh/sshd_config
grep "^PermitRootLogin" /etc/ssh/sshd_config
sleep 2

echo "Set SSH IgnoreRhosts to yes"
perl -i -npe 's/#IgnoreRhosts yes/IgnoreRhosts yes/' /etc/ssh/sshd_config
grep "IgnoreRhosts" /etc/ssh/sshd_config 
sleep 3

#echo "Set SSH HostbasedAuthentication to No"
#perl -i -npe 's/#HostbasedAuthentication no/HostbasedAuthentication no/' /etc/ssh/sshd_config
#grep "HostbasedAuthentication no" /etc/ssh/sshd_config
#sleep 2

echo "Set SSH PermitEmptyPasswords to no"
perl -i -npe 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
grep "PermitEmptyPasswords" /etc/ssh/sshd_config
sleep 2

echo "Do not allow users to set environment options"
perl -i -npe 's/#PermitUserEnvironment no/PermitUserEnvironment no/' /etc/ssh/sshd_config
grep "PermitUserEnvironment" /etc/ssh/sshd_config
sleep 2

echo "User Only Approved Cipher in Counter Mode"
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config
sleep 2

echo "Set Idle Timeout Interval for User Login"
perl -i -npe 's/#ClientAliveInterval 0/ClientAliveInterval 300/' /etc/ssh/sshd_config
perl -i -npe 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/' /etc/ssh/sshd_config
grep "ClientAliveInterval" /etc/ssh/sshd_config
grep "ClientAliveCountMax" /etc/ssh/sshd_config
sleep 2

echo "Enabling the banner"
sed -i '138a\Banner /etc/issue.net\' /etc/ssh/sshd_config
grep Banner /etc/ssh/sshd_config


#echo "Limit Access via SSH"
#echo "AllowGroups domain\ admins" >> /etc/ssh/sshd_config

echo "Confirm password hashing is sha512"
authconfig --test | grep hashing | grep sha512
sleep 2

#echo "Set password requirements"
#cp /etc/pam.d/system-auth /etc/pam.d/system-auth
#perl -i -npe 's/password    requisite     pam_cracklib.so try_first_pass retry=3 type=/password    required     pam_cracklib.so try_first_pass retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1/' /etc/pam.d/system-auth
#grep pam_cracklib.so /etc/pam.d/system-auth
#sleep 2 

# Place-holder for Failed Password Attempts Page 143
# Place-holder for Limit Password Reuse Page 144
# Place-holder for Restricting Access to the su Command Page 145
# Place-holder for Set Password Expiration Days Page 147
# Place-holder for Set Password Minimum Number of Days Page 147
# Place-holder for Set Password Expiring Warning Days Page 148

echo "Disable system accounts. No results should be returned."
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin") {print}'
sleep 2

echo "Set Default Group for root"
grep "^root:" /etc/passwd | cut -f4 -d:
echo "This should return 0"
sleep 2

echo "set Default umask for Users"
perl -i -npe 's/umask 002/umask 077/' /etc/bashrc
perl -i -npe 's/umask 002/umask 077/' /etc/profile
sleep 2

echo " Removing OS Information from Banners"
sed -i '1,2d' /etc/issue
egrep '(\\v|\\r|\\m|\\s)' /etc/issue
egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net
egrep '(\\v|\\r|\\m|\\s)' /etc/motd
sleep 2

echo "Review installed packages. The output file will be placed in the directory where the script is run from"
rpm -Va --nomtime --nosize --nomd5 --nolinkto > packages.txt
echo "Code Meaning S File size differs. M File mode differs (includes permissions and file type). 5 The MD5 checksum differs. D The major and minor version numbers differ on a device file. L A mismatch occurs in a link. U The file ownership differs. G The file group owner differs. T The file time (mtime) differs."
sleep 3

echo "Verify permissions on /etc/passwd"
chmod 644 /etc/passwd
ls -l /etc/passwd
sleep 2

echo "verify Permissions on /etc/shadow"
chmod 000 /etc/shadow
ls -l /etc/shadow
sleep 2

echo "Verify permissions on /etc/gshadow"
chmod 000 /etc/gshadow
ls -l /etc/gshadow
sleep 2

echo "Verify permissions on /etc/group"
chmod 644 /etc/group
ls -l /etc/group
sleep 2

echo "Verify User/Group Ownership on /etc/passwd"
chown root:root /etc/passwd
ls -l /etc/passwd
sleep 2

echo "Verify User/Group ownership on /etc/group"
chown root:root /etc/group
ls -l /etc/group
sleep 2

echo "Verify User/Group ownership on /etc/shadow"
chown root:root /etc/shadow
ls -l /etc/shadow
sleep 2

echo "Verify User/Group ownership on /etc/gshadow"
chown root:root /etc/gshadow
ls -l /etc/gshadow
sleep 2

echo "Find World Writable files"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 -print
sleep 2
echo "Correct the files in the output if any by running chmod o-w but check vendor documentation if the permissions are truly needed"
sleep 2

echo "Find Un-owned Files and Directories"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls
echo "Correct the output if any"
sleep 2

echo "Find SUID System Executables"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print
echo "Ensure no rogue SUID programs have been introduced"
sleep 5

echo "Find SGID System Executables"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print
echo "Ensure no rogue SGID programs have been introduced"
sleep 5

echo "Ensure password fields are not empty"
/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print $1 " does not have a password "}'
sleep 5

echo "Verify No Legacy plus Entries exist in /etc/passwd file"
/bin/grep '^+:' /etc/passwd
sleep 5

echo "Verify No Legacy plus Entries exist in /etc/shadow file"
/bin/grep '^+:' /etc/shadow
sleep 5

echo "Verify No Legacy plus Entries exist in /etc/group file"
/bin/grep '^+:' /etc/group
sleep 5

echo "Verify No UID 0 Accounts Exist other than root"
/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }'
sleep 3

echo "Checking for duplicate UIDs"
echo "The Output for the Audit of Control 9,2,15 - Check for Duplicate UIDs is"
/bin/cat /etc/passwd |/bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        users=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
             /etc/passwd | /usr/bin/xargs`
        echo "Duplicate UID ($@): ${users}"
    fi
done
sleep 2

echo "Checking for duplicate GIDs"
echo "The Output for the Audit of Control 9,2,16 - Check for Duplicate GIDs is"
/bin/cat /etc/group |/bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        users=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
             /etc/group | /usr/bin/xargs`
        echo "Duplicate UID ($@): ${users}"
    fi
done
sleep 2

echo "Checking Reserved SUIDs"
echo "The Output for the Audit of Control 9.2.17 - Check That Reserved UIDS Are Assigned to System Accounts is"
defUsers="root bin daemon adm lp sync shutdown halt mail news uucp operator games gopher ftp nobody nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid named xfs gdm sabayon usbmuxd rtkit abrt saslauth pulse postfix tcpdump"
/bin/cat /etc/passwd | /bin/awk -F: '($3 < 500) { print $1" "$3 }' |\
while read user uid; do
    found=0
    for tUser in ${defUsers}
    do
        if [ ${user} = ${tUser} ]; then
            found=1
        fi
    done
    if [ $found -eq 0 ]; then
        echo "User $user has a reserved UID ($uid)."
    fi
done
sleep 2

echo "Checking for duplicate users"
echo "The Output for the Audit of Control 9.2.18 - Check for Duplicate User Names is"
cat /etc/passwd | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
        echo "Duplicate User Name ($2): ${uids}"
    fi
done
sleep 2

echo "Checking for duplicate group names"
echo "The Output for the Audit of Control 9.2.19 - Check for Duplicate Group Names is"
cat /etc/group | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
        echo "Duplicate Group Name ($2): ${uids}"
    fi
done
sleep 2

echo "Configuring the warning banner"
sed -i '1,2d' /etc/issue.net
echo "WARNING ** WARNING ** WARNING ** WARNING ** WARNING" >> /etc/issue.net
echo "This is a U.S. Government computer system, which may be accessed and used only for authorized Government business by authorized personnel. Unauthorized access or use of this computer system may subject violators to criminal, civil, and/or administrative action.  All information on this computer system may be intercepted, recorded, read, copied, and disclosed by and to authorized personnel for official purposes, including criminal investigations.  Such information includes sensitive data encrypted to comply with confidentiality and privacy requirements.  Access or use of this computer system by any person, whether authorized or unauthorized, constitutes consent to these terms.  There is no right of privacy in this system." >> /etc/issue.net
echo "WARNING ** WARNING ** WARNING ** WARNING ** WARNING" >> /etc/issue.net
sed -i '/WARNING/{x;p;x;G;}' /etc/issue.net
cat /etc/issue.net
sleep 3

echo "Starting second script"

sleep 5

#
# Remediation for STIG violations
# Written by Matthew Trotter for Red Hat AS4U6 systems
# 5/15/08 Revision 2.0
# 7/07/08 Revision 2.1, modified by DHusk for RHEL5 and changed method to grep for tab in strings.
# 9/12/08 Revision 2.2, modified by DHusk, add code to fix permissions of sa and rpmpkgs log files.
# 7/01/09 Revision 2.3, modified by DHusk to fix permissions of doc and manpages.
# 9/6/2013 - SHenson (SDH) Re-written specifically for RHEL6. Adding new STIG fixes - Shawn Henson
# 11/20/13 Begin re-writing for automated crons - SHenson
# 11/27/13 Remove file fixes for baselined files.
# Files to be copied:
# /etc/pam.d/password-auth
# /etc/pam.d/system-auth
/etc/audit/audit.rules
/etc/audit/auditd.conf
/etc/issue
#/etc/ssh/sshd_config
/etc/login.defs
/etc/libuser.defs
/etc/aide.conf

# Insert exit choice here during testing phase of automation/cron/GIT setup
#echo "WARNING: This script will change files and config settings - continue? [Y|N] : "
#read ANS
#ANS=`echo $ANS |tr "[:lower:]" "[:upper:]"`

#if [ "$ANS" != "Y" ]
#then
#   echo "Exiting"
#   exit 0
#fi



# Initialize script variables

MYPID=`echo $$`
export MYDATE=`date +%m%d%y.%H%M%S`

# Backup Files we munge

#cp /etc/audit/audit.rules /etc/audit/audit.rules.$MYDATE.${MYPID}
#cp /etc/audit/auditd.conf /etc/audit/auditd.conf.$MYDATE.${MYPID}
#cp /etc/ssh/sshd_config /etc/ssh/sshd_config.$MYDATE.${MYPID}
#cp /etc/login.defs /etc/login.defs.$MYDATE.${MYPID}
#cp /etc/pam.d/system-auth /etc/pam.d/system-auth.$MYDATE.${MYPID}
#cp /etc/pam.d/password-auth /etc/pam.d/password-auth.$MYDATE.${MYPID}
#cp /etc/fstab /etc/fstab.$MYDATE.${MYPID}
#cp /etc/sysctl.conf /etc/sysctl.conf.$MYDATE.${MYPID}


# Find out what directory I am running from
SCRIPTDIR=`pwd`

DATE_STRING=$MYDATE
TESTVAR=
RHEL=
RHEL=`grep "release\ 6" /etc/redhat-release`
if [ "$RHEL" = "" ]
then
   echo "OS is not RHEL 6 - exiting"
   exit
fi

# Variable for file copies below
# Where possible STIG id numbers
# are in the files copied.
# yum files are copied here as well
# since they are required for security patches.

FILE_MATRIX="/root/FILES/FILE_MATRIX"

if [ -f "$FILE_MATRIX" ]

then

   for i in `awk '{print $1}' $FILE_MATRIX`

   do

      SOURCE="/root/FILES/$i"

      TARGET=`grep $i $FILE_MATRIX|awk '{print $2}'`

      /bin/cp $SOURCE $TARGET

   done

else

    echo "File $FILE_MATRIX is missing"

    echo "Exiting"

fi

#
# GEN000020,40,60 require password for single user mode
# SDH - 8/2013 - Red Hat 6 - This is now set in /etc/sysconfig/init
TESTVAR=
TESTVAR=`grep ^SINGLE /etc/sysconfig/init`
if [ "$TESTVAR" = "" ]
then
   cp -a /etc/sysconfig/init /etc/sysconfig/init.${DATE_STRING}
   echo "SINGLE=/sbin/sulogin" >> /etc/sysconfig/init
   chmod 644 /etc/sysconfig/init
fi

# GEN000760 An account is not locked after 35 days of inactivity.
for i in `cat /etc/passwd|cut -d : -f 1`
do
   CHK_MAX=`chage -l $i|grep Maximum|cut -d : -f 2|sed -e 's/^[ \t]*//'`
   if [ "$CHK_MAX" != 99999 ]
   then
      chage -M 60 -m 1 -I 35 $i
   fi
done
#
# GEN000920 set root account home directory to 700 permissions
chmod 700 /root
#
# GEN000980 root account can be logged into from other than console
# wipe out original and add required
# waiver for tty's - Waiver ID 71
cp -a /etc/securetty /etc/securetty.${DATE_STRING}
cat /dev/null > /etc/securetty
echo "console" >> /etc/securetty
echo "tty1" >> /etc/securetty

#
#
# GEN001200 System command permissions are more permissive than 755.
chmod 755 /etc/rc.d/init.d/*

# Added syslog section - SHenson 10/24/13
#if [ -f /etc/logrotate.d/rpm ]
#then
#  TESTVAR=
#  TESTVAR=`grep "create 0600" /etc/logrotate.d/rpm`
#  if [ "$TESTVAR" = "" ]
#  then
#      sed '/\}/i\    create 0600 root root' /etc/logrotate.d/rpm > /tmp/tempfile
#      mv -f /tmp/tempfile /etc/logrotate.d/rpm
#  fi
#fi


# and then fix the remaining logs
chmod 640 /var/log/sa/* >/dev/null 2>&1
chmod 600 /var/log/rpmpkgs* >/dev/null 2>&1
chmod 640 /var/log/wtmp* >/dev/null 2>&1
chmod 640 /var/log/messages* >/dev/null 2>&1

# make everything 640 in /var/log
find /var/log/. -type f -exec chmod 640 {} \;

if [ -f /var/log/ssevt.log ]
then
   chmod 640 /var/log/ssevt.log
fi
#
# GEN001280 set manpages and doc to 644 permissions
#chmod -R 644 /usr/share/doc;chmod -R 644 /usr/share/man
find /usr/share/doc -type f|xargs chmod 644
find /usr/share/man -type f|xargs chmod 644

#GEN001480 user (ca) has home permissions greater than 750
if [ -d /opt/ca ]
then
   chmod 750 /opt/cA
fi
   chmod 700 /home/*
#


# GEN001660 Run control scripts are not owned by root or bin.
chown root: /etc/rc.d/init.d/*
#
# GEN001880 local initialization files more permissive than 740
for i in .bash_profile .bash_logout .bashrc .emacs .gtkrc
do
      find /home -name $i -exec chmod o-rwx {} \;

done

chmod o-rwx /etc/skel/.bash*
chmod o-rwx /etc/skel/.emacs

# GEN001900
for i in `find / -name .profile|xargs grep -l ":\."`
do
   sed 's/\:\.//g' $i > /tmp/tempfile
   mv -f /tmp/tempfile $i
done
if [ -f /home/oracle/.profile ]
then
   chown oracle:dba /home/oracle/.profile
   chmod 640 /home/oracle/.profile
fi
#
#GEN002420 set nosuid option on removable media and non system filestems in fstab
cp -a /etc/fstab /etc/fstab.${DATE_STRING}
sed -e '/boot/s/defaults/nosuid/' -e '/home/s/defaults/nosuid/' -e '/websvr/s/defaults/nosuid/' -e '/pamconsole/s/pamconsole,/nosuid,&/' -e '/\/u0[0-9]/s/defaults/nosuid/' /etc/fstab > /tmp/tempfile
mv -f /tmp/tempfile /etc/fstab
chmod 644 /etc/fstab
mount /boot -o remount
mount /home -o remount

TESTVAR=
TESTVAR=`grep websvr /etc/fstab`
if [ "$TESTVAR" != "" ]
then
   mount /websvr -o remount
fi

for i in `grep u0 /etc/fstab |cut -d" " -f12`
do
   mount $i -o remount
done

#
# GEN002960 need cron.allow file and/or cron.deny
TESTVAR=
TESTVAR=`grep root /etc/cron.allow`
if [ "$TESTVAR" = "" ]
then
   echo "root" >> /etc/cron.allow
fi
TESTVAR=
TESTVAR=`grep atech /etc/cron.allow`
if [ "$TESTVAR" = "" ]
then
   echo "atech" >> /etc/cron.allow
fi
TESTVAR=
TESTVAR=`grep oracle /etc/cron.allow`
if [ "$TESTVAR" = "" ]
then
   echo "oracle" >> /etc/cron.allow
fi
chmod 600 /etc/cron.allow

#
# GEN003080 cron file are more permissive that 600 or 700 on some Linux systems.
chmod go-rwx /etc/crontab >/dev/null 2>&1
chmod go-rwx /etc/cron.d/* >/dev/null 2>&1
chmod go-rwx /etc/cron.hourly/* >/dev/null 2>&1
chmod go-rwx /etc/cron.daily/* >/dev/null 2>&1
chmod go-rwx /etc/cron.weekly/* >/dev/null 2>&1
chmod go-rwx /etc/cron.monthly/* >/dev/null 2>&1
#
# GEN003320 need a /etc/at.allow file.
if [ -f /etc/at.allow ]
then
   TESTVAR=
   TESTVAR=`grep root /etc/at.allow`
      if [ "$TESTVAR" = "" ]
      then
         echo "root" >> /etc/at.allow
      fi
else
   echo "root" > /etc/at.allow
fi
chmod 600 /etc/at.allow

# GEN003520 The core dump directory is not owned and group owned by root and/or is more permissive than 700.
# unmount first if FS
if [ -d /var/crash ]
then
   # check for filesystem to umount
   df /var/crash |grep -q crashvol

   if [ $? = "0" ]
   then
      umount /var/crash
      chmod 700 /var/crash
      mount /var/crash
   fi

   # if no FS - then just chmod
   chmod 700 /var/crash
fi
#
# GEN003600  Network parameters are not securely set.
TESTVAR=
TESTVAR=`grep "#Security requirements" /etc/sysctl.conf`
if [ "$TESTVAR" = "" ]
then
   cp -a /etc/sysctl.conf /etc/sysctl.conf.${DATE_STRING}
   echo "" >> /etc/sysctl.conf
   echo "#Security requirements" >> /etc/sysctl.conf
   echo "net.ipv4.tcp_max_syn_backlog = 1280" >> /etc/sysctl.conf
   echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
   echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
   echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
   echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
   echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
   echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
   echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
   echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
   echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
   echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
   echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
   echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
   # Load settings
   sysctl -p
fi
#
# GEN003700 All inetd/xinetd services are disabled and inetd is not disabled.
# Commnet out - we remove xinted now on RH6
#service xinetd stop >/dev/null 2>&1
#chkconfig xinetd off

# GEN003740  The inetd.conf file permissions are more permissive than 440 The linux xinetd.d directory is more permissive than 755.
# commnet out - we remove xinetd now on RH6
#chmod 440 /etc/xinetd.conf
#chmod 755 /etc/xinetd.d
#chmod 600 /etc/xinetd.d/*
#
# GEN003865  Network analysis tools are enabled. (tcpdump is required but will be restricted to root on use)
chmod 700 /usr/sbin/tcpdump
#
# GEN004000  The traceroute command is more permissive than 700.
chmod 700 /bin/traceroute
#
# GEN004540  The sendmail help command is not disabled.
if [ -f /etc/mail/sendmai.cf ]
then
   TESTVAR=
   TESTVAR=`grep "#HelpFile" /etc/mail/sendmail.cf`
   if [ "$TESTVAR" = "" ]
   then
      cp -a /etc/mail/sendmail.cf /etc/mail/sendmail.cf.${DATE_STRING}
      sed '/HelpFile/s/O/\#&/' /etc/mail/sendmail.cf > /tmp/tempfile
      mv -f /tmp/tempfile /etc/mail/sendmail.cf
      chmod 644 /etc/mail/sendmail.cf
   fi
fi
#
# GEN004560 The O Smtp greeting in sendmail.cf, or equivalent, has not been changed to mask the version.
if [ -f /etc/mail/sendmail.cf ]
then
   TESTVAR=
   TESTVAR=`grep "#SmtpGreeting" /etc/mail/sendmail.cf`
   if [ "$TESTVAR" = "" ]
   then
      sed -e '/SmtpGreeting/s/O/\#&/' -e '/SmtpGreeting/a\O\ SmtpGreetingMessage\=\$j\ \$b' /etc/mail/sendmail.cf > /tmp/tempfile
      mv -f /tmp/tempfile /etc/mail/sendmail.cf
      chmod 644 /etc/mail/sendmail.cf
      service sendmail restart
   fi
fi


# GEN004640  The sendmail decode command is not disabled.
TESTVAR=
TESTVAR=`grep "#decode" /etc/aliases`
if [ "$TESTVAR" = "" ]
then
   cp -a /etc/aliases /etc/aliases.${DATE_STRING}
   sed '/decode/s/decode/#&/' /etc/aliases > /tmp/tempfile
   mv /tmp/tempfile /etc/aliases
fi

# GEN005400  The /etc/syslog.conf is not owned by root or is more permissive than 640.
chmod 640 /etc/rsyslog.conf

#
#GEN005540  Encrypted communications are not configured for IP filtering and logon warning banners. SSH is not restricted with TCP Wrappers.
TESTVAR=
TESTVAR=`grep "sshd:" /etc/hosts.allow`
if [ "$TESTVAR" = "" ]
then
   cp -a /etc/hosts.allow /etc/hosts.allow.${DATE_STRING} 
   echo "sshd:    ALL" >> /etc/hosts.allow
   echo "sendmail:   localhost" >> /etc/hosts.allow
   echo "snmpd:    localhost" >> /etc/hosts.allow
fi
#
# GEN006620  The access control program is not configured to grant and deny system access to specific hosts. /etc/hosts.deny does not contain ALL:ALL.
TESTVAR=
TESTVAR=`grep "ALL:" /etc/hosts.deny`
if [ "$TESTVAR" = "" ]
then
   cp -a /etc/hosts.deny /etc/hosts.deny.${DATE_STRING}
   echo "ALL:   ALL" >> /etc/hosts.deny
fi
#

#LNX00160 The grub.conf is more permissive than 600.
chmod 600 /boot/grub/grub.conf

# LNX00320 Special privilege accounts, such as shutdown and halt have not been deleted.
# LNX00340 Unnecessary accounts. (e.g., games, news) and associated software have not been deleted
for i in shutdown halt games news gopher
do
   TESTVAR=
   TESTVAR=`grep $i /etc/passwd`
   if [ "$TESTVAR" != "" ]
      then
      userdel $i
   fi
done
#
# LNX00440  The /etc/login.access or /etc/security/access.conf file is more permissive than 640.
chmod 640 /etc/security/access.conf
#
# LNX00520  The /etc/sysctl.conf file is more permissive than 600.
chmod 600 /etc/sysctl.conf

# Other fixes without a STIG reference



# /etc/resolv.conf is 664 - change to 640
# Leave as 664 - vintela AD will not work
chmod 664 /etc/resolv.conf


# remove /etc/security/console.perms
if [ -f /etc/security/console.perms ]
then
   mv /etc/security/console.perms /etc/security/console.perms.$DATE_STRING
fi


# append  "mesg n" to /etc/profile and /etc/csh.login
for i in /etc/profile /etc/csh.login
do
    grep -q "mesg n" $i
    if [ $? != "0" ] 
    then
       echo "" >> $i
       echo "mesg n" >> $i 
    fi
done


# make sure core dumps are disabled
grep core /etc/security/limits.conf |grep hard |grep 0 >/dev/null 2>&1
if [ $? != "0" ]
then
   echo "" >> /etc/security/limits.conf
   echo "# Security setting to disable core dumps" >> /etc/security/limits.conf
   echo "*               hard    core            0" >> /etc/security/limits.conf
fi

# RHEL-06-000098 - disable ipv6 kernel module
# We now use ipv6
TESTVAR=
TESTVAR=`grep -d recurse -i ipv6 /etc/modprobe.d`
if [ "$TESTVAR" = "" ]
then
   echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6_disable.conf
fi

# RHEL-06-000124 - prevent loading of dccp
TESTVAR=
TESTVAR=`grep -d recurse -i dccp /etc/modprobe.d`
if [ "$TESTVAR" = "" ]
then
   echo "install dccp /bin/true" >> /etc/modprobe.d/dccp_disable.conf
fi

# RHEL-06-000125 - prevent loading of sctp
TESTVAR=
TESTVAR=`grep -d recurse -i sctp /etc/modprobe.d`
if [ "$TESTVAR" = "" ]
then
   echo "install sctp /bin/true" >> /etc/modprobe.d/sctp_disable.conf
fi

# RHEL-06-000127 - prevent loading of tipc
TESTVAR=
TESTVAR=`grep -d recurse -i tipc /etc/modprobe.d`
if [ "$TESTVAR" = "" ]
then
   echo "install tipc /bin/true" >> /etc/modprobe.d/tipc_disable.conf
fi

# RHEL-06-000315 - prevent loading of bluetooth
# Note - 2 entries for this
TESTVAR1=
TESTVAR1=`grep -d recurse -i bluetooth /etc/modprobe.d`
if [ "$TESTVAR1" = "" ]
then
   echo "install bluetooth /bin/true" >> /etc/modprobe.d/bluetooth_disable.conf
fi
TESTVAR2=
TESTVAR2=`grep -d recurse -i net-pf-31 /etc/modprobe.d`
if [ "$TESTVAR2" = "" ]
then
   echo "install net-pf-31 /bin/true" >> /etc/modprobe.d/bluetooth_disable.conf
fi

# RHEL-06-000503 - prevent loading of usb-storage
TESTVAR=
TESTVAR=`grep -d recurse -i usb-storage /etc/modprobe.d`
if [ "$TESTVAR" = "" ]
then
   echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb-storage_disable.conf
fi


# RHEL-06-000509 - Send audit records to syslog
TESTVAR=
TESTVAR=`grep "active = yes" /etc/audisp/plugins.d/syslog.conf`
if [ "$TESTVAR" = "" ]
then
   sed '/active/s/no/yes/' /etc/audisp/plugins.d/syslog.conf > /tmp/tempfile
   mv -f /tmp/tempfile /etc/audisp/plugins.d/syslog.conf
   chmod 640 /etc/audisp/plugins.d/syslog.conf
   service auditd restart
fi

# RHEL-06-000521
# forward root's email
TESTVAR=
TESTVAR=`grep ^root /etc/aliases`
if [ "$TESTVAR" = "" ]
then
   cp -a /etc/aliases /etc/aliases.${DATE_STRING}
   echo "root:  cmslinuxadmins@hp.com" >>/etc/aliases
   newaliases
fi

# RHEL-06-000521
# forward root's email
TESTVAR=
TESTVAR=`grep ^root /etc/postfix/generic`
if [ "$TESTVAR" = "" ]
then
   cp -a /etc/postfix/generic /etc/postfix/generic.${DATE_STRING}
   echo "root  cmslinuxadmins@hp.com" >>/etc/postfix/generic
   newaliases
fi


# RHEL-06-000204
# uninstall xinetd
TESTVAR=
TESTVAR=`rpm -q xinetd |grep -v "not installed"`
if [ "$TESTVAR" != "" ]
then
   rpm -q xinetd |xargs rpm -e
fi

# RHEL-06-000261
service abrtd stop >/dev/null 2>&1
chkconfig abrtd off

# RHEL-06-000262
service atd stop >/dev/null 2>&1
chkconfig atd off

# RHEL-06-000335
# set inactivity
TESTVAR=
TESTVAR=`grep INACTIVE=35 /etc/default/useradd`
if [ "$TESTVAR" = "" ]
then
   sed '/INACTIVE/s/180/35/' /etc/default/useradd >/tmp/tempfile
   mv -f /tmp/tempfile /etc/default/useradd
fi

# RHEL-06-000342, RHEL-06-000343, RHEL-06-000344 RHEL-06-000345
for i in /etc/bashrc /etc/csh.cshrc /etc/profile 
do
   sed 's/umask [0-9].*/umask 077/g' $i > /tmp/tempfile
   mv /tmp/tempfile $i
done


## New findings from HICS audit. - Added 9/25/13 - SHenson
# not in /patches/CMS-Linux yet (as of 11/27/13 - sdh

# RHEL-06-000070
# turn off interactive boot
TESTVAR=
TESTVAR=`grep ^PROMPT=no /etc/sysconfig/init`
if [ "$TESTVAR" = "" ]
then
   sed 's/PROMPT=yes/PROMPT=no/' /etc/sysconfig/init >/tmp/tempfile
   mv -f /tmp/tempfile /etc/sysconfig/init
fi

# Set UTC time per CMSR - no Vulnerability ID
TESTVAR=
TESTVAR=`grep UTC=true /etc/sysconfig/clock`
if [ "$TESTVAR" = "" ]
then
   echo "UTC=true" >>/etc/sysconfig/clock
fi

# RHEL-06-000243
service avahi-daemon stop >/dev/null 2>&1
chkconfig avahi-daemon off


# grub pw should be sha256 encrypted not md5
# RHEL-06-000068 
DATE=`date +%m%d%y.%H%M%S`
FILE=/etc/grub.conf
FILE2=/tmp/grub.conf.tmp
FILE3=/tmp/grub.conf.tmp2

grep "^password --md5" $FILE
if [ $? = "0" ]
then
   cp $FILE $FILE.$DATE
   sed 's/^password/#&/' $FILE > $FILE2
   sed '/^\#password/a\password --encrypted $6$YQwSemJs9DIsdUJa$PlvH1tg2p1tV/CKjqou5QK0ul0q4pZiua.ygZWv/hSgAx6GR/XLWQzU8AtbIKQoym/sjOI5wo.DilMA2jY.LN/' $FILE2 >$FILE3
   cp $FILE3 $FILE
   chmod 600 $FILE
   chown root:root $FILE
   /bin/rm $FILE2
   /bin/rm $FILE3
   grep ^password $FILE
fi 

### End HICS Audit specific findings.

### Adding Auditd Controls
service auditd start
chkconfig auditd on
 
 ###Adding NTPD settings
 service ntpd start
 chkconfig ntdp on
 

# Fix sshd_config
  echo ""
  echo "=========MANUAL TODO========="
  echo "WARNING:PermitRootlogin has been set to no"
  echo "You will probably want to change this unless vintela is installed"
  echo "System rebooting now..."
  reboot

