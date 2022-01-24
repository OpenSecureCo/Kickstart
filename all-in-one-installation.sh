#!/bin/bash
curl -L https://pkg.osquery.io/rpm/GPG | tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
yum-config-manager --enable osquery-s3-rpm
yum install osquery -y
amazon-linux-extras install epel -y
yum install autoconf libtool -y
yum install openssl-devel -y
yum install file-devel -y
yum install jansson jansson-devel -y
yum install flex bison byacc -y
yum install git -y

cd /opt
wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.1.3.tar.gz

tar xzvf v4.1.3.tar.gz

cd yara-4.1.3

./bootstrap.sh
./configure --enable-cuckoo --enable-magic --enable-dotnet
make
make install

git clone https://github.com/Neo23x0/signature-base.git

wget https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/osquery.conf -O /etc/osquery/osquery.conf

systemctl start osqueryd
sleep 3
systemctl stop osqueryd

service wazuh-agent stop
yum remove wazuh-agent -y
rm -rf /var/ossec/
WAZUH_MANAGER='' WAZUH_AGENT_GROUP='default' yum install https://packages.wazuh.com/4.x/yum/wazuh-agent-4.2.5-1.x86_64.rpm -y
echo "logcollector.remote_commands=1" >> /var/ossec/etc/local_internal_options.conf
echo "wazuh_command.remote_commands=1" >> /var/ossec/etc/local_internal_options.conf
echo "<ossec_config>
    <client>
    <server>
      <address></address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>amzn, amzn2</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>
  </ossec_config>" > /var/ossec/etc/ossec.conf
service wazuh-agent start
service wazuh-agent enable

amazon-linux-extras install epel -y

yum install jq -y

wget https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/custom-ssh.sh -O /var/ossec/active-response/bin/custom-ssh.sh

wget https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/custom-suricata.sh -O /var/ossec/active-response/bin/custom-suricata.sh

wget https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/custom-waf.sh -O /var/ossec/active-response/bin/custom-waf.sh

cd /opt/

wget https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-7.16.3-x86_64.rpm

rpm -iv packetbeat-7.16.3-x86_64.rpm 

wget https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/packetbeat.yml -O /etc/packetbeat/packetbeat.yml

systemctl enable packetbeat

systemctl start packetbeat

chown root:ossec /var/ossec/active-response/bin/*

chmod 750 /var/ossec/active-response/bin/*

systemctl restart wazuh-agent

yum install clamav-server clamav-data clamav-update clamav-filesystem clamav clamav-scanner-systemd clamav-devel clamav-lib clamav-server-systemd -y

freshclam

echo "@hourly /bin/freshclam --quiet" >> /etc/crontab

echo "/home/
/opt/
/usr/bin/
/etc/
/usr/sbin/" > /opt/scanfolders.txt

wget https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/Freshclam.conf -O /etc/freshclam.conf

wget https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/scan.conf -O /etc/clamd.d/scan.conf

mkdir /root/scripts/

wget https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/clamscan.sh -O /root/scripts/clamscan.sh

chmod +x /root/scripts/clamscan.sh

echo "0 8 * * * /root/scripts/clamscan.sh" >> /etc/crontab

wget https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/auditd.conf -O /etc/audit/rules.d/audit.rules

auditctl -R /etc/audit/rules.d/audit.rules

echo "Congrats"

ls /etc/nginx*
if [ $? != 0 ] ; then
   clear
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   echo "Please install nginx first..."
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   sleep 5
   else
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   echo "It looks like you need to install Modsecurity. Continuing......"
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   sleep 3
   curl -so ~/modsecinstall.sh https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/modsecinstall && bash ~/modsecinstall.sh
   fi
