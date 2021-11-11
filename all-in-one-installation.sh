#!/bin/bash
service wazuh-agent stop
yum remove wazuh-agent -y
rm -rf /var/ossec/
WAZUH_MANAGER='' WAZUH_AGENT_GROUP='default' yum install https://packages.wazuh.com/4.x/yum/wazuh-agent-4.2.4-1.x86_64.rpm -y
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
