#!/bin/bash
touch /tmp/install_log.log
rm /tmp/install_log.log
yum install wget -y
ls /etc/suricata/ 2>/dev/null
#echo $?
if [ $? == 0 ] ; then
   clear
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   echo "It looks like you've already installed Suricata. Wait 5 seconds to continue if you want to upgrade"
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   sleep 5
   while true; do
    read -p "Do you wish to upgrade Suricata?" yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
    done
   systemctl stop suricata
   else
   clear
   echo "Doesn't look like you have installed Suricata. Continuing with the installation..."
   fi
sleep 3
ls /etc/suricata/ 2>/dev/null
if [ $? == 0 ] ; then
   clear
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   echo "# Copying previous suricata.yaml to /tmp/suricata_previous.yaml"
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   sleep 5
   cp -f /etc/suricata/suricata.yaml /tmp/suricata_previous.yaml
   fi
sleep 3
ls /etc/suricata/ 2>/dev/null
if [ $? == 0 ] ; then
   echo "#######################################################"
   echo "# Removing the old Suricata version"
   echo "#------------------------------------------------------"
   echo "#######################################################"
   sleep 3
   clear
   rm -rf /run/suricata*
   rm -rf /usr/lib/python2.7/site-packages/suricata*
   rm -rf /usr/bin/suricata*
   rm -rf /usr/share/man/man1/suricata.1
   rm -rf /usr/share/suricata
   rm -rf /usr/share/doc/suricata
   rm -rf /etc/suricata
   rm -rf /opt/suricata*
   rm -rf /var/lib/suricata*
   rm -rf /var/log/suricata*
   rm -rf /var/updateSuricata.sh
   rm -rf /opt/setinterfaces.sh
   echo "# Old version of Suricata removed#"
   fi
sleep 3
cd /opt/
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "What Suricata version would you like to install?"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
read VER
wget "http://www.openinfosecfoundation.org/download/suricata-$VER.tar.gz"
if [ $? != 0 ] ; then
   clear
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   echo "There was an error..."
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   sleep 5
   exit
   else
   clear
   echo "so far so good"
   fi
echo "#######################################################"
echo "# Begining the Install"
echo "#------------------------------------------------------"
echo "#######################################################"
sleep 3
echo "--------------------------------"
echo "make sure you are ROOT for this!"
echo "--------------------------------"
sleep 3
echo "Phase-1: Getting the dependencies..."
echo "# CentOS-Base.repo
#
# The mirror system uses the connecting IP address of the client and the
# update status of each mirror to pick mirrors that are updated to and
# geographically close to the client.  You should use this for CentOS updates
# unless you are manually picking other mirrors.
#
# If the mirrorlist= does not work for you, as a fall back you can try the
# remarked out baseurl= line instead.
#
#

[base]
name=CentOS-$releasever - Base
mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=os&infra=$infra
#baseurl=http://mirror.centos.org/centos/$releasever/os/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

#released updates
[updates]
name=CentOS-$releasever - Updates
mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=updates&infra=$infra
#baseurl=http://mirror.centos.org/centos/$releasever/updates/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

#additional packages that may be useful
[extras]
name=CentOS-$releasever - Extras
mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=extras&infra=$infra
#baseurl=http://mirror.centos.org/centos/$releasever/extras/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

#additional packages that extend functionality of existing packages
[centosplus]
name=CentOS-$releasever - Plus
mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=centosplus&infra=$infra
#baseurl=http://mirror.centos.org/centos/$releasever/centosplus/$basearch/
gpgcheck=1
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7" > /etc/yum.repos.d/CentOS-Base.repo

wget https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

yum install epel-release-latest-7.noarch.rpm -y

yum install htop -y
yum install wget -y
yum -y install gcc libpcap-devel pcre-devel libyaml-devel file-devel \
zlib-devel jansson-devel nss-devel libcap-ng-devel libnet-devel tar make \
libnetfilter_queue-devel lua-devel

yum install cargo -y
yum install PyYAML -y
wget https://distrib-coffee.ipsl.jussieu.fr/pub/linux/Mageia/distrib/7.1/x86_64/media/core/updates/lib64htp2-4.1.9-1.mga7.x86_64.rpm
yum install lib64htp2-4.1.9-1.mga7.x86_64.rpm -y
yum install cmake ragel -y
yum install boost-devel -y
yum install gcc-c++ -y
yum groupinstall "Development tools" -y
if [ $? != 0 ] ; then
   clear
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   echo "There was an error..."
   echo "Attempting group install with other commands"
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   sleep 5
   exit
   else
   clear
   yum groups mark install "Development Tools" -y
   yum groups mark convert "Development Tools" -y
   yum groupinstall "Development Tools" -y
   echo "Dependencies installed"
   fi
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "Now it's time to install BOOST and HYPERSCAN"
echo "This can take up to 30-45 minutes total to complete configure"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
sleep 5
clear
cd /opt/
ls /opt/boost_*
if [ $? != 0 ] ; then
   clear
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   echo "It looks like you need to install Boost and Hyperscan. Continuing..."
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   sleep 5
   wget https://sourceforge.net/projects/boost/files/boost/1.75.0/boost_1_75_0.tar.gz
   tar xvzf boost_1_75_0.tar.gz
   cd /opt/boost_1_75_0/
   /opt/boost_1_75_0/bootstrap.sh --prefix=/opt/boost
   /opt/boost_1_75_0/b2 install --prefix=/opt/boost --with=all
   cd /opt/
   git clone https://github.com/01org/hyperscan
   cd /opt/hyperscan/
   mkdir /opt/hyperscan/build
   cd /opt/hyperscan/build/
   cmake -DBUILD_STATIC_AND_SHARED=1 -DBOOST_ROOT=/opt/boost_1_75_0/ ../
   make
   make install
   echo "/usr/local/lib64" | sudo tee --append /etc/ld.so.conf.d/usrlocal.conf
   ldconfig
   else
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   echo "Boost and Hyperscan already installed. Progressing"
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   sleep 5
   fi
clear
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "Now it's time to install SURICATA"
echo "This can take up to 10-20 minutes total to complete configure"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
sleep 3
cd /opt/
tar xvf suricata*
rm *.gz
cd /opt/suricata*
echo "Phase-2: Issuing the configure command.  Please be patient while this completes..."
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-nfqueue --enable-lua --enable-rust --with-libhs-includes=/usr/local/include/hs/ --with-libhs-libraries=/usr/local/lib64/
if [ $? != 0 ] ; then
   clear
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   echo "There was an error..."
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   sleep 5
   exit
   else
   clear
   echo "configure command finished without errors"
   fi
echo "Phase-3: Issuing the MAKE command...this could take a bit to complete so please be patient..."
make
if [ $? != 0 ] ; then
   clear
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   echo "There was an error..."
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   sleep 5
   exit
   else
   clear
   echo "MAKE command finished without errors"
   fi
echo "Phase-4: Issuing the 'make install' command..."
make install-full
if [ $? != 0 ] ; then
   clear
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   echo "There was an error..."
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   sleep 5
   exit
   else
   clear
   echo "Phase-5: finalizing installation!"
   fi
suricata-update list-sources
clear
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "Enabling rules - secret code is 8350622693964949"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
sleep 5
suricata-update enable-source et/pro
suricata-update enable-source oisf/trafficid
suricata-update enable-source sslbl/ja3-fingerprints
suricata-update enable-source ptresearch/attackdetection
suricata-update enable-source sslbl/ssl-fp-blacklist
suricata-update enable-source etnetera/aggressive
echo "# Rules matching specifiers in this file will be converted to drop rules.
#
# Examples:
#
# 1:2019401
# 2019401
#
# re:heartbleed
# re:MS(0[7-9]|10)-\d+" > /etc/suricata/drop.conf

echo "# Rules matching specifiers in this file will be converted to disabled rules.
#
# Examples:
#
# 1:2019401
# 2019401
#
# re:heartbleed
# re:MS(0[7-9]|10)-\d+" > /etc/suricata/disable.conf

echo "# Rules matching specifiers in this file will be local rules.
#
# Examples:
#
# 1:2019401
# 2019401
#
# re:heartbleed
# re:MS(0[7-9]|10)-\d+" > /etc/suricata/local.rules

echo "# Rules matching specifiers in this file will be modified rules.
#
# Examples:
#
# 1:2019401
# 2019401
#
# re:heartbleed
# re:MS(0[7-9]|10)-\d+" > /etc/suricata/modify.conf

echo "# Rules matching specifiers in this file will be enabled rules.
#
# Examples:
#
# 1:2019401
# 2019401
#
# re:heartbleed
# re:MS(0[7-9]|10)-\d+" > /etc/suricata/enable.conf

tee -a /var/updateSuricata.sh <<EOF
#!/bin/bash
suricata-update -f -v --local=/etc/suricata/local.rules --disable-conf=/etc/suricata/disable.conf --modify-conf=/etc/suricata/modify.conf --enable-conf=/etc/suricata/enable.conf --drop-conf=/etc/suricata/drop.conf --reload-command='kill -USR2 \$(cat /var/run/suricata.pid)' |& tee /tmp/updateSuricataOutput.txt

#don't need if statement anymore because doing it in salt command
#if cat /tmp/updateSuricataOutput.txt | grep -i '<Error>'; then
#       echo "1"
#else
#       echo "0"
#fi"
EOF
chmod +x /var/updateSuricata.sh
/var/updateSuricata.sh
if [ $? != 0 ] ; then
   clear
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   echo "There was an error..."
   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
   sleep 5
   exit
   else
   clear
   echo "Rules Updated!"
   fi
echo "touching the suricata.yaml  file to show suricata is installed"
touch /etc/suricata/suricata.yaml
echo "You made it!  Installation was a success. Your installation of suricata is complete"
echo "To configure the interface setting to run in a layer 2 mode run the interfaces.sh script"
python -c 'import sys;print("Enter the interfaces Suricata will use in Layer 2 mode. Provide the interface name one at a time then press ENTER key. Press Ctrl+D when finished.");f=open("/opt/interfaces.txt","w");[f.write(l) for l in sys.stdin.readlines()];f.close()'
tee -a /opt/setinterfaces.sh <<EOF
#!/bin/bash
for i in \$(cat /opt/interfaces.txt)
do
  /usr/sbin/ifdown \$i
  /usr/sbin/ethtool -L \$i combined 16
  /usr/sbin/ifup \$i
  /usr/sbin/ethtool -X \$i hkey 6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A equal 16
  /usr/sbin/ethtool -C \$i adaptive-rx off adaptive-tx off rx-usecs 125
  /usr/sbin/ethtool -G \$i rx 4096
  /usr/sbin/ethtool -K \$i tx-checksum-ipv4 on
  /usr/sbin/ethtool -K \$i hw-tc-offload off
  /usr/sbin/ethtool -K \$i rx off tx off
  /usr/sbin/ethtool -K \$i sg off gro off lro off tso off gso off
done
EOF
chmod +x /opt/setinterfaces.sh
/opt/setinterfaces.sh
#if [ $? != 0 ] ; then
#   clear
#   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
#   echo "There was an error..."
#   echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
#   sleep 5
#   exit
#   else
#   clear
#   echo "Interface settings set!"
#   fi

echo "Creating Suricata as a service and enabling it to run after reboot"
echo "[Unit]
Description=Suricata Intrusion Detection Service
After=syslog.target network-online.target

[Service]
Type=forking
Environment=UNIXCMD_SOCKET=\"/var/run/suricata/suricata-command.socket\"
ExecStartPre=/bin/rm -f /var/run/suricata.pid
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --af-packet -vvv -D
ExecStop=/bin/sh -c \"/usr/bin/suricatasc -c shutdown \${UNIXCMD_SOCKET}\"
ExecStopPost=/bin/rm -rf /var/run/suricata

[Install]
WantedBy=multi-user.target" > /usr/lib/systemd/system/suricata.service
systemctl daemon-reload
systemctl enable suricata
echo "Test running Suricata"
systemctl start suricata
echo "Installation of Suricata is complete. Observe the /var/log/suricata/suricata.log file to view any startup errors."
