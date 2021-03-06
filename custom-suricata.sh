#!/bin/bash

LOCAL=`dirname $0`;
cd $LOCAL
cd ../

PWD=`pwd`

read -r INPUT_JSON
SRCIP=$(echo $INPUT_JSON | jq -r .parameters.alert.data.src_ip)
COMMAND=$(echo $INPUT_JSON | jq -r .command)
ALERT=$(echo $INPUT_JSON | jq -r .parameters.alert.data.alert.signature)
LOG_FILE="${PWD}/../logs/active-responses.log"

#------------------------ Analyze command -------------------------#
# Blocking Source IP
if [ ${COMMAND} = "add" ]
then
/sbin/iptables -I INPUT -s ${SRCIP} -j DROP
/sbin/iptables -I FORWARD -s ${SRCIP} -j DROP
echo "`date` /var/ossec/$0 Source IP $SRCIP Added to Blacklist due to alert $ALERT" >> ${LOG_FILE}
#echo "$INPUT_JSON" > /tmp/alerts.log
else
/sbin/iptables -D INPUT -s ${SRCIP} -j DROP
/sbin/iptables -D FORWARD -s ${SRCIP} -j DROP
echo "`date` /var/ossec/$0 Source IP $SRCIP Removed from Blacklist due to alert $ALERT" >> ${LOG_FILE}
#echo "$INPUT_JSON" > /tmp/alerts.log
fi

exit 0;
