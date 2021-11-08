#!/bin/bash
DIRTOSCAN="/var/www /home /opt /usr/bin /etc /usr/sbin";
TODAY=$(date +%u);

if [ "$TODAY" == "6" ];then
 nice -n5 clamscan -ri / --exclude-dir=/sys/;

else
 for S in ${DIRTOSCAN}; do
  DIRSIZE=$(du -sh "$S" 2>/dev/null | cut -f1);

  clamscan -ri "$S";
done
fi
