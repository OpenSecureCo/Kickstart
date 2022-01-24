#!/usr/bin/bash
# YARA active response
#------------------------- Set Memory Limit (KB)-------------------------#
ulimit -v 128000
#------------------------- Aadjust IFS to read files -------------------------#
SAVEIFS=$IFS
IFS=$(echo -en "\n\b")
# Static active response parameters
LOCAL=`dirname $0`
#------------------------- Folders to scan. Modify array as required -------------------------#
folders_to_scan=( "/home/" "/tmp" "/root/" "/opt/" "/etc/" "/usr/bin/" "/usr/sbin/" "/boot/" "/dev/shm/")

#------------------------- Files extensions to scan. Modify array as required -------------------------#
file_extenstions_to_scan=( ".sh" ".bin" ".js" )
#------------------------- Active Response Log File -------------------------#

LOG_FILE="/var/ossec/logs/active-responses.log"

#------------------------- Main workflow --------------------------#

# Execute YARA scan on target folders and subfolders
for f in "${folders_to_scan[@]}"
do
  for f1 in $( find $f -type f); do
  yara_output=$(/opt/yara-4.1.3/yara -C -w -r -f -m /opt/yara-4.1.3/signature-base/yara_base_ruleset_compiled.yar "$f1")
  if [[ $yara_output != "" ]]
  then
      # Iterate every detected rule and append it to the LOG_FILE
      while read -r line; do
          echo "wazuh-yara: info: $line" >> ${LOG_FILE}
      done <<< "$yara_output"
  fi
  done
done
# Execute YARA scan on target file extensions, all locations in HD
for e in "${file_extenstions_to_scan[@]}"
do
  for f1 in $( find / -type f | grep -F $e ); do
    yara_output=$(/opt/yara-4.1.3/yara -C -w -r -f -m /opt/yara-4.1.3/signature-base/yara_base_ruleset_compiled.yar "$f1")
    if [[ $yara_output != "" ]]
    then
    # Iterate every detected rule and append it to the LOG_FILE
      while read -r line; do
        echo "wazuh-yara: info: $line" >> ${LOG_FILE}
      done <<< "$yara_output"
    fi
  done
done
IFS=$SAVEIFS
exit 1;
