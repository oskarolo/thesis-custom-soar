#!/bin/bash

# --- CONFIGURATION ---
UBUNTU_HOST="INSERT MACHINE IP"
SSH_USER="INSERT SSH USERNAME"
SSH_KEY_PATH="INSERT SSH KEY PATH"
LOG_FILE="/tmp/auto_block.log"
# --- END CONFIGURATION ---

# Splunk passes the IP as the first argument
IP_TO_BLOCK=$1

echo "---" >> $LOG_FILE
echo "$(date): Splunk alert triggered. Attempting to block IP: $IP_TO_BLOCK" >> $LOG_FILE

# Basic validation to prevent errors
if ! [[ $IP_TO_BLOCK =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo "$(date): ERROR: '$IP_TO_BLOCK' is not a valid IP address. Exiting." >> $LOG_FILE
  exit 1
fi

# The command to run on the remote server, "insert 1" puts this rule at the TOP of the firewall chain
# COMMAND 1: Block future connections with UFW
BLOCK_COMMAND="sudo /usr/sbin/ufw insert 1 deny out from any to $IP_TO_BLOCK"
echo "$(date): Executing: $BLOCK_COMMAND on $UBUNTU_HOST" >> $LOG_FILE

# Execute the block over SSH, with a 10-second timeout
# We redirect all output (stdout and stderr) to the log file for debugging
ssh -i $SSH_KEY_PATH -o ConnectTimeout=10 $SSH_USER@$UBUNTU_HOST $BLOCK_COMMAND >> $LOG_FILE 2>&1

# COMMAND 2: Kill current, established connections with conntrack
KILL_COMMAND="sudo /usr/sbin/conntrack -D -d $IP_TO_BLOCK"
echo "$(date): Executing: $KILL_COMMAND on $UBUNTU_HOST" >> $LOG_FILE

# Execute the conntrack kill over SSH
ssh -i $SSH_KEY_PATH -o ConnectTimeout=10 $SSH_USER@$UBUNTU_HOST $KILL_COMMAND >> $LOG_FILE 2>&1

echo "$(date): Script finished." >> $LOG_FILE
