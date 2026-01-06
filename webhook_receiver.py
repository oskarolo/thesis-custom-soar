#!/usr/bin/env python3

import subprocess
import logging
import time
import requests
from flask import Flask, request, abort

# --- CONFIGURATION ---
# Full, absolute path to the bash script Splunk should run
BLOCK_SCRIPT_PATH = "scripts/block_external_ip.sh"
LOG_FILE = "/tmp/webhook_receiver.log"
# --- END CONFIGURATION ---

# --- IRIS CONFIGURATION ---
IRIS_API_KEY = "INSERT YOUR API KEY HERE"
IRIS_URL = "https://127.0.0.1"
# --- END CONFIGURATION ---

# Set up logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

app = Flask(__name__)

# Function creating a case in IRIS
def create_iris_case(alert_data):
    logging.info("Attempting to create IRIS case...")

    # Get data from the Splunk alert
    # We use .get() method to avoid errors if a field is missing
    ip_to_block = alert_data.get('dest_ip', 'N/A')
    signatures = alert_data.get('signatures', 'N/A')
    src_ip = alert_data.get('src_ip', 'N/A')

    case_name = f"Automated Alert: C2 Beacon Detected from {src_ip} to {ip_to_block}"
    case_description = f"""
Automated Case Creation from Splunk

Alert: Outbound Suricata Alert
Source IP: {src_ip}
Destination IP: {ip_to_block}
Signatures: {signatures}

Action Taken: Automated block initiated via UFW and conntrack.
"""

    headers = {
        "Authorization": f"Bearer {IRIS_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "case_soc_id": f"splunk_c2_{int(time.time())}", # A unique ID for the alert
        "case_customer": 1,                             # Default customer ID
        "case_name": case_name,
        "case_description": case_description
    }

    try:
        response = requests.post(f"{IRIS_URL}/manage/cases/add", headers=headers, json=payload, verify=False)

        if response.status_code == 200 or response.status_code == 201:
            logging.info(f"Successfully created IRIS case {case_id} for IP {ip_to_block}")
        else:
            logging.error(f"Failed to create IRIS case. Status: {response.status_code}, Response: {response.text}")

    except Exception as e:
        logging.error(f"Error connecting to IRIS API: {e}")

@app.route('/blockip', methods=['POST'])
def block_ip_webhook():
    if not request.json:
        logging.warning("Received request without JSON data.")
        abort(400, "Bad Request: No JSON data received.")

    try:
        # Splunk sends the data inside a 'result' object
        alert_result = request.json.get('result', {})
        ip_to_block = alert_result.get('dest_ip')

        # This check is critical to prevent the script from crashing
        if not ip_to_block:
            logging.error("Failed to parse JSON. 'result.dest_ip' not found.")
            logging.debug(f"Received JSON: {request.data}")
            abort(400, "Bad Request: JSON missing 'result.dest_ip' field.")

        logging.info(f"Received block request for IP: {ip_to_block}")

        # Calling bash script to block the IPv4 remotely
        result = subprocess.run(
            [BLOCK_SCRIPT_PATH, ip_to_block],
            capture_output=True,
            text=True,
            timeout=15
        )

        # Creating a new IRIS case
        create_iris_case(alert_result)

        if result.returncode == 0:
            logging.info(f"Successfully ran block script for {ip_to_block}.")
            logging.debug(f"Script stdout: {result.stdout}")
            return "Block command executed and case created.", 200
        else:
            logging.error(f"Failed to run block script for {ip_to_block}.")
            logging.error(f"Script stderr: {result.stderr}")
            return "Script execution FAILED, but case was still created.", 500

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return "Internal server error.", 500

if __name__ == '__main__':
    # Listens on port 5001, but ONLY on localhost (127.0.0.1)
    # This is secure and means only Splunk (on the same machine) can talk to it.
    app.run(host='127.0.0.1', port=5001)
