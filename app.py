import streamlit as st
import pandas as pd
import json
import os
from openai import OpenAI
from dotenv import load_dotenv
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Define alert types
AUDIT_LOGS_ALERTS = [
    "Forwarding Email to another account",
    "Suspicious User Password Change",
    "User accounts added or Deleted",
    "Audit Logs Disabled",
    "MFA disabled",
    "Record Type Based alerts",
    "Device No Longer Compliant",
    "Suspicious Inbox Manipulation Rule",
    "Insight and report events",
    "EOP Phishing and Malware events",
    "Member added to Group",
    "Member added to Role"
]

SIGN_IN_LOGS_ALERTS = [
    "Unusual amount of login failures",
    "Possible Brute Force Lockout Evasion",
    "Impossible Travel Alerts",
    "Sign ins with Blacklisted IPs",
    "Sign ins with anonymous IPs",
    "Foreign country alerts",
    "Unusual logins"
]

ALL_ALERTS = AUDIT_LOGS_ALERTS + SIGN_IN_LOGS_ALERTS

def csv_to_json(csv_file):
    df = pd.read_csv(csv_file)
    return df.to_json(orient='records')

def process_alerts(json_data):
    data = json.loads(json_data)
    alerts = {alert: [] for alert in ALL_ALERTS}

    for event in data:
        # Audit Logs Alerts
        if event['RecordType'] == 1 and event['Operation'] == 'Set-Mailbox' and 'ForwardingSmtpAddress' in event.get('Parameters', ''):
            alerts["Forwarding Email to another account"].append(event)
        
        if event['RecordType'] == 8 and event['Operation'] == 'Change User Password' and event['UserID'] != event['ObjectId']:
            alerts["Suspicious User Password Change"].append(event)
        
        if event['RecordType'] == 8 and event['Operation'] in ['Add User', 'Delete User']:
            alerts["User accounts added or Deleted"].append(event)
        
        if event['RecordType'] == 1 and event['Operation'] == 'Set-AdminAuditLogConfig' and 'UnifiedAuditLogIngestionEnabled' in event.get('Parameters', '') and 'False' in event.get('Parameters', ''):
            alerts["Audit Logs Disabled"].append(event)
        
        if event['RecordType'] == 8 and event['Operation'] == 'DisableStrongAuthentication':
            alerts["MFA disabled"].append(event)
        
        if event['RecordType'] in [61, 78, 90, 87, 106, 113]:
            alerts["Record Type Based alerts"].append(event)
        
        if event['RecordType'] == 8 and event['Operation'] == 'Device no longer compliant':
            alerts["Device No Longer Compliant"].append(event)
        
        if event['Operation'] == 'New-InboxRule':
            alerts["Suspicious Inbox Manipulation Rule"].append(event)
        
        if event['RecordType'] in [42, 40, 98]:
            alerts["Insight and report events"].append(event)
        
        if event['RecordType'] == 28 and event.get('LatestDeliveryLocation') == 'Inbox':
            alerts["EOP Phishing and Malware events"].append(event)
        
        if event['RecordType'] == 8 and event['Operation'] == 'Member Added to Group':
            alerts["Member added to Group"].append(event)
        
        if event['RecordType'] == 8 and event['Operation'] == 'Member Added to Role':
            alerts["Member added to Role"].append(event)

        # Sign In Logs Alerts
        if event['RecordType'] == 15 and event['Operation'] == 'UserLoginFailed':
            alerts["Unusual amount of login failures"].append(event)
            alerts["Possible Brute Force Lockout Evasion"].append(event)
        
        if event['RecordType'] == 15 and event['Operation'] == 'UserLoggedIn':
            alerts["Impossible Travel Alerts"].append(event)
            alerts["Sign ins with Blacklisted IPs"].append(event)
            alerts["Sign ins with anonymous IPs"].append(event)
            alerts["Foreign country alerts"].append(event)
            alerts["Unusual logins"].append(event)

    return alerts

def generate_report(alerts):
    prompt = f"Generate a comprehensive security report based on the following alert data:\n\n"
    for alert_type, events in alerts.items():
        prompt += f"{alert_type}: {len(events)} events\n"
    prompt += "\nProvide a summary of the alerts, including the most critical issues, potential security risks, and recommended actions. Please format the report in Markdown."

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

def main():
    st.set_page_config(page_title="Comprehensive Log Analysis", layout="wide")

    st.title("🔍 Comprehensive Log Analysis System")

    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
    if uploaded_file is not None:
        json_data = csv_to_json(uploaded_file)
        
        st.download_button(
            label="📥 Download JSON",
            data=json_data,
            file_name="converted_data.json",
            mime="application/json"
        )

        if st.button("🔍 Analyze Logs"):
            with st.spinner("Processing..."):
                alerts = process_alerts(json_data)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("📊 Alert Summary")
                    for alert_type, events in alerts.items():
                        st.metric(alert_type, len(events))
                
                with col2:
                    st.subheader("📝 Detailed Report")
                    report = generate_report(alerts)
                    st.markdown(report)

                st.subheader("🔍 Detailed Alerts")
                for alert_type, events in alerts.items():
                    if events:
                        with st.expander(f"{alert_type} ({len(events)} events)"):
                            st.json(events)

if __name__ == "__main__":
    main()
