import streamlit as st
import pandas as pd
import json
import sys
from datetime import datetime, timedelta

# Try to import OpenAI, handling different versions
try:
    from openai import OpenAI
    client = OpenAI(api_key=st.secrets["openai_api_key"])
    def create_chat_completion(**kwargs):
        return client.chat.completions.create(**kwargs)
except ImportError:
    import openai
    openai.api_key = st.secrets["openai_api_key"]
    def create_chat_completion(**kwargs):
        return openai.ChatCompletion.create(**kwargs)

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

def process_alerts(json_data):
    try:
        data = json.loads(json_data)
    except json.JSONDecodeError:
        st.error("Error: Invalid JSON data. Please check the uploaded file.")
        return {}

    alerts = {alert: [] for alert in ALL_ALERTS}

    for event in data:
        try:
            record_type = event.get('RecordType')
            operation = event.get('Operation')
            parameters = event.get('Parameters', '')

            # Audit Logs Alerts
            if record_type == 1 and operation == 'Set-Mailbox' and 'ForwardingSmtpAddress' in parameters:
                alerts["Forwarding Email to another account"].append(event)
            
            if record_type == 8 and operation == 'Change User Password' and event.get('UserID') != event.get('ObjectId'):
                alerts["Suspicious User Password Change"].append(event)
            
            if record_type == 8 and operation in ['Add User', 'Delete User']:
                alerts["User accounts added or Deleted"].append(event)
            
            if record_type == 1 and operation == 'Set-AdminAuditLogConfig' and 'UnifiedAuditLogIngestionEnabled' in parameters and 'False' in parameters:
                alerts["Audit Logs Disabled"].append(event)
            
            if record_type == 8 and operation == 'DisableStrongAuthentication':
                alerts["MFA disabled"].append(event)
            
            if record_type in [61, 78, 90, 87, 106, 113]:
                alerts["Record Type Based alerts"].append(event)
            
            if record_type == 8 and operation == 'Device no longer compliant':
                alerts["Device No Longer Compliant"].append(event)
            
            if operation == 'New-InboxRule':
                alerts["Suspicious Inbox Manipulation Rule"].append(event)
            
            if record_type in [42, 40, 98]:
                alerts["Insight and report events"].append(event)
            
            if record_type == 28 and event.get('LatestDeliveryLocation') == 'Inbox':
                alerts["EOP Phishing and Malware events"].append(event)
            
            if record_type == 8 and operation == 'Member Added to Group':
                alerts["Member added to Group"].append(event)
            
            if record_type == 8 and operation == 'Member Added to Role':
                alerts["Member added to Role"].append(event)

            # Sign In Logs Alerts
            if record_type == 15 and operation == 'UserLoginFailed':
                alerts["Unusual amount of login failures"].append(event)
                alerts["Possible Brute Force Lockout Evasion"].append(event)
            
            if record_type == 15 and operation == 'UserLoggedIn':
                alerts["Impossible Travel Alerts"].append(event)
                alerts["Sign ins with Blacklisted IPs"].append(event)
                alerts["Sign ins with anonymous IPs"].append(event)
                alerts["Foreign country alerts"].append(event)
                alerts["Unusual logins"].append(event)

        except Exception as e:
            st.warning(f"Error processing event: {str(e)}")
            continue

    return alerts

def generate_report(alerts):
    prompt = f"Generate a comprehensive security report based on the following alert data:\n\n"
    for alert_type, events in alerts.items():
        prompt += f"{alert_type}: {len(events)} events\n"
    prompt += "\nProvide a summary of the alerts, including the most critical issues, potential security risks, and recommended actions. Please format the report in Markdown."

    try:
        response = create_chat_completion(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    except Exception as e:
        st.error(f"Error generating report: {str(e)}")
        return "Unable to generate report due to an error with the OpenAI API."

def llm_call(prompt, model="gpt-4o-mini"):
    try:
        response = create_chat_completion(
            model=model,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        st.error(f"Error in LLM call: {str(e)}")
        return None

def process_question(question, json_data):
    prompt = f"""Given the following question about log data: '{question}'
    
The log data is in JSON format. Here's a sample of the data (first 5 entries):
{json.dumps(json.loads(json_data)[:5], indent=2)}

Please analyze this data and provide an answer to the question. If the question cannot be answered based on the given data, please state that clearly. Format your response in a clear and concise manner."""

    answer = llm_call(prompt)
    if not answer:
        return "Unable to process the question due to an error."
    return answer

def main():
    st.set_page_config(page_title="Comprehensive Log Analysis", layout="wide")

    st.title("CSV Analysis")
    
    # Safely try to get OpenAI version
    try:
        openai_version = openai.__version__
    except:
        openai_version = "Version information not available"
    st.sidebar.write(f"OpenAI library version: {openai_version}")

    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
    if uploaded_file is not None:
        # CSV Preview
        df = pd.read_csv(uploaded_file)
        st.subheader("CSV Preview")
        st.dataframe(df.head())

        json_data = df.to_json(orient='records')
        
        st.download_button(
            label="Download JSON",
            data=json_data,
            file_name="converted_data.json",
            mime="application/json"
        )

        # Question Answering Section
        st.subheader("Ask a Question")
        question = st.text_input("Enter your question about the log data:")
        if st.button("Get Answer"):
            with st.spinner("Processing question..."):
                answer = process_question(question, json_data)
                st.markdown(answer)

        # Log Analysis Section
        if st.button("Perform Detailed Log Analysis"):
            with st.spinner("Analyzing logs..."):
                alerts = process_alerts(json_data)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("Alert Summary")
                    for alert_type, events in alerts.items():
                        st.metric(alert_type, len(events))
                
                with col2:
                    st.subheader("Detailed Report")
                    report = generate_report(alerts)
                    st.markdown(report)

                st.subheader("Detailed Alerts")
                for alert_type, events in alerts.items():
                    if events:
                        with st.expander(f"{alert_type} ({len(events)} events)"):
                            st.json(events)

    else:
        st.warning("Please upload a CSV file to begin analysis.")

if __name__ == "__main__":
    main()
