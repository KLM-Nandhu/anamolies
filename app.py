import streamlit as st
import pandas as pd
import json
import sys
from openai import OpenAI
from datetime import datetime, timedelta

# Initialize OpenAI client with Streamlit secrets
client = OpenAI(api_key=st.secrets["openai_api_key"])

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
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    except Exception as e:
        st.error(f"Error generating report: {str(e)}")
        return "Unable to generate report due to an error with the OpenAI API."

def llm_call(prompt, model="gpt-4o-mini"):
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        st.error(f"Error in LLM call: {str(e)}")
        return None

def determine_relevant_alert_types(question):
    prompt = f"""Given the following question: '{question}', which of these alert types are most relevant? List up to 3 most relevant types in order of relevance.

Alert types:
{', '.join(ALL_ALERTS)}

Respond with just the names of the relevant alert types, separated by commas."""

    return llm_call(prompt)

def extract_relevant_info(question, alert_type, events):
    event_sample = json.dumps(events[:5], indent=2)  # Sample of up to 5 events
    prompt = f"""Question: {question}
Alert Type: {alert_type}
Number of events: {len(events)}

Sample events:
{event_sample}

Based on this information, extract and summarize the key details that are relevant to answering the question. Focus on the most important information."""

    return llm_call(prompt)

def generate_initial_answer(question, alert_types, relevant_info):
    prompt = f"""Question: {question}

Relevant Alert Types: {alert_types}

Relevant Information:
{relevant_info}

Based on this information, provide a comprehensive answer to the question. If the alert types don't seem directly relevant, explain why and provide the best possible answer based on the available information."""

    return llm_call(prompt)

def refine_answer(question, initial_answer):
    prompt = f"""Original Question: {question}

Initial Answer:
{initial_answer}

Please refine and improve this answer. Ensure it's clear, concise, and directly addresses the question. Add any additional insights or context that might be helpful. If there are any potential security implications or recommendations, include them."""

    return llm_call(prompt)

def process_question(question, alerts):
    # Step 1: Determine relevant alert types
    relevant_alert_types = determine_relevant_alert_types(question)
    if not relevant_alert_types:
        return "Unable to process the question due to an error."

    # Step 2: Extract relevant information for each alert type
    relevant_info = ""
    for alert_type in relevant_alert_types.split(', '):
        events = alerts.get(alert_type.strip(), [])
        info = extract_relevant_info(question, alert_type, events)
        if info:
            relevant_info += f"\n\nAlert Type: {alert_type}\n{info}"

    # Step 3: Generate initial answer
    initial_answer = generate_initial_answer(question, relevant_alert_types, relevant_info)
    if not initial_answer:
        return "Unable to generate an answer due to an error."

    # Step 4: Refine the answer
    final_answer = refine_answer(question, initial_answer)
    if not final_answer:
        return initial_answer  # Fallback to initial answer if refinement fails

    return f"Relevant Alert Types: {relevant_alert_types}\n\nAnswer: {final_answer}"

def main():
    st.set_page_config(page_title="Comprehensive Log Analysis", layout="wide")

    st.title("Comprehensive Log Analysis System")

    # Add debugging information
    st.sidebar.write("Debug Information:")
    st.sidebar.write(f"Streamlit version: {st.__version__}")
    st.sidebar.write(f"Python version: {sys.version}")
    
    # Safely try to get OpenAI version
    try:
        openai_version = openai.__version__
    except AttributeError:
        openai_version = "Version information not available"
    st.sidebar.write(f"OpenAI library version: {openai_version}")

    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
    if uploaded_file is not None:
        json_data = csv_to_json(uploaded_file)
        
        st.download_button(
            label="Download JSON",
            data=json_data,
            file_name="converted_data.json",
            mime="application/json"
        )

        if st.button("Analyze Logs"):
            with st.spinner("Processing..."):
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

        # Question Answering Section
        st.subheader("Ask a Question")
        question = st.text_input("Enter your question about the log data:")
        if st.button("Get Answer"):
            if 'alerts' in locals():
                with st.spinner("Processing question..."):
                    answer = process_question(question, alerts)
                    st.markdown(answer)
            else:
                st.warning("Please analyze the logs first before asking questions.")

if __name__ == "__main__":
    main()
