import datetime
from typing import Dict, List
import streamlit as st
import pandas as pd
from openai import OpenAI
import time

# Configuration
MAX_TOKENS = 150
RATE_LIMIT_SECONDS = 20
MAX_CONTEXT_TOKENS = 3000

# Set up OpenAI client
client = OpenAI(api_key=st.secrets["openai_api_key"])

class LogProcessor:
    def __init__(self):
        self.alerts = []
        self.login_failures = {}
        self.user_logins = {}

    def process_log(self, log: Dict):
        record_type = log.get('RecordType')
        operation = log.get('Operation')

        if record_type == 1:
            self._process_record_type_1(log)
        elif record_type == 8:
            self._process_record_type_8(log)
        elif record_type == 15:
            self._process_record_type_15(log)
        elif record_type in [61, 78, 90, 87, 106, 113]:
            self._process_special_record_types(log)
        elif record_type in [42, 40, 98]:
            self._process_insight_report_events(log)
        elif record_type == 28:
            self._process_eop_events(log)

    def _process_record_type_1(self, log: Dict):
        operation = log.get('Operation')
        if operation == 'Set-Mailbox' and 'ForwardingSmtpAddress' in log.get('Parameter', ''):
            self._add_alert("Email Forwarding Rule Detected", log)
        elif operation == 'Set-AdminAuditLogConfig':
            parameters = log.get('Parameter', {})
            if parameters.get('Name') == 'UnifiedAuditLogIngestionEnabled' and parameters.get('Value') == 'False':
                self._add_alert("Audit Logs Disabled", log)

    def _process_record_type_8(self, log: Dict):
        operation = log.get('Operation')
        if operation == 'Change User Password' and log.get('UserID') != log.get('ObjectID'):
            self._add_alert("Suspicious User Password Change", log)
        elif operation in ['Add User', 'Delete User']:
            self._add_alert(f"User Account {operation}d", log)
        elif operation == 'DisableStrongAuthentication':
            self._add_alert("MFA Disabled", log)
        elif operation == 'Device no longer compliant':
            self._add_alert("Device No Longer Compliant", log)
        elif operation == 'Member Added to Group':
            self._add_alert("Member Added to Group", log)
        elif operation == 'Member Added to Role':
            self._add_alert("Member Added to Role", log)

    def _process_record_type_15(self, log: Dict):
        operation = log.get('Operation')
        if operation == 'UserLoginFailed':
            self._check_login_failures(log)
        elif operation == 'UserLoggedIn':
            self._check_successful_login(log)

    def _process_special_record_types(self, log: Dict):
        self._add_alert(f"Special Record Type {log.get('RecordType')} Detected", log)

    def _process_insight_report_events(self, log: Dict):
        self._add_alert(f"Insight and Report Event (RecordType {log.get('RecordType')}) Detected", log)

    def _process_eop_events(self, log: Dict):
        if log.get('LatestDeliveryLocation') == 'Inbox':
            self._add_alert("EOP Phishing or Malware Event Detected in Inbox", log)

    def _check_login_failures(self, log: Dict):
        user_id = log.get('UserID')
        timestamp = log.get('CreationTime')
        if user_id not in self.login_failures:
            self.login_failures[user_id] = []
        self.login_failures[user_id].append(timestamp)
        
        recent_failures = [t for t in self.login_failures[user_id] if (datetime.datetime.now() - datetime.datetime.fromisoformat(t)).total_seconds() <= 600]
        if len(recent_failures) > 10:
            self._add_alert(f"Unusual amount of login failures for user {user_id}", log)
        
        if len(self.login_failures[user_id]) > 10:
            self._add_alert(f"Possible Brute Force Lockout Evasion for user {user_id}", log)

    def _check_successful_login(self, log: Dict):
        user_id = log.get('UserID')
        ip_address = log.get('ClientIP')
        location = log.get('Location')
        timestamp = log.get('CreationTime')

        if user_id not in self.user_logins:
            self.user_logins[user_id] = []
        self.user_logins[user_id].append((timestamp, ip_address, location))

        self._check_impossible_travel(user_id, log)
        self._check_ip_reputation(ip_address, log)
        self._check_foreign_login(location, log)
        self._check_unusual_login(user_id, ip_address, log)

    def _check_impossible_travel(self, user_id, log):
        if len(self.user_logins[user_id]) < 2:
            return
        
        prev_login = self.user_logins[user_id][-2]
        curr_login = self.user_logins[user_id][-1]
        
        time_diff = (datetime.datetime.fromisoformat(curr_login[0]) - datetime.datetime.fromisoformat(prev_login[0])).total_seconds() / 3600  # in hours
        distance = self._calculate_distance(prev_login[2], curr_login[2])  # You need to implement this method
        speed = distance / time_diff if time_diff > 0 else 0
        
        if speed > 200:  # 200 miles per hour threshold
            self._add_alert(f"Impossible Travel Detected for user {user_id}", log)

    def _check_ip_reputation(self, ip_address, log):
        # This is a placeholder. You should implement actual IP reputation checking.
        if self._is_ip_blacklisted(ip_address):
            self._add_alert(f"Login from blacklisted IP: {ip_address}", log)
        elif self._is_ip_anonymous(ip_address):
            self._add_alert(f"Login from anonymous IP (VPN/TOR): {ip_address}", log)

    def _check_foreign_login(self, location, log):
        if location != 'US':
            alert = f"Foreign country login detected: {location}"
            if log.get('Operation') == 'UserLoggedIn':
                alert = f"**{alert}**"  # Bold for successful logins
            self._add_alert(alert, log)

    def _check_unusual_login(self, user_id, ip_address, log):
        recent_logins = [login for login in self.user_logins[user_id] if (datetime.datetime.now() - datetime.datetime.fromisoformat(login[0])).days <= 7]
        if ip_address not in [login[1] for login in recent_logins[:-1]]:
            self._add_alert(f"Unusual login from new IP for user {user_id}", log)

    def _add_alert(self, alert_message, log):
        self.alerts.append((alert_message, log))

    def _is_ip_blacklisted(self, ip_address):
        # Placeholder method. Implement actual IP blacklist checking.
        return False

    def _is_ip_anonymous(self, ip_address):
        # Placeholder method. Implement actual anonymous IP checking.
        return False

    def _calculate_distance(self, location1, location2):
        # Placeholder method. Implement actual distance calculation.
        return 0

    def get_alerts(self) -> List[str]:
        return self.alerts

    def analyze_alerts_with_gpt(self):
        if not self.alerts:
            return "No alerts to analyze."

        alerts_text = "\n".join([f"{alert[0]} - {alert[1]}" for alert in self.alerts[:10]])  # Limit to 10 alerts for API efficiency
        
        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini", 
                messages=[
                    {"role": "system", "content": "You are a cybersecurity analyst tasked with analyzing security alerts from a Microsoft 365 environment. Provide insights and potential next steps based on the alerts."},
                    {"role": "user", "content": f"Analyze the following security alerts and provide insights:\n\n{alerts_text}"}
                ],
                max_tokens=MAX_TOKENS
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"Error in GPT analysis: {str(e)}"

def main():
    st.set_page_config(page_title="Log Analyzer", page_icon="🔒", layout="wide")
    
    st.title("Log Analyzer with GPT-4o-mini Insights")
    st.write("Upload your log file and get AI-powered insights!")

    uploaded_file = st.file_uploader("Choose a CSV log file", type="csv")
    
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            st.success("Log file loaded successfully!")
            
            processor = LogProcessor()
            
            with st.spinner("Processing logs..."):
                for _, row in df.iterrows():
                    processor.process_log(row.to_dict())
            
            alerts = processor.get_alerts()
            
            if alerts:
                st.subheader("Detected Alerts")
                for alert, log in alerts:
                    st.write(f"- {alert}")
                    with st.expander("View Log Details"):
                        st.json(log)
                
                with st.spinner("Generating AI insights..."):
                    insights = processor.analyze_alerts_with_gpt()
                
                st.subheader("AI Insights")
                st.write(insights)
            else:
                st.info("No alerts detected in the provided logs.")
        
        except Exception as e:
            st.error(f"An error occurred while processing the log file: {str(e)}")
    else:
        st.info("Please upload a CSV log file to begin analysis.")

if __name__ == "__main__":
    main()
