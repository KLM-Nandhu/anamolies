import streamlit as st
import pandas as pd
import json
import openai
import io

# Load OpenAI API key from Streamlit secrets
openai.api_key = st.secrets["openai_api_key"]

# Define all alert types
ALL_ALERTS = [
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
    "Member added to Role",
    "Unusual amount of login failures",
    "Possible Brute Force Lockout Evasion",
    "Impossible Travel Alerts",
    "Sign ins with Blacklisted IPs",
    "Sign ins with anonymous IPs",
    "Foreign country alerts",
    "Unusual logins"
]

# Function to call GPT-4 with a specific prompt
def create_chat_completion(prompt, model="gpt-4o-mini"):
    try:
        response = openai.ChatCompletion.create(
            model=model,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        st.error(f"Error in LLM call: {str(e)}")
        return None

# Function to convert CSV to JSON
def convert_csv_to_json(df):
    return df.to_json(orient='records')

# Function to categorize the question using LLM
def categorize_question(question):
    prompt = f"""Given the following question about log data: '{question}'
    Please categorize this question into one of the following alert types:
    {', '.join(ALL_ALERTS)}
    
    Respond with just the name of the most relevant alert type. If the question doesn't match any specific alert type, respond with "General Question".
    """
    return create_chat_completion(prompt)

# Function to filter the dataset based on the alert type
def filter_relevant_rows(alert_type, df):
    def safe_column_check(column):
        return column in df.columns

    # Define filtering conditions for each alert type
    filter_conditions = {
        "Forwarding Email to another account": (safe_column_check('RecordType') & (df['RecordType'] == 1) & safe_column_check('Operation') & (df['Operation'] == 'Set-Mailbox') & safe_column_check('Parameters') & (df['Parameters'].str.contains('ForwardingSmtpAddress', na=False))),
        "Suspicious User Password Change": (safe_column_check('RecordType') & (df['RecordType'] == 8) & safe_column_check('Operation') & (df['Operation'] == 'Change User Password') & safe_column_check('UserID') & safe_column_check('ObjectID') & (df['UserID'] != df['ObjectID'])),
        "User accounts added or Deleted": (safe_column_check('RecordType') & (df['RecordType'] == 8) & safe_column_check('Operation') & (df['Operation'].isin(['Add User', 'Delete User']))),
        "Audit Logs Disabled": (safe_column_check('RecordType') & (df['RecordType'] == 1) & safe_column_check('Operation') & (df['Operation'] == 'Set-AdminAuditLogConfig') & safe_column_check('Parameters') & (df['Parameters'].str.contains('"Name": "UnifiedAuditLogIngestionEnabled", "Value": "False"', na=False))),
        "MFA disabled": (safe_column_check('RecordType') & (df['RecordType'] == 8) & safe_column_check('Operation') & (df['Operation'] == 'DisableStrongAuthentication')),
        "Record Type Based alerts": (safe_column_check('RecordType') & df['RecordType'].isin([61, 78, 90, 87, 106, 113])),
        "Device No Longer Compliant": (safe_column_check('RecordType') & (df['RecordType'] == 8) & safe_column_check('Operation') & (df['Operation'] == 'Device no longer compliant')),
        "Suspicious Inbox Manipulation Rule": (safe_column_check('Operation') & (df['Operation'] == 'New-InboxRule')),
        "Insight and report events": (safe_column_check('RecordType') & df['RecordType'].isin([42, 40, 98])),
        "EOP Phishing and Malware events": (safe_column_check('RecordType') & (df['RecordType'] == 28) & safe_column_check('LatestDeliveryLocation') & (df['LatestDeliveryLocation'] == 'Inbox')),
        "Member added to Group": (safe_column_check('RecordType') & (df['RecordType'] == 8) & safe_column_check('Operation') & (df['Operation'] == 'Member Added to Group')),
        "Member added to Role": (safe_column_check('RecordType') & (df['RecordType'] == 8) & safe_column_check('Operation') & (df['Operation'] == 'Member Added to Role')),
        "Unusual amount of login failures": (safe_column_check('RecordType') & (df['RecordType'] == 15) & safe_column_check('Operation') & (df['Operation'] == 'UserLoginFailed') & safe_column_check('Failures') & (df['Failures'].gt(10))),
        "Possible Brute Force Lockout Evasion": (safe_column_check('RecordType') & (df['RecordType'] == 15) & safe_column_check('Operation') & (df['Operation'] == 'UserLoginFailed')),
        "Impossible Travel Alerts": (safe_column_check('RecordType') & (df['RecordType'] == 15) & safe_column_check('Operation') & (df['Operation'] == 'UserLoggedIn')),
        "Sign ins with Blacklisted IPs": (safe_column_check('RecordType') & (df['RecordType'] == 15) & safe_column_check('Operation') & (df['Operation'] == 'UserLoggedIn') & safe_column_check('IP') & (df['IP'].str.contains('blacklist', na=False))),
        "Sign ins with anonymous IPs": (safe_column_check('RecordType') & (df['RecordType'] == 15) & safe_column_check('Operation') & (df['Operation'] == 'UserLoggedIn') & safe_column_check('IP') & (df['IP'].str.contains('vpn', na=False))),
        "Foreign country alerts": (safe_column_check('RecordType') & (df['RecordType'] == 15) & safe_column_check('Operation') & (df['Operation'].isin(['UserLoginFailed', 'UserLoggedIn'])) & safe_column_check('Country') & (df['Country'] != 'US')),
        "Unusual logins": (safe_column_check('RecordType') & (df['RecordType'] == 15) & safe_column_check('Operation') & (df['Operation'] == 'UserLoggedIn') & safe_column_check('NewIPFlag') & (df['NewIPFlag'] == True))
    }

    if alert_type in filter_conditions:
        return df[filter_conditions[alert_type]]
    else:
        return df  # Return full dataset if no specific filter applies

# Main Streamlit app
def main():
    st.set_page_config(page_title="CSV to JSON & Log Analyzer", layout="wide")

    st.title("CSV to JSON Converter & Log Analyzer")

    # File upload for CSV
    uploaded_file = st.file_uploader("Upload a CSV file", type=["csv"])

    if uploaded_file is not None:
        try:
            # Convert CSV to DataFrame
            df = pd.read_csv(uploaded_file)
            st.write("Uploaded CSV data:")
            st.dataframe(df)

            # Convert CSV to JSON
            json_data = convert_csv_to_json(df)

            # Download button for JSON
            json_bytes = io.BytesIO(json_data.encode())
            st.download_button(
                label="Download JSON",
                data=json_bytes,
                file_name="converted_data.json",
                mime="application/json"
            )

            # Asking questions based on logs
            st.subheader("Ask a Question")
            question = st.text_input("Enter your question:")

            if st.button("Submit"):
                if question.strip() != "":
                    # Categorize the question using LLM
                    with st.spinner("Categorizing question..."):
                        alert_type = categorize_question(question)

                    if alert_type == "General Question":
                        st.info("This appears to be a general question. Analyzing based on all log data.")
                        filtered_data = df
                    else:
                        st.info(f"Question categorized as: {alert_type}")
                        filtered_data = filter_relevant_rows(alert_type, df)

                    if filtered_data.empty:
                        st.warning("No relevant data found based on the question category.")
                    else:
                        # Process filtered data with GPT-4
                        prompt = f"""
                        Based on the following log data related to {alert_type}:
                        {json.dumps(filtered_data.to_dict(orient="records"), indent=2)}

                        Answer the following question: '{question}'
                        Provide a detailed answer with any relevant insights or recommendations.
                        """

                        with st.spinner("Processing answer..."):
                            answer = create_chat_completion(prompt)
                            if answer:
                                st.subheader("Analysis Result")
                                st.markdown(answer)
                            else:
                                st.error("Unable to generate an answer.")
                else:
                    st.warning("Please enter a valid question.")

        except Exception as e:
            st.error(f"Error processing the CSV file: {str(e)}")
            st.write("Please ensure your CSV file has the correct format and column names.")

    else:
        st.warning("Please upload a CSV file to begin analysis.")

if __name__ == "__main__":
    main()
