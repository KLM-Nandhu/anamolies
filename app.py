import streamlit as st
import pandas as pd
import json
import openai
import io

# Load OpenAI API key from Streamlit secrets
openai.api_key = st.secrets["openai_api_key"]

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

# Function to match the question with log types (Audit or Sign-In)
def determine_log_type(question):
    # Audit log keywords
    audit_keywords = ["forwarding email", "password change", "user accounts", 
                      "audit logs", "mfa", "device no longer compliant", 
                      "inbox rule", "insight", "phishing", "malware", 
                      "group", "role"]

    # Sign-in log keywords
    sign_in_keywords = ["login failures", "brute force", "impossible travel", 
                        "blacklisted ips", "anonymous ips", "foreign country", 
                        "unusual logins"]

    # Check for audit log keywords
    for keyword in audit_keywords:
        if keyword.lower() in question.lower():
            return "Audit Logs Alerts"

    # Check for sign-in log keywords
    for keyword in sign_in_keywords:
        if keyword.lower() in question.lower():
            return "Sign In Logs Alerts"

    # Fallback if no match found
    st.warning("Unable to determine log type from the question. Please ensure you're asking about an event that matches either Audit Logs or Sign-In Logs.")
    return None

# Function to filter the dataset based on the log type and the relevant rules
def filter_relevant_rows(log_type, df):
    def safe_column_check(column):
        return column in df.columns

    if log_type == "Audit Logs Alerts":
        # Apply the conditions for audit logs
        filtered_data = df[
            (safe_column_check('RecordType') & (df['RecordType'] == 1) & safe_column_check('Operation') & (df['Operation'] == 'Set-Mailbox') & safe_column_check('Parameters') & (df['Parameters'].str.contains('ForwardingSmtpAddress', na=False))) |
            (safe_column_check('RecordType') & (df['RecordType'] == 8) & safe_column_check('Operation') & (df['Operation'] == 'Change User Password') & safe_column_check('UserID') & safe_column_check('ObjectID') & (df['UserID'] != df['ObjectID'])) |
            (safe_column_check('RecordType') & (df['RecordType'] == 8) & safe_column_check('Operation') & (df['Operation'].isin(['Add User', 'Delete User']))) |
            (safe_column_check('RecordType') & (df['RecordType'] == 1) & safe_column_check('Operation') & (df['Operation'] == 'Set-AdminAuditLogConfig') & safe_column_check('Parameters') & (df['Parameters'].str.contains('"Name": "UnifiedAuditLogIngestionEnabled", "Value": "False"', na=False))) |
            (safe_column_check('RecordType') & (df['RecordType'] == 8) & safe_column_check('Operation') & (df['Operation'] == 'DisableStrongAuthentication')) |
            (safe_column_check('RecordType') & df['RecordType'].isin([61, 78, 90, 87, 106, 113])) |
            (safe_column_check('RecordType') & (df['RecordType'] == 8) & safe_column_check('Operation') & (df['Operation'] == 'Device no longer compliant')) |
            (safe_column_check('Operation') & (df['Operation'] == 'New-InboxRule')) |
            (safe_column_check('RecordType') & df['RecordType'].isin([42, 40, 98])) |
            (safe_column_check('RecordType') & (df['RecordType'] == 28) & safe_column_check('LatestDeliveryLocation') & (df['LatestDeliveryLocation'] == 'Inbox')) |
            (safe_column_check('RecordType') & (df['RecordType'] == 8) & safe_column_check('Operation') & (df['Operation'] == 'Member Added to Group')) |
            (safe_column_check('RecordType') & (df['RecordType'] == 8) & safe_column_check('Operation') & (df['Operation'] == 'Member Added to Role'))
        ]
    elif log_type == "Sign In Logs Alerts":
        # Apply the conditions for sign-in logs
        filtered_data = df[
            (safe_column_check('RecordType') & (df['RecordType'] == 15) & safe_column_check('Operation') & (df['Operation'] == 'UserLoginFailed') & safe_column_check('Failures') & (df['Failures'].gt(10))) |
            (safe_column_check('RecordType') & (df['RecordType'] == 15) & safe_column_check('Operation') & (df['Operation'] == 'UserLoginFailed')) |
            (safe_column_check('RecordType') & (df['RecordType'] == 15) & safe_column_check('Operation') & (df['Operation'] == 'UserLoggedIn')) |
            (safe_column_check('RecordType') & (df['RecordType'] == 15) & safe_column_check('Operation') & (df['Operation'] == 'UserLoggedIn') & safe_column_check('IP') & (df['IP'].str.contains('blacklist', na=False))) |
            (safe_column_check('RecordType') & (df['RecordType'] == 15) & safe_column_check('Operation') & (df['Operation'] == 'UserLoggedIn') & safe_column_check('IP') & (df['IP'].str.contains('vpn', na=False))) |
            (safe_column_check('RecordType') & (df['RecordType'] == 15) & safe_column_check('Operation') & (df['Operation'].isin(['UserLoginFailed', 'UserLoggedIn'])) & safe_column_check('Country') & (df['Country'] != 'US')) |
            (safe_column_check('RecordType') & (df['RecordType'] == 15) & safe_column_check('Operation') & (df['Operation'] == 'UserLoggedIn') & safe_column_check('NewIPFlag') & (df['NewIPFlag'] == True))
        ]
    else:
        filtered_data = pd.DataFrame()  # Return empty DataFrame if no match
    
    return filtered_data

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
                    # Determine the log type based on the question
                    log_type = determine_log_type(question)

                    if log_type is None:
                        st.warning("Unable to determine the log type. Please ask a relevant question about Audit Logs or Sign-In Logs.")
                    else:
                        # Filter relevant data based on the log type
                        filtered_data = filter_relevant_rows(log_type, df)

                        if filtered_data.empty:
                            st.warning("No relevant data found based on the rules.")
                        else:
                            # Process filtered data with GPT-4
                            prompt = f"""
                            Based on the following {log_type} log data:
                            {json.dumps(filtered_data.to_dict(orient="records"), indent=2)}

                            Answer the following question: '{question}'
                            """

                            with st.spinner("Processing..."):
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
