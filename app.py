import streamlit as st
import pandas as pd
import json
import openai
import io

# Load OpenAI API key from Streamlit secrets
openai.api_key = st.secrets["openai_api_key"]

# LLM call function for processing audit and sign-in logs
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

# Filter the dataset to only include relevant rows based on pre-defined rules
def filter_relevant_rows(log_type, df):
    if log_type == "Audit Logs Alerts":
        # Apply the conditions for audit logs
        filtered_data = df[
            ((df['RecordType'] == 1) & (df['Operation'] == 'Set-Mailbox') & (df['Parameters'].str.contains('ForwardingSmtpAddress', na=False))) |
            ((df['RecordType'] == 8) & (df['Operation'] == 'Change User Password') & (df['UserID'] != df['ObjectID'])) |
            ((df['RecordType'] == 8) & (df['Operation'].isin(['Add User', 'Delete User']))) |
            ((df['RecordType'] == 1) & (df['Operation'] == 'Set-AdminAuditLogConfig') & (df['Parameters'].str.contains('"Name": "UnifiedAuditLogIngestionEnabled", "Value": "False"', na=False))) |
            ((df['RecordType'] == 8) & (df['Operation'] == 'DisableStrongAuthentication')) |
            (df['RecordType'].isin([61, 78, 90, 87, 106, 113])) |
            ((df['RecordType'] == 8) & (df['Operation'] == 'Device no longer compliant')) |
            (df['Operation'] == 'New-InboxRule') |
            (df['RecordType'].isin([42, 40, 98])) |
            ((df['RecordType'] == 28) & (df['LatestDeliveryLocation'] == 'Inbox')) |
            ((df['RecordType'] == 8) & (df['Operation'] == 'Member Added to Group')) |
            ((df['RecordType'] == 8) & (df['Operation'] == 'Member Added to Role'))
        ]
    elif log_type == "Sign In Logs Alerts":
        # Apply the conditions for sign-in logs
        filtered_data = df[
            ((df['RecordType'] == 15) & (df['Operation'] == 'UserLoginFailed') & (df['Failures'].gt(10))) |
            ((df['RecordType'] == 15) & (df['Operation'] == 'UserLoginFailed')) |
            ((df['RecordType'] == 15) & (df['Operation'] == 'UserLoggedIn')) |
            ((df['RecordType'] == 15) & (df['Operation'] == 'UserLoggedIn') & (df['IP'].str.contains('blacklist', na=False))) |
            ((df['RecordType'] == 15) & (df['Operation'] == 'UserLoggedIn') & (df['IP'].str.contains('vpn', na=False))) |
            ((df['RecordType'] == 15) & (df['Operation'].isin(['UserLoginFailed', 'UserLoggedIn'])) & (df['Country'] != 'US')) |
            ((df['RecordType'] == 15) & (df['Operation'] == 'UserLoggedIn') & (df['NewIPFlag'] == True))
        ]
    else:
        filtered_data = pd.DataFrame()  # Return empty DataFrame if no match
    
    return filtered_data

# Main Streamlit app
def main():
    st.set_page_config(page_title="CSV to JSON & Audit Log Analyzer", layout="wide")

    st.title("CSV to JSON Converter & Audit Log Analyzer")

    # File upload for CSV
    uploaded_file = st.file_uploader("Upload a CSV file", type=["csv"])

    if uploaded_file is not None:
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

        # Asking questions based on audit and sign-in logs
        st.subheader("Ask a Question (Audit or Sign-In Logs)")
        log_type = st.selectbox("Select Log Type", ["Audit Logs Alerts", "Sign In Logs Alerts"])
        question = st.text_input("Enter your question:")

        if st.button("Submit"):
            if question.strip() != "":
                # Filter relevant data based on log type and rules
                filtered_data = filter_relevant_rows(log_type, df)

                if filtered_data.empty:
                    st.warning("No relevant data found based on the rules.")
                else:
                    # Send filtered data (smaller chunks) to GPT-4o-mini
                    prompt = f"""
                    Based on the following log data:
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

if __name__ == "__main__":
    main()
