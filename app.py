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

# Prompt to process audit and sign-in events based on the predefined rules
def generate_prompt(log_type, chunk):
    if log_type == "Audit Logs Alerts":
        # Define the prompt based on the 12 Audit Logs Alerts
        prompt = f"""
        Based on the following log data:
        {json.dumps(chunk, indent=2)}

        Determine if any of the following Audit Logs Alerts apply:
        1. Forwarding Email to another account
        2. Suspicious User Password Change
        3. User accounts added or Deleted
        4. Audit Logs Disabled
        5. MFA disabled
        6. Record Type Based alerts
        7. Device No Longer Compliant
        8. Suspicious Inbox Manipulation Rule
        9. Insight and report events
        10. EOP Phishing and Malware events
        11. Member added to Group
        12. Member added to Role

        Provide detailed answers and explanations for the relevant events.
        """
    elif log_type == "Sign In Logs Alerts":
        # Define the prompt based on the 7 Sign In Logs Alerts
        prompt = f"""
        Based on the following log data:
        {json.dumps(chunk, indent=2)}

        Determine if any of the following Sign-In Logs Alerts apply:
        1. Unusual amount of login failures
        2. Possible Brute Force Lockout Evasion
        3. Impossible Travel Alerts
        4. Sign ins with Blacklisted IPs
        5. Sign ins with anonymous IPs
        6. Foreign country alerts
        7. Unusual logins

        Provide detailed answers and explanations for the relevant events.
        """
    return prompt

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
                # Split the data into chunks (to simulate different events processing)
                chunks = [df.iloc[i:i+500].to_dict(orient="records") for i in range(0, len(df), 500)]

                final_answer = ""
                for chunk in chunks:
                    prompt = generate_prompt(log_type, chunk)
                    
                    # Call LLM multiple times (as per your requirement)
                    with st.spinner("Processing..."):
                        answer = create_chat_completion(prompt)
                        if answer:
                            final_answer += answer + "\n\n"

                # Display the final answer from multiple LLM calls
                st.subheader("Audit/Sign-In Logs Analysis Result")
                st.markdown(final_answer)
            else:
                st.warning("Please enter a valid question.")

if __name__ == "__main__":
    main()
