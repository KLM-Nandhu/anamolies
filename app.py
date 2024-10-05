import streamlit as st
import pandas as pd
import json
import openai

# Set up OpenAI API key
openai.api_key = st.secrets["openai_api_key"]

def create_chat_completion(**kwargs):
    """
    Wrapper function to create chat completion using OpenAI API.
    """
    try:
        return openai.ChatCompletion.create(**kwargs)
    except Exception as e:
        st.error(f"Error in LLM call: {str(e)}")
        return None

def process_question(question, data):
    """
    Process the user's question based on the CSV data and generate an answer.
    The prompt passes a sample of the CSV data and the user's question to GPT-4.
    """
    sample_data = data.head(5).to_dict(orient="records")
    
    # Prepare the prompt for GPT-4
    prompt = f"""The user has uploaded a CSV file with the following sample data (first 5 rows):
{json.dumps(sample_data, indent=2)}

Based on this data, answer the following question: '{question}'
If the question cannot be answered from the given data, please state that clearly.

Format your response clearly and concisely, and ensure it is based solely on the provided data.
"""

    # Make a request to GPT-4
    response = create_chat_completion(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}]
    )
    
    if response:
        return response.choices[0].message.content.strip()
    else:
        return "Unable to process the question due to an error."

def main():
    st.set_page_config(page_title="Dynamic CSV Analysis", layout="wide")
    
    st.title("Ask Questions Based on CSV Data")
    
    # File uploader for CSV
    uploaded_file = st.file_uploader("Upload a CSV file", type=["csv"])
    
    if uploaded_file is not None:
        # Read the CSV file
        df = pd.read_csv(uploaded_file)
        st.subheader("CSV Data Preview")
        st.dataframe(df.head())

        st.subheader("Ask a Question")
        question = st.text_input("Enter your question based on the CSV data:")
        
        if st.button("Get Answer"):
            with st.spinner("Processing question..."):
                answer = process_question(question, df)
                st.markdown(answer)
    
    else:
        st.warning("Please upload a CSV file to begin analysis.")

if __name__ == "__main__":
    main()
