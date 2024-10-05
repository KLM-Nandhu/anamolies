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
    This function passes a structured prompt to GPT-4, including relevant data samples and the user's question.
    """
    sample_data = data.head(5).to_dict(orient="records")
    
    # Generate a detailed and efficient prompt for GPT-4
    prompt = f"""
    You are analyzing a CSV dataset uploaded by a user. Below is a sample of the first 5 rows of the data:
    {json.dumps(sample_data, indent=2)}

    The user has asked the following question about the data: '{question}'

    Your task is to analyze the data provided and answer the user's question as accurately as possible, based solely on the information in the data. 
    If the question cannot be answered from the data, explicitly state that the data does not provide enough information to answer the question. 
    Make sure the response is clear, concise, and directly addresses the user's query.
    
    Format the response clearly and provide explanations when necessary.
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
    
    st.title("Dynamic Question Answering Based on CSV Data")
    
    # File uploader for CSV
    uploaded_file = st.file_uploader("Upload a CSV file", type=["csv"])
    
    if uploaded_file is not None:
        # Read the CSV file
        df = pd.read_csv(uploaded_file)
        st.subheader("CSV Data Preview")
        st.dataframe(df.head())
        
        # Let user input their question dynamically
        st.subheader("Ask a Question About the Data")
        question = st.text_input("Enter your question based on the CSV data:")
        
        if st.button("Get Answer"):
            if question.strip() != "":
                with st.spinner("Processing question..."):
                    answer = process_question(question, df)
                    st.markdown(answer)
            else:
                st.warning("Please enter a valid question.")
    else:
        st.warning("Please upload a CSV file to begin analysis.")

if __name__ == "__main__":
    main()
