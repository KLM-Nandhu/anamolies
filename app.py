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

def summarize_data(data):
    """
    Summarizes the entire dataset, providing column names, row count, and a brief description of each column.
    """
    columns_summary = {}
    for col in data.columns:
        unique_vals = data[col].nunique()
        columns_summary[col] = {
            "Type": str(data[col].dtype),
            "Unique Values": unique_vals,
            "Sample Values": data[col].dropna().unique()[:5].tolist()  # Show 5 unique values
        }
    
    summary = {
        "Total Rows": len(data),
        "Total Columns": len(data.columns),
        "Columns": columns_summary
    }
    
    return summary

def process_question(question, data):
    """
    Process the user's question based on the CSV data and generate an answer.
    This function passes a structured prompt to GPT-4, including a summary of the dataset and the user's question.
    """
    summary = summarize_data(data)
    
    # Generate a detailed and efficient prompt for GPT-4
    prompt = f"""
    You are analyzing a CSV dataset with the following summary:
    - Total Rows: {summary['Total Rows']}
    - Total Columns: {summary['Total Columns']}
    
    Here is a breakdown of the columns:
    {json.dumps(summary['Columns'], indent=2)}
    
    The user has asked the following question about the data: '{question}'

    Based on this data summary, answer the user's question as accurately as possible. 
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
    
    st.title("Dynamic Question Answering Based on Large CSV Data")
    
    # File uploader for CSV
    uploaded_file = st.file_uploader("Upload a CSV file", type=["csv"])
    
    if uploaded_file is not None:
        # Read the CSV file
        df = pd.read_csv(uploaded_file)
        
        st.subheader(f"CSV Data Preview: {len(df)} rows and {len(df.columns)} columns.")
        
        # Show the entire dataframe with scrollable content
        st.write("Scroll through the full dataset below:")
        st.dataframe(df)  # Display the entire dataframe in a scrollable format
        
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
