import streamlit as st
import pandas as pd
import openai

# Set up OpenAI API key
openai.api_key = st.secrets["openai_api_key"]

@st.cache_data
def load_csv(file):
    return pd.read_csv(file)

def process_question_with_gpt(question, context):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful assistant that analyzes questions about CSV data and provides key terms to search for in the data."},
                {"role": "user", "content": f"Given this context about a CSV file:\n{context}\n\nAnalyze this question and provide key terms to search for in the CSV data: {question}"}
            ],
            max_tokens=100
        )
        return response.choices[0].message['content'].strip()
    except Exception as e:
        st.error(f"An error occurred while processing with GPT: {str(e)}")
        return None

def find_answer_in_csv(df, question, gpt_analysis):
    key_terms = gpt_analysis.lower().split()
    
    for column in df.columns:
        if any(term in column.lower() for term in key_terms):
            for value in df[column].astype(str):
                if any(term in value.lower() for term in key_terms):
                    result = df[df[column].astype(str).str.lower() == value.lower()]
                    if not result.empty:
                        return result.iloc[0].to_dict()
    
    return "I couldn't find a relevant answer in the CSV data."

def format_answer(answer_dict):
    if isinstance(answer_dict, str):
        return answer_dict
    
    formatted_answer = "Here's the information I found:\n\n"
    for key, value in answer_dict.items():
        formatted_answer += f"{key}: {value}\n"
    return formatted_answer

def main():
    st.set_page_config(page_title="CSV Q&A System", page_icon="📊", layout="wide")
    
    st.title("CSV Q&A System with OpenAI")
    st.write("Upload your CSV file, preview the data, and ask questions!")

    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
    
    if uploaded_file is not None:
        try:
            df = load_csv(uploaded_file)
            st.success("CSV file loaded successfully!")
            
            st.subheader("Data Preview")
            st.dataframe(df.head())
            st.info(f"Total rows: {len(df)}, Total columns: {len(df.columns)}")
            
            context = f"The CSV file contains the following columns: {', '.join(df.columns)}"
            
            st.subheader("Ask a Question")
            question = st.text_input("Enter your question about the data:")
            
            if question:
                with st.spinner("Processing question and searching data..."):
                    gpt_analysis = process_question_with_gpt(question, context)
                    if gpt_analysis:
                        answer_dict = find_answer_in_csv(df, question, gpt_analysis)
                        formatted_answer = format_answer(answer_dict)
                    else:
                        formatted_answer = "Failed to process the question with GPT."
                
                st.subheader("Answer")
                st.write(formatted_answer)
                
                with st.expander("View GPT Analysis"):
                    st.text(gpt_analysis)
            
            # Additional data exploration options
            st.subheader("Data Exploration")
            if st.checkbox("Show column information"):
                st.write(df.dtypes)
            
            if st.checkbox("Show summary statistics"):
                st.write(df.describe())
            
            selected_column = st.selectbox("Select a column to view unique values:", df.columns)
            if selected_column:
                unique_values = df[selected_column].nunique()
                st.write(f"Number of unique values in {selected_column}: {unique_values}")
                if unique_values <= 20:
                    st.write(df[selected_column].value_counts())
                else:
                    st.write("Too many unique values to display. Here are the top 20:")
                    st.write(df[selected_column].value_counts().head(20))
        
        except Exception as e:
            st.error(f"An error occurred while processing the CSV file: {str(e)}")
    else:
        st.info("Please upload a CSV file to begin.")

if __name__ == "__main__":
    main()
