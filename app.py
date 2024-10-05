import streamlit as st
import pandas as pd
from openai import OpenAI
from io import StringIO
import time

# Configuration
MAX_TOKENS = 150
RATE_LIMIT_SECONDS = 20
MAX_CONTEXT_TOKENS = 3000

# Set up OpenAI client
client = OpenAI(api_key=st.secrets["openai_api_key"])

@st.cache_data
def load_data(files):
    dfs = []
    for file in files:
        try:
            df = pd.read_csv(file)
            dfs.append(df)
        except pd.errors.EmptyDataError:
            st.warning(f"The file {file.name} is empty and will be skipped.")
        except pd.errors.ParserError:
            st.warning(f"Error parsing the file {file.name}. It will be skipped.")
    
    if not dfs:
        return None
    
    return pd.concat(dfs, ignore_index=True)

def get_relevant_data(df, question, max_tokens):
    relevance = df.apply(lambda row: sum(1 for word in question.lower().split() if word in ' '.join(row.astype(str)).lower()), axis=1)
    sorted_df = df.loc[relevance.sort_values(ascending=False).index]
    
    context = ""
    for _, row in sorted_df.iterrows():
        row_text = ' '.join(row.astype(str))
        if len(context) + len(row_text) > max_tokens:
            break
        context += row_text + "\n"
    
    return context

def get_gpt4o_mini_response(context, question):
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Using the specified model name
            messages=[
                {"role": "system", "content": "You are a helpful assistant that answers questions based on the given data."},
                {"role": "user", "content": f"Given the following data:\n{context}\n\nQuestion: {question}\nAnswer:"}
            ],
            max_tokens=MAX_TOKENS
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
        return None

def main():
    st.set_page_config(page_title="Multi-CSV Q&A System", page_icon="📊", layout="wide")
    
    st.title("Multi-CSV Q&A System with GPT-4o-mini")
    st.write("Upload your CSV files and ask questions about the data!")

    uploaded_files = st.file_uploader("Choose CSV files", type="csv", accept_multiple_files=True)
    
    if uploaded_files:
        try:
            with st.spinner("Loading and processing data..."):
                df = load_data(uploaded_files)
            
            if df is not None:
                st.success("Data loaded successfully!")
                
                st.subheader("Data Preview")
                st.write("First 5 rows of combined data:")
                st.dataframe(df.head())
                st.info(f"Total rows in combined dataset: {len(df)}")
                
                st.subheader("Ask a Question")
                user_question = st.text_input("Enter your question about the data:")
                
                if user_question:
                    with st.spinner("Analyzing data and generating answer..."):
                        context = get_relevant_data(df, user_question, MAX_CONTEXT_TOKENS)
                        answer = get_gpt4o_mini_response(context, user_question)
                    
                    if answer:
                        st.subheader("Answer")
                        st.write(answer)
                        
                        with st.expander("Show context used for answering"):
                            st.text_area("Context:", value=context, height=200)
                    else:
                        st.error("Failed to generate an answer. Please try again.")
            else:
                st.error("No valid data was found in the uploaded files. Please upload CSV files containing data.")
        except Exception as e:
            st.error(f"An unexpected error occurred: {str(e)}")
    else:
        st.info("Please upload one or more CSV files to begin.")

if __name__ == "__main__":
    main()
