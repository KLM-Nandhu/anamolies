import streamlit as st
import pandas as pd
import openai
from io import StringIO
import time
import random

# Configuration
MAX_TOKENS = 150
RATE_LIMIT_SECONDS = 20
MAX_CONTEXT_TOKENS = 3000

# Set up OpenAI API key
openai.api_key = st.secrets["openai_api_key"]

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
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",  # Using the specified model name
            messages=[
                {"role": "system", "content": "You are a helpful assistant that answers questions based on the given data."},
                {"role": "user", "content": f"Given the following data:\n{context}\n\nQuestion: {question}\nAnswer:"}
            ],
            max_tokens=MAX_TOKENS
        )
        return response.choices[0].message['content'].strip()
    except openai.error.RateLimitError:
        st.error("OpenAI API rate limit reached. Please wait a moment before trying again.")
        time.sleep(RATE_LIMIT_SECONDS)
        return None
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
        return None

def generate_question_suggestions(df):
    columns = df.columns.tolist()
    suggestions = [
        f"What is the average {random.choice(columns)}?",
        f"How many unique values are there in the {random.choice(columns)} column?",
        f"What is the relationship between {random.choice(columns)} and {random.choice(columns)}?",
        f"What is the most common value in the {random.choice(columns)} column?",
        f"How has the {random.choice(columns)} changed over time?"
    ]
    return suggestions

def main():
    st.title("Multi-CSV Q&A System with GPT-4o-mini")
    uploaded_files = st.file_uploader("Choose CSV files", type="csv", accept_multiple_files=True)
    
    if uploaded_files:
        try:
            df = load_data(uploaded_files)
            if df is not None:
                st.write("Data Preview (first 5 rows of combined data):")
                st.write(df.head())
                st.write(f"Total rows in combined dataset: {len(df)}")
                
                # Generate and display question suggestions
                suggestions = generate_question_suggestions(df)
                selected_question = st.selectbox("Suggested questions:", [""] + suggestions)
                
                # Allow user to input their own question or use a suggestion
                user_question = st.text_input("Ask a question about the data:", value=selected_question)
                
                if user_question:
                    context = get_relevant_data(df, user_question, MAX_CONTEXT_TOKENS)
                    
                    with st.spinner("Generating answer with GPT-4o-mini..."):
                        answer = get_gpt4o_mini_response(context, user_question)
                    if answer:
                        st.write("Answer:", answer)
                        # Option to see the context used
                        if st.checkbox("Show context used for answering"):
                            st.text_area("Context:", context, height=200)
            else:
                st.error("No valid data was found in the uploaded files.")
        except Exception as e:
            st.error(f"An unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    main()
