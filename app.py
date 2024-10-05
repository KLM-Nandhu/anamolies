import streamlit as st
import pandas as pd
import io
import openai
import re

# Configuration
MAX_TOKENS = 150
MAX_CONTEXT_TOKENS = 3000
SAMPLE_ROWS = 100

# Set up OpenAI API key
openai.api_key = st.secrets["openai_api_key"]

@st.cache_data
def load_csv(file):
    return pd.read_csv(file)

def get_data_summary(df):
    summary = io.StringIO()
    df.info(buf=summary)
    return summary.getvalue()

def get_data_sample(df, n=SAMPLE_ROWS):
    return df.sample(n=min(n, len(df))).to_string(index=False)

def truncate_context(context, max_tokens):
    tokens = context.split()
    if len(tokens) > max_tokens:
        return " ".join(tokens[:max_tokens]) + "..."
    return context

def process_question_with_gpt(question, context):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini", 
            messages=[
                {"role": "system", "content": "You are a helpful assistant that analyzes questions about CSV data and provides key terms to search for in the data."},
                {"role": "user", "content": f"Given this context about a CSV file:\n{context}\n\nAnalyze this question and provide key terms to search for in the CSV data: {question}"}
            ],
            max_tokens=MAX_TOKENS
        )
        return response.choices[0].message['content'].strip()
    except Exception as e:
        st.error(f"An error occurred while processing with GPT: {str(e)}")
        return None

def find_answer_in_csv(df, gpt_analysis):
    # Extract key terms from GPT analysis
    key_terms = re.findall(r'\b\w+\b', gpt_analysis.lower())
    
    relevant_rows = df[df.apply(lambda row: any(term in ' '.join(row.astype(str)).lower() for term in key_terms), axis=1)]
    
    if relevant_rows.empty:
        return "I couldn't find a relevant answer in the CSV data based on the analysis."
    
    # Construct an answer based on the relevant rows
    answer = f"Based on the GPT analysis and CSV data, I found {len(relevant_rows)} relevant entries. "
    answer += f"Here's a summary:\n\n{relevant_rows.head().to_string()}"
    
    return answer

def main():
    st.set_page_config(page_title="CSV Q&A System", page_icon="📊", layout="wide")
    
    st.title("CSV Q&A System ")
    st.write("Upload your CSV file, preview the data, and ask questions!")

    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
    
    if uploaded_file is not None:
        try:
            df = load_csv(uploaded_file)
            st.success("CSV file loaded successfully!")
            
            st.subheader("Data Preview")
            st.dataframe(df.head())
            st.info(f"Total rows: {len(df)}, Total columns: {len(df.columns)}")
            
            # Data summary for context
            data_summary = get_data_summary(df)
            data_sample = get_data_sample(df)
            context = f"Data Summary:\n{data_summary}\n\nData Sample:\n{data_sample}"
            context = truncate_context(context, MAX_CONTEXT_TOKENS)
            
            st.subheader("Ask a Question")
            question = st.text_input("Enter your question about the data:")
            
            if question:
                with st.spinner("Processing question with GPT and searching data..."):
                    gpt_analysis = process_question_with_gpt(question, context)
                    if gpt_analysis:
                        answer = find_answer_in_csv(df, gpt_analysis)
                    else:
                        answer = "Failed to process the question with GPT."
                
                st.subheader("Answer")
                st.write(answer)
                
                with st.expander("View GPT Analysis"):
                    st.text(gpt_analysis)
                
                with st.expander("View Data Context"):
                    st.text(context)
            
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
