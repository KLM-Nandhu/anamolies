import streamlit as st
import pandas as pd
from openai import OpenAI
import io

# Configuration
MAX_TOKENS = 150
MAX_CONTEXT_TOKENS = 3000
SAMPLE_ROWS = 100

# Set up OpenAI client
client = OpenAI(api_key=st.secrets["openai_api_key"])

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

def get_gpt_response(context, question, model="4o-mini"):  # Keeping the model as 4o-mini
    try:
        # Attempting to use the 4o-mini model
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a helpful assistant that answers questions based on the given CSV data. Provide concise and accurate answers."},
                {"role": "user", "content": f"Here's a summary and sample of the CSV data:\n{context}\n\nQuestion: {question}\nAnswer:"}
            ],
            max_tokens=MAX_TOKENS
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        # Catch the error and show the specific error message if 4o-mini doesn't work
        st.error(f"Error with model {model}: {str(e)}")
        return None

def main():
    st.set_page_config(page_title="CSV Q&A System", page_icon="📊", layout="wide")
    
    st.title("CSV Q&A System with 4o-mini Model")
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
                with st.spinner("Generating answer..."):
                    answer = get_gpt_response(context, question)
                
                if answer:
                    st.subheader("Answer")
                    st.write(answer)
                    
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
