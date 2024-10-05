import streamlit as st
import json
import openai
from typing import List, Dict

# Load OpenAI API key from Streamlit secrets
openai.api_key = st.secrets["openai_api_key"]

# Function to call GPT-4 with a specific prompt
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

# Function to sample and summarize data
def sample_and_summarize_data(data: List[Dict], max_samples: int = 10) -> str:
    if len(data) <= max_samples:
        return json.dumps(data, indent=2)
    
    sampled_data = data[:max_samples]
    summary = {
        "sampled_data": sampled_data,
        "total_records": len(data),
        "sampled_records": len(sampled_data)
    }
    return json.dumps(summary, indent=2)

# Main Streamlit app
def main():
    st.set_page_config(page_title="JSON Log Analyzer", layout="wide")

    st.title("JSON Log Analyzer")

    # File upload for JSON
    uploaded_file = st.file_uploader("Upload a JSON file", type=["json"])

    if uploaded_file is not None:
        try:
            # Load JSON data
            json_data = json.load(uploaded_file)
            
            # Display JSON data preview
            st.write("JSON Data Preview:")
            st.json(json_data[:5])  # Display first 5 records

            # Show total number of records
            st.write(f"Total records in JSON: {len(json_data)}")

            # Asking questions based on logs
            st.subheader("Ask a Question")
            
            # Create a form for the question input
            with st.form(key='question_form'):
                question = st.text_input("Enter your question:")
                submit_button = st.form_submit_button(label='Submit')

            # Process the question when the form is submitted (either by Enter key or Submit button)
            if submit_button or question:
                if question.strip() != "":
                    # Sample and summarize the JSON data
                    sampled_data = sample_and_summarize_data(json_data)
                    
                    # Process data with GPT-4
                    prompt = f"""
                    Based on the following log data:
                    {sampled_data}

                    Answer the following question: '{question}'
                    Provide a detailed answer with any relevant insights or recommendations.
                    If the data provided is a sample, mention this in your answer and provide insights based on the available information.
                    """

                    with st.spinner("Processing answer..."):
                        answer = create_chat_completion(prompt)
                        if answer:
                            st.subheader("Analysis Result")
                            st.markdown(answer)
                        else:
                            st.error("Unable to generate an answer.")
                else:
                    st.warning("Please enter a valid question.")

        except Exception as e:
            st.error(f"Error processing the JSON file: {str(e)}")
            st.write("Please ensure your JSON file has the correct format.")

    else:
        st.warning("Please upload a JSON file to begin analysis.")

if __name__ == "__main__":
    main()
