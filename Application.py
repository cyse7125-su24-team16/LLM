
import streamlit as st
from langchain_core.prompts import PromptTemplate
from langchain_community.llms import CTransformers
from pinecone import Pinecone
from langchain.schema import BaseRetriever
from langchain_huggingface import HuggingFaceEmbeddings
import os

os.environ["TOKENIZERS_PARALLELISM"] = "false"


# Initialize Pinecone with the API key
api_key = os.getenv('PINECONE_API_KEY')

# Initialize Pinecone client with the API key
pc = Pinecone(api_key=api_key)

# Connect to the existing Pinecone index
index = pc.Index("cve")

embeddings = HuggingFaceEmbeddings()
 
# Define PineconeRetriever
class PineconeRetriever(BaseRetriever):
    def _get_relevant_documents(self, query, **kwargs):
        # Generate the query vector using the embedding model
        query_vector = embeddings.embed_query(query)
        # Perform the query against the Pinecone index
        response = index.query(
            vector=query_vector,
            top_k=kwargs.get('top_k', 2),
            include_metadata=True
        )

        # st.write("Pinecone Response:", response)
        matches = response.get('matches', [])
        if not matches:
            st.write("No matches found.")
            return []
        return matches
    def invoke(self, query, **kwargs):
        return self._get_relevant_documents(query, **kwargs)

def simple_combine_documents(documents):
    combined_texts = []
    for doc in documents:
        metadata = doc.get('metadata', {})
        text = metadata.get('text', '')  # Fetch text directly from metadata
        if text:
            combined_texts.append(text)
        else:
            st.write(f"No text found in document ID: {doc.get('id')}")
    return ' '.join(combined_texts)
 
# Define load_llm function
def load_llm():
    return CTransformers(
        model="TheBloke/Llama-2-7B-Chat-GGML",
        model_type="llama"
    )
 
# Setup prompt template

custom_prompt_template = """Context: {context}
Question: {question}
Answer: """

prompt_template = PromptTemplate(template=custom_prompt_template, input_variables=['context', 'question'])
def retrieval_qa(query):
    retriever = PineconeRetriever()
    documents = retriever.invoke(query)
    # st.write("Retrieved Documents:", documents)
    combined_text = simple_combine_documents(documents)
    # st.write("Combined Context:", combined_text)
    prompt = prompt_template.format(context=combined_text, question=query)
    # st.write("Prompt passed to LLM:", prompt)
    llm = load_llm()
    answer = llm.invoke(prompt)
    return answer
 

def main():
    st.title("Query Assistance")
    st.write("Hi, how can I assist you today?")
    # Utilize session state to manage continuity
    if 'queries' not in st.session_state:
        st.session_state['queries'] = []
        st.session_state['query_count'] = 0
    query_key = f"query_{st.session_state['query_count']}"
    query = st.text_input("Enter your query:", key=query_key)
    submit_key = f"submit_{st.session_state['query_count']}"
    if st.button("Get Answer", key=submit_key):
        if query:
            result = retrieval_qa(query)
            st.session_state['queries'].append(query)  # Store queries if needed for future use
            st.write("Result:", result)
            # Increment the counter for a new unique key for the next input

            st.session_state['query_count'] += 1
            if st.button("Ask another query", key=f"another_query_{st.session_state['query_count']}"):
                # This button press will trigger a rerun; new inputs will have a unique key
                pass
        else:
            st.warning("Please enter a query to proceed.")
    if not query and st.session_state['query_count'] > 0:
        st.write("Thank you for using our service! You can restart the session by refreshing the page or continue typing new queries above.")
 
if __name__ == "__main__":
    main()

