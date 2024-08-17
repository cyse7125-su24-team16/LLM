# pip install requests zipfile36 pymongo transformers

import os
import requests
import zipfile
from io import BytesIO

github_api_url = os.getenv('GITHUB_API_URL')
DOWNLOAD_PATH = "./downloads"

def download_latest_release():
    response = requests.get(github_api_url)
    release_info = response.json()
    zip_url = release_info['zipball_url']

    response = requests.get(zip_url)
    zip_file = zipfile.ZipFile(BytesIO(response.content))

    if not os.path.exists(DOWNLOAD_PATH):
        os.makedirs(DOWNLOAD_PATH)

    zip_file.extractall(DOWNLOAD_PATH)
    return DOWNLOAD_PATH

download_latest_release()

# !pip install sentence-transformers -q

# ! pip install unstructured -q
# ! pip install unstructured[local-inference] -q
# ! pip install detectron2@git+https://github.com/facebookresearch/detectron2.git@v0.6#egg=detectron2 -q
# ! pip install pytesseract

# ! apt-get install poppler-utils

# ! pip install langchain

# ! pip install -U langchain-community

import os
import json
from langchain.schema import Document

directory = '/content/downloads/CVEProject-cvelistV5-f34b70d/cves'

def custom_load_docs(directory):
    documents = []
    for root, _, files in os.walk(directory):
        for file in files:
            # Skip delta.json and DeltaLog.json
            if file not in ['delta.json', 'deltaLog.json']:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r') as f:
                        content = json.load(f)
                        # Add the document to the list, wrapping the content in a Document object
                        documents.append(Document(page_content=str(content), metadata={"source": file_path}))
                except Exception as e:
                    print(f"Error loading {file_path}: {e}")
    return documents

documents = custom_load_docs(directory)
print(f"Loaded {len(documents)} documents.")

# !pip install orjson

import os
import orjson
import csv
from multiprocessing import Pool, cpu_count

# Define the root directory containing the JSON files
directory = os.getenv('CVE_DIRECTORY')

# Define the output CSV file path
output_csv = 'cve_data.csv'

def flatten_json(y, prefix=''):
    out = {}
    if isinstance(y, dict):
        for key, value in y.items():
            if isinstance(value, dict):
                out.update(flatten_json(value, prefix + key + '_'))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    out.update(flatten_json(item, prefix + key + f'_{i}_'))
            else:
                out[prefix + key] = value
    elif isinstance(y, list):
        for i, item in enumerate(y):
            out.update(flatten_json(item, prefix + f'_{i}_'))
    else:
        out[prefix.rstrip('_')] = y
    return out

def process_file(file_path):
    try:
        with open(file_path, 'rb') as f:  # Use 'rb' for faster binary reading
            content = orjson.loads(f.read())  # Faster JSON parsing with orjson
            flat_content = flatten_json(content)
            return flat_content
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

def custom_load_and_parse_docs(directory, output_csv):
    file_paths = []

    # Collect file paths to process
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.json') and file.lower() not in ['delta.json', 'deltalog.json']:
                file_paths.append(os.path.join(root, file))

    # Initialize the multiprocessing pool
    with Pool(cpu_count()) as pool:
        # Process files in parallel
        results = pool.map(process_file, file_paths)

    # Collect all fieldnames dynamically
    all_fieldnames = set()
    for flat_content in results:
        if flat_content:
            all_fieldnames.update(flat_content.keys())

    # Write results to CSV
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.DictWriter(csvfile, fieldnames=list(all_fieldnames))
        csvwriter.writeheader()

        for flat_content in results:
            if flat_content:
                csvwriter.writerow(flat_content)

    print(f"Data extraction complete. CSV file saved at {output_csv}")

# Run the function
custom_load_and_parse_docs(directory, output_csv)

from google.colab import files

# Assuming the file is saved as 'cve_data.csv' in the current directory
files.download('cve_data.csv')

import re
from collections import defaultdict
from langchain.text_splitter import RecursiveCharacterTextSplitter

# Step 1: Group documents by year
def group_documents_by_year(documents):
    year_docs = defaultdict(list)
    for doc in documents:
        # Extract the year from the file path, assuming it's the first directory level under 'cves'
        match = re.search(r'/cves/(\d{4})/', doc.metadata['source'])
        if match:
            year = match.group(1)
            year_docs[year].append(doc)
    return year_docs

# Step 2: Split documents within each year group
def split_docs_by_year(documents_by_year, chunk_size=500, chunk_overlap=20):
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    split_docs_by_year = {}

    for year, docs in documents_by_year.items():
        split_docs_by_year[year] = text_splitter.split_documents(docs)

    return split_docs_by_year

# Assuming 'documents' is already loaded as before
# Group documents by year
documents_by_year = group_documents_by_year(documents)

# Split documents by year
split_docs = split_docs_by_year(documents_by_year)

# Print the number of chunks for each year
for year, chunks in split_docs.items():
    print(f"Year {year}: {len(chunks)} chunks")

# If you need a flat list of all split documents:
all_split_docs = [chunk for chunks in split_docs.values() for chunk in chunks]
print(f"Total chunks: {len(all_split_docs)}")

# Inspect the first few split chunks (after splitting)
for year, chunks in split_docs.items():
    print(f"Year {year}:")
    for i, chunk in enumerate(chunks[:3]):  # Adjust the number 3 if you want to inspect more or fewer chunks
        print(f"Chunk {i+1}:")
        print(f"Content: {chunk.page_content}")  # Print the entire content of the chunk
        print(f"Metadata: {chunk.metadata}")
        print("="*80)

# Loop through the dictionary
for year, chunks in split_docs.items():
    if year == "2006":  # Check if the current year is 2006
        print(f"Year {year}:")
        for i, chunk in enumerate(chunks[:30]):  # Adjust to print only the first 20 chunks
            print(f"Chunk {i+1}:")
            print(f"Content: {chunk.page_content}")  # Print the content of the chunk
            print(f"Metadata: {chunk.metadata}")
            print("="*80)
        break  # Exit the loop after processing year 2006

# Combine content and metadata into a single text string
texts = []
metadatas = []

for doc in all_split_docs:
    # Combine content and metadata
    combined_text = f"Content: {doc.page_content}\nMetadata: {doc.metadata}"
    texts.append(combined_text)
    metadatas.append(doc.metadata)  # Retain the original metadata if needed

# !pip install pinecone-client
# !pip install sentence-transformers
# !pip install langchain
# !pip install langchain_huggingface

from pinecone import Pinecone
from langchain_huggingface import HuggingFaceEmbeddings

# Initialize Pinecone with the API key
api_key = os.getenv('PINECONE_API_KEY')

# Initialize Pinecone client with the API key
pc = Pinecone(api_key=api_key)


# Connect to the existing Pinecone index
index = pc.Index("cve")


# pc.create_index(
#     name='cve-index',
#     dimension=768,
#     metric='euclidean',
#     deletion_protection='enabled',
#     spec=ServerlessSpec(
#         cloud='aws',
#         region='us-east-1'
#     )
# )

# Testing connection to index by listing indexes - output: cve-index
for idx in pc.list_indexes():
    print(idx['name'])

# Initialize the embeddings model - using sentence-transformers from Transformers library of HuggingFace
embeddings = HuggingFaceEmbeddings()

# Use only a smaller subset of documents for testing
small_docs = all_split_docs[:30]  # Adjust this number as needed
print(small_docs)

# Convert the small subset of documents into embeddings and upsert them into the Pinecone index
# Convert the small subset of documents into embeddings and upsert them into the Pinecone index
vectors = [embeddings.embed_query(doc.page_content) for doc in small_docs]
upsert_data = [
    (
        str(i),  # Document ID
        vectors[i],  # Vector embedding
        {"text": doc.page_content, **doc.metadata}  # Metadata including the original text
    )
    for i, doc in enumerate(small_docs)
]

# Upsert the vectors and associated metadata (including text) into Pinecone
upsert_response = index.upsert(
    vectors=upsert_data,
    # namespace="cve-namespace"
)

print("Upsert Response:", upsert_response)

print(type(index))

def get_similar_docs(query, k=1, score=False):
    # Embed the query into a vector
    query_vector = embeddings.embed_query(query)

    # Query Pinecone index with the embedded vector
    response = index.query(
        vector=query_vector,
        top_k=k,
        include_values=True,  # Include the values (vectors)
        include_metadata=True  # Include metadata if stored
    )

    similar_docs = []

    for match in response['matches']:
        doc_info = {
            "id": match['id'],
            "score": match['score'] if score else None,
            "metadata": match.get('metadata', {}),
            "vector": match.get('values', [])
        }
        similar_docs.append(doc_info)

    return similar_docs

# Example usage
query = "What is the Latest CVE ID?"
similar_docs = get_similar_docs(query, k=3, score=True)  # Fetch top 3 results with scores
print(similar_docs)

prompt_template="""
Use the following pieces of information to answer the user's question.
If you don't know the answer, just say that you don't know, don't try to make up an answer.

Context: {context}
Question: {question}

Only return the helpful answer below and nothing else.
Helpful answer:
"""

from langchain.prompts import PromptTemplate
PROMPT=PromptTemplate(template=prompt_template, input_variables=["context", "question"])
chain_type_kwargs={"prompt": PROMPT}

# !pip install ctransformers

import pinecone
from langchain.schema import BaseRetriever

# Initialize Pinecone environment
# Initialize Pinecone with the API key
# Initialize Pinecone with the API key
api_key = os.getenv('PINECONE_API_KEY')

# Initialize Pinecone client with the API key
pc = Pinecone(api_key=api_key)

# Connect to the existing Pinecone index
index = pc.Index("cve")


class PineconeRetriever(BaseRetriever):
    def _get_relevant_documents(self, query, **kwargs):
        query_vector = embeddings.embed_query(query)  # Replace with your embedding function
        response = index.query(
            vector=query_vector,
            top_k=kwargs.get('top_k', 2),
            include_values=True,
            include_metadata=True
        )
        documents = []
        for match in response['matches']:
            doc_info = {
                "id": match['id'],
                "score": match.get('score', None),
                "metadata": match.get('metadata', {}),
                "vector": match.get('values', [])
            }
            documents.append(doc_info)
        return documents

# Replace `embeddings` with your actual embeddings object

def load_llm():
    llm = CTransformers(
        model="TheBloke/Llama-2-7B-Chat-GGML",
        model_type="llama",
        config={'max_new_tokens': 512, 'temperature': 0.8}
    )
    return llm

from langchain.llms import CTransformers
llm=CTransformers(model="TheBloke/Llama-2-7B-Chat-GGML",
                  model_type="llama",
                  config={'max_new_tokens':512,
                          'temperature':0.8})

from langchain_core.prompts import PromptTemplate

custom_prompt_template = """Use the following information to answer the user's question:
Context: {context}
Question: {question}
Answer:
"""
prompt_template = PromptTemplate(template=custom_prompt_template, input_variables=['context', 'question'])

# !pip install --upgrade langchain langchain_core langchain_community
# !

from langchain_core.prompts import PromptTemplate
from langchain_community.llms import CTransformers
import pinecone
from langchain.schema import BaseRetriever

# Define PineconeRetriever
class PineconeRetriever(BaseRetriever):
    def _get_relevant_documents(self, query, **kwargs):
        query_vector = embeddings.embed_query(query)
        response = index.query(
            vector=query_vector,
            top_k=kwargs.get('top_k', 2),
            include_values=True,
            include_metadata=True
        )
        documents = [
            {"id": match['id'], "score": match.get('score'), "metadata": match.get('metadata'), "vector": match.get('values')}
            for match in response['matches']
        ]
        return documents

    def invoke(self, query, **kwargs):
        return self._get_relevant_documents(query, **kwargs)

# Custom combine documents function
def simple_combine_documents(documents):
    return ' '.join([doc['metadata'].get('text', '') for doc in documents])

# Define load_llm function
def load_llm():
    return CTransformers(
        model="TheBloke/Llama-2-7B-Chat-GGML",
        model_type="llama"
    )

# Setup prompt template
custom_prompt_template = """Context: {context} Question: {question} Answer: """
prompt_template = PromptTemplate(template=custom_prompt_template, input_variables=['context', 'question'])

# Define the QA function manually with invoke
def retrieval_qa(query):
    # Step 1: Retrieve documents using the invoke method
    retriever = PineconeRetriever()
    documents = retriever.invoke(query)
    print("Retrieved Documents",documents)

    # Step 2: Combine documents
    combined_text = simple_combine_documents(documents)
    print("Combined Context:", combined_text)

    # Step 3: Prepare the prompt with context and question
    prompt = prompt_template.format(context=combined_text, question=query)
    print("prompt passed to LLM", prompt)

    # Step 4: Generate the answer using the LLM with invoke method
    llm = load_llm()
    answer = llm.invoke(prompt)

    return answer

# Example usage
query = "Check if the assigner short name for CVE-2023-23456 has been changed from its original entry"
result = retrieval_qa(query)
print(result)