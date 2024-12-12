import os
import json5
import re
from PyPDF2 import PdfFileReader
import faiss
import numpy as np
from qwen_agent.tools.base import BaseTool, register_tool
from openai.embeddings_utils import get_embedding

# Initialize FAISS index
faiss_index = faiss.IndexFlatL2(1536)  # OpenAI embeddings have 1536 dimensions

def extract_text_from_pdf(pdf_path):
    """Extract text from a PDF file."""
    extracted_text = ""
    try:
        with open(pdf_path, 'rb') as file:
            reader = PdfFileReader(file)
            for page_num in range(reader.numPages):
                page = reader.getPage(page_num)
                extracted_text += page.extract_text() + "\n"
    except Exception as e:
        print(f"Error reading PDF: {e}")
    return extracted_text

def create_embeddings_and_store(pdf_text):
    """Create embeddings for extracted text using OpenAI and store in FAISS."""
    # Split text into smaller chunks
    text_chunks = pdf_text.split("\n")
    embeddings = []
    chunk_texts = []

    for chunk in text_chunks:
        if chunk.strip():
            embedding = get_embedding(chunk, engine="text-embedding-ada-002")
            embeddings.append(embedding)
            chunk_texts.append(chunk)

    # Convert embeddings to FAISS-compatible format and add to index
    if embeddings:
        embeddings = np.array(embeddings).astype('float32')
        faiss_index.add(embeddings)
    
    return chunk_texts

def search_in_embeddings(query, chunk_texts, k=5):
    """Search FAISS index for relevant chunks based on a query."""
    query_embedding = get_embedding(query, engine="text-embedding-ada-002")
    query_embedding = np.array([query_embedding]).astype('float32')
    distances, indices = faiss_index.search(query_embedding, k)

    results = []
    for idx in indices[0]:
        if idx < len(chunk_texts):
            results.append(chunk_texts[idx])

    return results

@register_tool('rag_pdf_analyzer')
class RAGPDFAnalyzer(BaseTool):
    description = 'Tool to analyze PDF files, create embeddings, store in FAISS, and retrieve context for queries.'

    parameters = [
        {
            'name': 'pdf_paths',
            'type': 'list',
            'description': 'List of paths to the PDF files',
            'required': True
        },
        {
            'name': 'query',
            'type': 'string',
            'description': 'The query for retrieving context',
            'required': True
        }
    ]

    def call(self, params: str, **kwargs) -> str:
        params = json5.loads(params)
        pdf_paths = params['pdf_paths']
        query = params['query']

        all_text = ""
        chunk_texts = []

        for pdf_path in pdf_paths:
            extracted_text = extract_text_from_pdf(pdf_path)
            all_text += extracted_text

        # Create embeddings and store in FAISS
        chunk_texts = create_embeddings_and_store(all_text)

        # Search the FAISS index with the query
        results = search_in_embeddings(query, chunk_texts)

        return json5.dumps({'results': results}, ensure_ascii=False)

# Integration with Original System
class PDFIntegrationWithRAG:
    def __init__(self, pdf_paths, query):
        self.pdf_paths = pdf_paths
        self.query = query

    def process_and_analyze(self):
        """Process PDFs and analyze using RAG."""
        analyzer = RAGPDFAnalyzer()
        response = analyzer.call(json5.dumps({"pdf_paths": self.pdf_paths, "query": self.query}))
        return json5.loads(response)

def integrate_with_existing_system(pdf_paths, query):
    integration = PDFIntegrationWithRAG(pdf_paths, query)
    results = integration.process_and_analyze()

    print("Integration Results:")
    for idx, result in enumerate(results['results']):
        print(f"Result {idx + 1}: {result}")

# Example integration usage
def main():
    pdf_paths = ["example1.pdf", "example2.pdf"]
    query = "What are the guidelines for impact analysis?"

    integrate_with_existing_system(pdf_paths, query)

if __name__ == "__main__":
    main()
