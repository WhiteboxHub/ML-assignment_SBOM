from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import openai
import os
from dotenv import load_dotenv

# Configuration
load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
 
# Connect to PostgreSQL database
def connect_to_db():
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Test the connection
    try:
        engine.connect()
        print("Database connection successful.")
    except Exception as e:
        print(f"Failed to connect to the database: {e}")
    
    return engine, session

# Fetch relevant SBOM data from all tables
def fetch_relevant_sbom_data(session, query):
    query = query.replace(' ', ' & ')  # Format query for full-text search

    relevant_data = {
        'advisories': [],
        'vulnerabilities': [],
        'fixes': [],
        'products': [],
        'vendors': []
    }

    # Fetch relevant advisories
    try:
        advisories_result = session.execute(
            text("""
            SELECT *
            FROM advisories
            WHERE to_tsvector('english', advisory_text || ' ' || description) @@ to_tsquery('english', :query)
            ORDER BY ts_rank(to_tsvector('english', advisory_text || ' ' || description), to_tsquery('english', :query)) DESC
            LIMIT 5;
            """),
            {'query': query}
        ).fetchall()
        relevant_data['advisories'].extend([row._mapping for row in advisories_result])
        print(f"Advisories Result: {relevant_data['advisories']}")  # Debugging print
    except Exception as e:
        print(f"Error fetching advisories: {e}")
    
    # Fetch relevant vulnerabilities
    try:
        vulnerabilities_result = session.execute(
            text("""
            SELECT *
            FROM vulnerabilities
            WHERE to_tsvector('english', cve_id || ' ' || description) @@ to_tsquery('english', :query)
            ORDER BY severity DESC
            LIMIT 5;
            """),
            {'query': query}
        ).fetchall()
        relevant_data['vulnerabilities'].extend([row._mapping for row in vulnerabilities_result])
        print(f"Vulnerabilities Result: {relevant_data['vulnerabilities']}")  # Debugging print
    except Exception as e:
        print(f"Error fetching vulnerabilities: {e}")
    
    # Fetch relevant fixes
    try:
        fixes_result = session.execute(
            text("""
            SELECT *
            FROM fixes
            WHERE to_tsvector('english', fix_description) @@ to_tsquery('english', :query)
            LIMIT 5;
            """),
            {'query': query}
        ).fetchall()
        relevant_data['fixes'].extend([row._mapping for row in fixes_result])
        print(f"Fixes Result: {relevant_data['fixes']}")  # Debugging print
    except Exception as e:
        print(f"Error fetching fixes: {e}")
    
    # Fetch relevant products
    try:
        products_result = session.execute(
            text("""
            SELECT *
            FROM products
            WHERE to_tsvector('english', product_name || ' ' || version) @@ to_tsquery('english', :query)
            LIMIT 5;
            """),
            {'query': query}
        ).fetchall()
        relevant_data['products'].extend([row._mapping for row in products_result])
        print(f"Products Result: {relevant_data['products']}")  # Debugging print
    except Exception as e:
        print(f"Error fetching products: {e}")
    
    # Fetch relevant vendors
    try:
        vendors_result = session.execute(
            text("""
            SELECT *
            FROM vendors
            WHERE to_tsvector('english', vendor_name || ' ' || contact_info) @@ to_tsquery('english', :query)
            LIMIT 5;
            """),
            {'query': query}
        ).fetchall()
        relevant_data['vendors'].extend([row._mapping for row in vendors_result])
        print(f"Vendors Result: {relevant_data['vendors']}")  # Debugging print
    except Exception as e:
        print(f"Error fetching vendors: {e}")
    
    # Check if any relevant data was found in the database
    if any(relevant_data.values()):  # If any of the lists is non-empty
        return relevant_data
    else:
        return None

# Generate context for LLM
def generate_context(relevant_data):
    context = ""
    
    # Add advisory information
    for advisory in relevant_data.get('advisories', []):
        context += f"Advisory ID: {advisory.get('id', 'N/A')}, Text: {advisory.get('advisory_text', 'N/A')}, Description: {advisory.get('description', 'N/A')}, Published Date: {advisory.get('published_date', 'N/A')}, Assigner: {advisory.get('assigner', 'N/A')}\n"
    
    # Add vulnerability information
    for vuln in relevant_data.get('vulnerabilities', []):
        context += f"Vulnerability: {vuln.get('cve_id', 'N/A')}, Description: {vuln.get('description', 'N/A')}, Severity: {vuln.get('severity', 'N/A')}\n"
    
    # Add fixes information
    for fix in relevant_data.get('fixes', []):
        context += f"Fix ID: {fix.get('fix_id', 'N/A')}, Description: {fix.get('fix_description', 'N/A')}, Fixed Product ID: {fix.get('fixed_product_id', 'N/A')}\n"
    
    # Add products information
    for product in relevant_data.get('products', []):
        context += f"Product ID: {product.get('product_id', 'N/A')}, Name: {product.get('product_name', 'N/A')}, Version: {product.get('version', 'N/A')}, Vendor ID: {product.get('vendor_id', 'N/A')}, Release Date: {product.get('release_date', 'N/A')}\n"
    
    # Add vendors information
    for vendor in relevant_data.get('vendors', []):
        context += f"Vendor ID: {vendor.get('vendor_id', 'N/A')}, Name: {vendor.get('vendor_name', 'N/A')}, Contact Info: {vendor.get('contact_info', 'N/A')}\n"
    
    return context

# Generate response using OpenAI API (using chat model)
def generate_sbom_response(query, relevant_data):
    # Generate context for LLM prompt
    context = generate_context(relevant_data)
    
    # Customize the prompt to request specific information
    messages = [
        {"role": "system", "content": "You are an assistant that helps with software security advisories."},
        {"role": "user", "content": f"Given the following SBOM data:\n{context}\nPlease provide detailed recommendations for mitigating the identified vulnerabilities."}
    ]
    
    openai.api_key = OPENAI_API_KEY
    response = openai.ChatCompletion.create(
        model="gpt-4-turbo",
        messages=messages,
        max_tokens=300  # Increased token limit for detailed response
    )
    return response.choices[0].message['content'].strip()

# RAG system function
def rag_sbom_response(query, session):
    # Retrieval: Fetch relevant data from the database
    relevant_data = fetch_relevant_sbom_data(session, query)
    
    # If relevant data is found in the database, use it; otherwise, use LLM to generate a response
    if relevant_data:
        print("Retrieving data from the database...")
        context = generate_context(relevant_data)
        return context
    else:
        print("No relevant data found in the database, querying LLM...")
        response = generate_sbom_response(query, {})
        return response

# Main function to execute the RAG system with user input
def main():
    engine, session = connect_to_db()
    
    # Get query from user input
    query = input("Enter your query regarding SBOM vulnerabilities and fixes: ")
    
    try:
        # Execute RAG system
        response = rag_sbom_response(query, session)
        print("Response:")
        print(response)
    except Exception as e:
        print(f"An error occurred: {e}")
        # Provide a fallback response using GPT-3.5 model for non-database queries
        openai.api_key = OPENAI_API_KEY
        fallback_prompt = "Please provide general information or recommendations on software security advisories."
        fallback_response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are an assistant that provides general information about software security."},
                {"role": "user", "content": fallback_prompt}
            ],
            max_tokens=150
        )
        print("Fallback response from GPT-3.5:")
        print(fallback_response.choices[0].message['content'].strip())
    
    session.close()

if __name__ == "__main__":
    main()
 