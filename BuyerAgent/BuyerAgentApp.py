import streamlit as st
import requests

# Streamlit app layout
st.title("Buyer Agent Application")
st.write("Enter your Product Id to get SBOM of Product")

# Input from the user
user_input = st.text_input("Enter Product ID")

# Initialize session state for storing SBOM data, analysis results, and individual vulnerability scores
if 'sbomdata' not in st.session_state:
    st.session_state.sbomdata = None

if 'vulnerability' not in st.session_state:
    st.session_state.vulnerability = None

if 'analyzed_vulnerabilities' not in st.session_state:
    st.session_state.analyzed_vulnerabilities = {}

# Button to request SBOM data
if st.button("Request SBOM"):
    if user_input:
        st.write(f"Calling SBOM API with Product ID: {user_input}")

        try:
            integration_agent_url = 'http://integrationagent:8082/get_sbom'
            data = {"product_id": user_input}
            response = requests.post(integration_agent_url, json=data)
            response.raise_for_status()
            sbomdata = response.json()
            st.session_state.sbomdata = sbomdata  # Store SBOM data in session state
            st.success("API Response Received")
        except requests.exceptions.RequestException as e:
            st.error(f"API call failed: {e}")

# Display SBOM data if available
if st.session_state.sbomdata:
    with st.expander("Expand SBOM JSON data"):
        st.json(st.session_state.sbomdata)

    # Analyze SBOM button, visible only if sbomdata is available
    if st.button("Analyze SBOM"):
        try:
            assess_sbom_risk_integration_agent_url = "http://integrationagent:8082/acess_sbom/"
            response = requests.post(assess_sbom_risk_integration_agent_url, json=st.session_state.sbomdata)
            response.raise_for_status()
            st.session_state.vulnerability = response.json()  # Store analysis results in session state
            st.success("Analysis Completed")
            st.json(st.session_state.vulnerability)  # Display the full analysis result
        except requests.exceptions.RequestException as e:
            st.error(f"API call failed: {e}")

# Display analysis results if available
if st.session_state.vulnerability:
    vulnerabilities = st.session_state.vulnerability.get('data', {}).get('vulnerabilities', [])
    if vulnerabilities:
        st.write("Vulnerability Analysis Results:")
        
        # Iterate through each vulnerability and create a UI layout
        for vulnerability in vulnerabilities:
            vulnerability_id = vulnerability.get('CVE ID', 'Unknown ID')
            description = vulnerability.get('Description', 'No description available')
            
            st.write(f"**Vulnerability ID**: {vulnerability_id}")
            st.write(f"**Description**: {description}")
            
            # Add an "Analyze Vulnerability Score" button
            if st.button(f"Analyze Vulnerability Score for {vulnerability_id}"):
                try:
                    access_vulnerability_score = f"http://integrationagent:8082/get_vulnerability_score/?cveid={vulnerability_id}"
                    response = requests.get(access_vulnerability_score)
                    response.raise_for_status()
                    
                    # Store the result in session state using the vulnerability ID as a key
                    st.session_state.analyzed_vulnerabilities[vulnerability_id] = response.json()
                    st.success(f"Analysis Completed for {vulnerability_id}")
                    with st.expander("vulnerability Score"):
                        st.json(st.session_state.analyzed_vulnerabilities[vulnerability_id])
                    
                    
                except requests.exceptions.RequestException as e:
                    st.error(f"API call failed: {e}")

# Display all analyzed vulnerability scores
for vulnerability_id, score_data in st.session_state.analyzed_vulnerabilities.items():
    with st.expander(f"{vulnerability_id} Vulnerability Score"):
        st.json(score_data)
