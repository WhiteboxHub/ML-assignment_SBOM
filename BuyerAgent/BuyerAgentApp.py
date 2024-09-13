import streamlit as st
import requests

# Streamlit app layout
st.title("Buyer Agent Application")
st.write("Enter your Product Id to get SBOM of Product")

# Input from the user
user_input = st.text_input("Enter Product ID")

# Initialize session state for storing SBOM data and analysis results
if 'sbomdata' not in st.session_state:
    st.session_state.sbomdata = None

if 'vulnerability' not in st.session_state:
    st.session_state.vulnerability = None

# Button to submit input
if st.button("Call API"):
    if user_input:
        st.write(f"Calling API with input: {user_input}")

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
            st.session_state.vulnerability = response.json()
            st.json(response.json())
              # Store analysis results in session state
            st.success("Analysis Completed")
            
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
                # You can add functionality here to analyze the score
                st.write(f"Button clicked for CVE ID: {vulnerability_id}")
                # Add further functionality if needed
    else:
        st.write("No vulnerabilities found.")
