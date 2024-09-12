from fastapi import FastAPI, HTTPException,Request
from pydantic import BaseModel,Field
import requests
import time
from typing import List ,Dict,Optional
app = FastAPI(
    title="Security Agent API",
    description="An API to analyze SBOMs by querying the NVD for vulnerabilities.",
    version="1.0.0"
)


class AnalyzeSBOMRequest(BaseModel):
    cveid: str
    

@app.post('/analyze_sbom_vulneribilitys/')
async def analyze_sbom(request : Request ):
    """
    Endpoint to analyze an SBOM by querying the NVD for vulnerabilities.

    Args:
        The request containing the package name.

    Returns:
        dict: JSON response containing vulnerabilities with their IDs and descriptions.
    """
    cpesData = {}
    Sbom_json_data = await request.json()
    cpes = Sbom_json_data.get('artifacts')[0].get('cpes')
    print(cpes)
    for cpe in cpes:
        cpe_value = cpe.get('cpe')
        cpesData[cpe.get('source')] = []
        analyze_sbom_data = check_vulnerabilities(cpe_value)
        cpesData[cpe.get('source')].append(analyze_sbom_data)
    return cpesData


def get_vulnerabilities_from_nvd(cpe_name):
    """Query the NVD API for vulnerabilities using CPE name."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}"
    try:
        print(f'Creating requestion to get vulnerabilities for {cpe_name}')
       
        response = requests.get(url)
        response.raise_for_status() 
        print('GetVulnerabilities exicution completed')
        return response.json().get('vulnerabilities', [])
    except requests.RequestException as e:
        # logging.error(f"Error fetching data from NVD: {e}")
        print('error in get_vulnerabilities_from_nvd', e)
        return []
def check_vulnerabilities(cpe):
    """Check the SBOM dependencies for known vulnerabilities."""
    vulnerabilities_info = {}
    print(f"Checking vulnerabilities for {cpe}...")
    cve_list = get_vulnerabilities_from_nvd(cpe)
    time.sleep(1)  # Rate limit to avoid hitting API limits
    vulnerabilities = cve_list
    vulnerabilities_info['vulnerabilities'] = []
    for vulnerabilitie in vulnerabilities:
        cve_info = vulnerabilitie.get('cve', {})
        cve_id = cve_info.get('id', 'Unknown')
        cve_description = cve_info.get('descriptions', [{}])[0].get('value', 'No description available')
        
        vulnerabilities_info['vulnerabilities'].append({
            'CVE ID': cve_id,
            'Description': cve_description
        })
    return vulnerabilities_info



@app.post('/assess_vulnerability')
async def assess_vulnerability(request:AnalyzeSBOMRequest):
    """
    Endpoint to assess a specific vulnerability by its ID.

    Args:
        request (AssessVulnerabilityRequest): The request containing the vulnerability ID.

    Returns:
        dict: JSON response containing the assessment of the vulnerability.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={request.cveid}"

    try:
       
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
       
        vulnerabilities = response.json().get('vulnerabilities', [])
        check_vulnerabilities_score = check_vulnerabilities_info(vulnerabilities,request.cveid)
        return check_vulnerabilities_score
    except requests.RequestException as e:
        # logging.error(f"Error fetching data from NVD: {e}")
        print('error in get_vulnerabilities_from_nvd', e)
        return []

def check_vulnerabilities_info(vulnerability,cveid):
    """Check the SBOM dependencies for known vulnerabilities."""
    
    vulnerabilities_info = {}
    time.sleep(1)  # Rate limit to avoid hitting API limits
    vulnerabilities = vulnerability
    vulnerabilities_info[cveid] = []
    
    cve_info = vulnerabilities[0].get('cve', {})
    cve_id = cve_info.get('id', 'Unknown')
    cve_description = cve_info.get('descriptions', [{}])[0].get('value', 'No description available')
    metrics = cve_info.get('metrics', {})
    cvss_metric_v2 = metrics.get('cvssMetricV2', metrics.get('cvssMetricV31',[{}]))[0]
    cvss_score = cvss_metric_v2.get('cvssData', {}).get('baseScore', 'N/A')
    baseSeverity = cvss_metric_v2.get('baseSeverity')
    cve_exploitabilityScore = cvss_metric_v2.get('exploitabilityScore')
    cve_impactScore = cvss_metric_v2.get('impactScore')
    vulnerabilities_info[cve_id].append({
        'CVE ID': cve_id,
        'Description': cve_description,
        'CVSS Score': cvss_score,
        'cve_impactScore':cve_impactScore,
        'cve_exploitabilityScore':cve_exploitabilityScore,
        'baseSeverity':baseSeverity
    })
        
       


    return vulnerabilities_info