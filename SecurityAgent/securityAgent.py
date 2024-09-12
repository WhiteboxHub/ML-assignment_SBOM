from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import time
from typing import List ,Dict,Optional
app = FastAPI(
    title="Security Agent API",
    description="An API to analyze SBOMs by querying the NVD for vulnerabilities.",
    version="1.0.0"
)

class Cpe(BaseModel):
    cpe: str
    source: Optional[str]

class Artifact(BaseModel):
    id: str
    name: str
    version: str
    type: str
    foundBy: str
    locations: List[Dict]
    licenses: List
    language: str
    cpes: List[Cpe]
    purl: str
    metadataType: str
    metadata: Dict

class AnalyzeSbom(BaseModel):
    artifacts: List[Artifact]
    artifactRelationships: List[Dict]
    files: List[Dict]
    source: Dict
    distro: Dict
    descriptor: Dict
    schema: Dict

class AnalyzeSBOMRequest(BaseModel):
    package_name : str
    cpe : str
    cveid: str
    

@app.post('/analyze_sbom')
async def analyze_sbom(request : AnalyzeSbom ):
    """
    Endpoint to analyze an SBOM by querying the NVD for vulnerabilities.

    Args:
        request (AnalyzeSBOMRequest): The request containing the package name.

    Returns:
        dict: JSON response containing vulnerabilities with their IDs and descriptions.
    """
    print('called the function')
    cpesData = {}
    cpes = request.artifacts[0].cpes
    for cpe in cpes:
        cpe_value = cpe.cpe
        cpesData[cpe_value] = []
        analyze_sbom_data = check_vulnerabilities(cpe_value)
        cpesData[cpe_value].append(analyze_sbom_data)
    
    
    return cpesData
def get_vulnerabilities_from_nvd(cpe_name):
    """Query the NVD API for vulnerabilities using CPE name."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}"
    try:
        print(f'Creating requestion to get vulnerabilities for {cpe_name}')
       
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        # with open(f'{name}.json', 'w') as json_file:
        #     json.dump(response.json(), json_file, indent=4)  # indent=4 for pretty printing
        # print(f"Data saved to {name}.json")
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