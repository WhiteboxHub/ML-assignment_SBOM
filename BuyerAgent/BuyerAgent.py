
from fastapi import FastAPI, HTTPException,Request
from pydantic import BaseModel
from typing import Dict,Any
import requests
import json
app = FastAPI(
    title="Buyer API",
    description="An API for buyers to request SBOMs from vendors through the Integration API and assess risks.",
    version="1.1.0"
)

class RequestSBOMRequest(BaseModel):
    # vendor_id: int
    product_id: int

# class AssessRiskRequest(BaseModel):
#     sbom: dict
#     vex: dict
@app.get('/')
def api_start():
    return {'hello':"this is buyer agent"}
@app.post("/request_sbom/")
async def request_sbom(request: RequestSBOMRequest):
    """
    Endpoint for buyers to request SBOMs from vendors through the Integration API.

    Args:
        request (RequestSBOMRequest): The request containing vendor_id and product_ids.

    Returns:
        dict: JSON response containing the SBOM analysis results.
    """

    try:
        sbom_json_data = await request.json()
        sbom_analysis_results = []
        integration_agent_url = 'http://integrationagent:8082/get_sbom'
        data = {"product_id":request.product_id}
        response = requests.post(integration_agent_url,json=data)
        response.raise_for_status()

        return {
            "message": "SBOM requests sent to Vendor API and analyzed successfully.",
            "sbom_data": response.json()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/assess_sbom_risk/")
async def assess_risk(sbomdata: Request):
    """
    Endpoint to assess the risk of an SBOM using a VEX document by calling the Security Agent API.

    Args:
        request (AssessRiskRequest): The request containing the SBOM and VEX document.

    Returns:
        dict: JSON response containing the risk assessment.
    """
    try:
       
       jsonsbom = await sbomdata.json()
       
       assess_sbom_risk_integration_agent_url = "http://integrationagent:8082/acess_sbom/"
       response = requests.post(assess_sbom_risk_integration_agent_url,json=jsonsbom)
        # Check for errors in response from Vendor API
       response.raise_for_status()
       return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

