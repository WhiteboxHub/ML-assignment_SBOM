from fastapi import FastAPI, HTTPException, status,Request
import requests
from pydantic import BaseModel
from typing import Any,Dict,Optional,List
import json
import httpx
app = FastAPI()

class SBOMRequest(BaseModel):
    product_id: int

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


@app.get('/')
def func():
    return {'hello':'api is working'}

@app.post('/get_sbom')
async def Get_sbom_data(request: SBOMRequest):
    """
    Endpoint to receive a message from the Buyer API and route it to the Vendor API.

    Args:
        request (RouteMessageRequest): The request containing sender, recipient, and product_id.

    Returns:
        dict: JSON response from the Vendor API.
    """
    try:
        # Route the message to the Vendor API running on localhost:8081
        vendor_api_url = "http://vendoragent:8083/generate-sbom/"
        response = requests.post(vendor_api_url, json={"product_id": request.product_id})
        # Check for errors in response from Vendor API
        response.raise_for_status()
        return response.json()

    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error communicating with Vendor API: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.post('/acess_sbom/')
async def access_sbom(sbomdata : Request):
    """"
    End point to receive a message Sbom json data from buyer and rout it to the security api api
    Returns: 
    dict : json response from the vendor api
    """
    try:
        headers = {'Content-Type': 'application/json'}
        Sbom_json = await sbomdata.json()
        security_access_sbom_url = "http://securityagent:8084/analyze_sbom_vulneribilitys"
        response = requests.post(security_access_sbom_url, json=Sbom_json)
       
        response.raise_for_status()

        return {
            "details":"SBOM Vulinerabities acessed",
            "data":response.json()
        }

    except requests.RequestException as e:
        raise HTTPException(status_code=501, detail=f"Error communicating with Vendor API: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=e)


@app.get('/get_vulnerability_score')
def get_vulnerability_score_endpoint(cveid:str):
    try:
        security_Vulnerability_score_endpoint = "http://securityagent:8084/assess_vulnerability"
        data = {
            'cveid':cveid
        }
        response = requests.post(security_Vulnerability_score_endpoint, json=data)
        response.raise_for_status()
        return {
            "details":"Vulinerabities Score acessed",
            "data":response.json()
        }
    except requests.RequestException as e:
        raise HTTPException(status_code=501, detail=f"Error communicating with Vendor API: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=e)
    