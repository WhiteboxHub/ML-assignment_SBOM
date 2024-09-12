from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests

app = FastAPI(
    title="Buyer API",
    description="An API for buyers to request SBOMs from vendors through the Integration API.",
    version="1.0.0"
)

class RequestSBOMRequest(BaseModel):
    vendor_id: int
    product_ids: list[str]


async def request_sbom(request : RequestSBOMRequest):
    """
    Endpoint for buyers to request SBOMs from vendors through the Integration API.

    Args:
        request (RequestSBOMRequest): The request containing vendor_id and product_ids.

    Returns:
        dict: JSON response from the Integration API.
    """
    try:
        # Call the Integration API to route the message to the Vendor API
        integration_api_url = "http://localhost:8082/route_message/"
        security_agent_api_url = "http://localhost:8084/analyze_sbom/"
        sbom_analysis_results = []
        
        for product_id in request.product_ids:
            data = {
                "sender": "Buyer API",
                "recipient": "Vendor API",
                "product_id": product_id
            }
            
            # Request SBOM from Integration API
            response = requests.post(integration_api_url, json=data)
            response.raise_for_status()
            sbom = response.json()

            # Analyze the SBOM by calling Security Agent API
            analyze_response = requests.post(security_agent_api_url, json={"package_name": product_id})
            analyze_response.raise_for_status()
            analysis_result = analyze_response.json()
            sbom_analysis_results.append(analysis_result)

        return {
            "message": "SBOM requests sent to Vendor API and analyzed successfully.",
            "analysis_results": sbom_analysis_results
        }

    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error communicating with APIs: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))