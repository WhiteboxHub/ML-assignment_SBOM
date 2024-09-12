
from fastapi import FastAPI, HTTPException
import subprocess
import json
import os
from pydantic import BaseModel
from typing import List

app = FastAPI()

# In-memory storage for product statuses (simulated database)
product_statuses = {}

class RequestInfo(BaseModel):
    product_id: int

class FixRequestInfo(BaseModel):
    product_id: int
    vulnerability_ids: List[int]

class StatusUpdateInfo(BaseModel):
    product_id: int
    status: str

def generate_sbom(package_path, output_format='json'):
    """
    Generate SBOM for a given software package using syft.

    Args:
        package_path (str): Path to the software package or container image.
        output_format (str): Format of the SBOM output (json, table, etc.). Default is 'json'.

    Returns:
        dict: The SBOM output as a dictionary in the specified format.
    """
    try:
        # Build the syft command
        command = ['syft', package_path, f'-o={output_format}']
        
        # Execute the command and capture the output
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Parse the JSON output to a Python dictionary
        sbom_data = json.loads(result.stdout)
        
        # Return the SBOM output
        return sbom_data
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error generating SBOM: {e.stderr}")
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Error parsing JSON output: {e}")

@app.post("/generate-sbom/")
async def generate_sbom_endpoint(request: RequestInfo):
    """
    Endpoint to generate SBOM for a selected JAR file based on the product_id.

    Args:
        request (RequestInfo): The request payload containing product_id.

    Returns:
        dict: JSON response containing the SBOM.
    """
    try:
        # Set the base path where JAR files are located within the Docker container
        base_path = "/app/packages/"

        # Map product_id to the corresponding JAR file
        if request.product_id == 100:
            file_location = os.path.join(base_path, "log4j-nosql-2.3.2-javadoc.jar")
        elif request.product_id == 200:
            file_location = os.path.join(base_path, "log4j-web-2.3.2-javadoc.jar")
        elif request.product_id == 300:
           file_location = os.path.join(base_path, "openssl-1_1_1s.jar")
        elif request.product_id == 400:
            file_location = os.path.join(base_path, "poi-5.3.0.jar")
        elif request.product_id == 500:
            file_location = os.path.join(base_path, "log4j-core-3.0.0-beta2.jar")
        elif request.product_id == 600:
            file_location = os.path.join(base_path, "kotlin-stdlib-1.4.21.jar")
        else:
            raise HTTPException(status_code=400, detail="Invalid product_id. Please provide 100 or 200.")

        # Check if the file exists in the specified location
        if not os.path.exists(file_location):
            raise HTTPException(status_code=404, detail=f"File {file_location} not found.")

        # Generate SBOM for the selected JAR file
        sbom_data = generate_sbom(file_location)

        return sbom_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/acknowledge-fix-request/")
async def acknowledge_fix_request(request: FixRequestInfo):
    """
    Endpoint to acknowledge a fix request.

    Args:
        request (FixRequestInfo): The request payload containing product_id and vulnerability_ids.

    Returns:
        dict: JSON response confirming the acknowledgment of the fix request.
    """
    try:
        # Log the fix request (simulating database or external service interaction)
        print(f"Acknowledging fix request for product_id {request.product_id} with vulnerabilities {request.vulnerability_ids}")

        # For simulation purposes, we'll assume the acknowledgment was successful
        return {"message": f"Fix request acknowledged for product_id {request.product_id} with vulnerabilities {request.vulnerability_ids}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/update-product-status/")
async def update_product_status(request: StatusUpdateInfo):
    """
    Endpoint to update the status of a product.

    Args:
        request (StatusUpdateInfo): The request payload containing product_id and status.

    Returns:
        dict: JSON response confirming the status update.
    """
    try:
        # Update the product status in the in-memory dictionary
        product_statuses[request.product_id] = request.status

        # Log the status update (simulating database or external service interaction)
        print(f"Updated status for product_id {request.product_id} to '{request.status}'")

        return {"message": f"Product status updated for product_id {request.product_id} to '{request.status}'"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)