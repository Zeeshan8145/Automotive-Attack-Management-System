
import os
import asyncio 
import httpx
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


# Address of the internal attack lookup service.
LOOKUP_SERVICE_URL = os.getenv(
    "LOOKUP_SERVICE_URL",
    "http://internal-attack-lookup:8000",
)

# Address of the external CVE lookup microservice.
CVE_SERVICE_URL = os.getenv(
    "CVE_SERVICE_URL",
    "http://cve-lookup:8000",
)

# Create the frontend application.
app = FastAPI(title="Threat And Risk Assessment Dashboard")

# Configure HTML templates and static files.
templates = Jinja2Templates(directory="app/templates")

app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static",
)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    # Default values keep the dashboard available if lookup fails.
    statistics = {
        "known_attacks": 0,
        "cached_cves": 0,
        "pending_lookups": 0,
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                f"{LOOKUP_SERVICE_URL}/stats"
            )
            response.raise_for_status()
            statistics.update(response.json())

    except (httpx.HTTPError, ValueError):
        pass

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "title": "Threat Analysis Dashboard",
            **statistics,
        },
    )


@app.get("/search", response_class=HTMLResponse)
async def search_attacks(request: Request, query: str = ""):
    query = query.strip()

    # Separate internal attack results from external CVE results.
    results = []
    result_type = None
    error = None

    if query:
        try:
            # First, search our own automotive attack database.
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{LOOKUP_SERVICE_URL}/attacks/search",
                    params={"query": query},
                )
                response.raise_for_status()
                results = response.json().get("results", [])

            if results:
                # Internal records take priority.
                result_type = "attacks"

            else:
                # Only query the CVE service if no internal match exists.
                async with httpx.AsyncClient(timeout=20.0) as client:
                    response = await client.get(
                        f"{CVE_SERVICE_URL}/cves/search",
                        params={"query": query},
                    )
                    response.raise_for_status()
                    results = response.json().get("results", [])

                result_type = "cves"

        except httpx.TimeoutException:
            error = "A lookup service took too long to respond."

        except httpx.HTTPStatusError as exc:#HTTP Errors
            if exc.request.url.host == "cve-lookup":
                error = "The CVE lookup service returned an error."
            elif str(exc.request.url).startswith(CVE_SERVICE_URL):
                error = "The CVE lookup service returned an error."
            else:
                error = "The internal attack lookup service returned an error."

        except httpx.RequestError as exc: #Request Erris at network or if a connection breaks 
            if str(exc.request.url).startswith(CVE_SERVICE_URL):
                error = "The CVE lookup service is temporarily unavailable."
            else:
                error = "The internal attack lookup service is temporarily unavailable."

        except ValueError:
            error = "A lookup service returned an invalid response."

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "title": "Threat Analysis Dashboard",
            "known_attacks": 0,
            "cached_cves": 0,
            "pending_lookups": 0,
            "query": query,
            "results": results,
            "result_type": result_type,
            "error": error,
        },
    )
@app.get("/search-cves", response_class=HTMLResponse)
async def search_cves(request: Request, query: str = ""):
    query = query.strip()

    results = []
    error = None

    if not query:
        error = "Enter a keyword or CVE ID to search the CVE database."
    else:
        try:
            # Search the external CVE lookup microservice directly.
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(
                    f"{CVE_SERVICE_URL}/cves/search",
                    params={"query": query},
                )
                response.raise_for_status()
                results = response.json().get("results", [])

        except httpx.TimeoutException:
            error = "The CVE lookup service took too long to respond."

        except httpx.HTTPStatusError:
            error = "The CVE lookup service returned an error."

        except httpx.RequestError:
            error = "The CVE lookup service is temporarily unavailable."

        except ValueError:
            error = "The CVE lookup service returned an invalid response."

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "title": "Threat Analysis Dashboard",
            "known_attacks": 0,
            "cached_cves": 0,
            "pending_lookups": 0,
            "query": query,
            "results": results,
            "result_type": "cves",
            "search_mode": "cve",
            "error": error,
            "approval_message": None,
        },
    )

@app.post("/approve-cve", response_class=HTMLResponse)
async def approve_cve(
    request: Request,
    cve_id: str = Form(...),
    title: str = Form(...),
    description: str = Form(""),
    keywords: str = Form(""),
    applicable_ecu: str = Form(...),
):
    keyword_list = [
        keyword.strip()
        for keyword in keywords.split(",")
        if keyword.strip()
    ]

    ecu_list = [
        ecu.strip()
        for ecu in applicable_ecu.split(",")
        if ecu.strip()
    ]

    payload = {
        "cve_id": cve_id.strip(),
        "title": title.strip(),
        "description": description.strip(),
        "keywords": keyword_list,
        "applicable_ecu": ecu_list,
    }

    # Default values ensure that error responses can render the page.
    error = None
    approval_message = None
    results = []
    result_type = None
    display_query = cve_id

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:

            # Submit the approved CVE to the internal service to quw a job
            response = await client.post(
                f"{LOOKUP_SERVICE_URL}/attacks/from-cve",
                json=payload,
            )
            response.raise_for_status()
            job_result = response.json()
            job_id = job_result.get("job_id")

            if not job_id:
                raise ValueError("The response did not contain a job ID")

            job_status = None

            for attempt in range(40):
                await asyncio.sleep(3)
                status_response = await client.get(
                    f"{LOOKUP_SERVICE_URL}/jobs/{job_id}"
                )
                status_response.raise_for_status()
                job_status = status_response.json()
                if job_status.get("status") == "Completed":
                    break
                if job_status.get("status") == "Failed":
                    error = (
                        "Background processing failed. "
                        "Please check the worker logs before retrying."
                    )
                    break
            if job_status and job_status.get("status") == "Completed":
                attack_id = job_status.get("attack_id")

                # Retrieve the saved attack so the dashboard can display and its threat score and other fields generated by the worker.
                attack_response = await client.get(
                    f"{LOOKUP_SERVICE_URL}/attacks/search",
                    params={"query": attack_id},
                )
                attack_response.raise_for_status()
                attack_result = attack_response.json()

                attack_results = attack_result.get("results", [])

                
                if attack_results:
                    attack = attack_results[0]
                else:
                    raise ValueError(
                        "The completed attack record was not returned"
                    )

                
                results = [attack]
                result_type = "attacks"
                display_query = attack_id
                approval_message = (
                    "CVE approved and processed successfully. "
                    f"New internal Attack ID: {attack_id}"
                )

            
            elif error is None:
                approval_message = (
                    "The CVE approval job is queued or still processing. "
                    f"Job ID: {job_id}. Please check again shortly."
                )

    except httpx.HTTPStatusError as exc:
        
        if exc.response.status_code == 409:
            error = (
                "This CVE may already be registered. "
                "Search by its CVE ID or check the existing attack records."
            )
        else:
            error = (
                "The internal service returned an error while "
                "submitting or checking the background job."
            )

    except httpx.RequestError:
        # Handle network errors between the frontend and internal service.
        error = "The internal attack service is temporarily unavailable."

    
    except (ValueError, KeyError, TypeError) as exc:
        # Loggingbthe original exception to help diagnose unexpected responses. Added becasue i saw an intermittent 502 error but couldnt repsorce it after 
        import logging
        logging.exception("Unexpected response while approving CVE")

        
        error = f"The service returned an unexpected response: {exc}"


    
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "title": "Threat Analysis Dashboard",
            "known_attacks": 0,
            "cached_cves": 0,
            "pending_lookups": 0,
            "query": display_query,
            "results": results,
            "result_type": result_type,
            "search_mode": "cve",
            "error": error,
            "approval_message": approval_message,
        },
        status_code=502 if error else 200,
    )


@app.get("/health")
async def health():
    return {"status": "healthy"}
