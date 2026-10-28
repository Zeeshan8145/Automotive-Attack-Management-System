import os
import uuid # Generate unique identifiers for background-processing jobs.
from datetime import datetime, timezone # Record job creation and update times in UTC.
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field #for validcaiona attakc recoded
from pymongo import MongoClient, ASCENDING, ReturnDocument
from pymongo.errors import PyMongoError, DuplicateKeyError
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
#Creating MongoDB client and timeout to make there is no hanging if connection fails
client = MongoClient(
    MONGO_URL,
    serverSelectionTimeoutMS=3000,
)

db = client["automotive_cybersecurity"]
# Store CVE approval jobs for the background worker to process.
jobs = db["attack_jobs"]

@asynccontextmanager
async def lifespan(app: FastAPI):
    client.admin.command("ping")

    db.known_attacks.create_index(
        [("attack_id", ASCENDING)],
        unique=True,
    )

    db.cve_cache.create_index(
        [("cve_id", ASCENDING)],
        unique=True,
    )

    
    db.pending_lookups.create_index(
        [("status", ASCENDING)],
    )

    # Ensure that every background job has a unique job identifier.
    jobs.create_index(
        [("job_id", ASCENDING)],
        unique=True,
    )

    # Help the worker find jobs by status 
    jobs.create_index(
        [("status", ASCENDING), ("created_at", ASCENDING)],
    )


    existing_ids = db.known_attacks.find(
        {
            "attack_id": {
                "$regex": r"^AUTO-ATTACK-\d+$"
            }
        },
        {"attack_id": 1, "_id": 0},
    )

    highest_id = max(
        (
            int(record["attack_id"].rsplit("-", 1)[1])
            for record in existing_ids
        ),
        default=0,
    )

    # Initialize the counter if missing, without resetting an existing counter.
    db.attack_id_counters.update_one(
        {"_id": "internal_attack"},
        {"$setOnInsert": {"sequence": highest_id}},
        upsert=True,
    )

    
    counter_document = db.attack_id_counters.find_one(
        {"_id": "internal_attack"}
    )

    
    if counter_document is None:
        raise RuntimeError("Could not initialize the Attack ID counter")

    try:
    
        yield
    finally:
        client.close()


app = FastAPI(
    title="Automotive Attack Lookup Service",
    description="Search and manage the internal cybersecurity attack database.",
    version="1.0.0",
    lifespan=lifespan,
)


class AttackCreate(BaseModel):
    attack_id: str = Field(min_length=1, max_length=50)
    title: str = Field(min_length=1, max_length=250)
    description: str = ""
    keywords: list[str] = Field(default_factory=list)
    applicable_ecu: list[str] = Field(default_factory=list)

class ApprovedCVEAttack(BaseModel):
    # The original CVE identifier remains a separate reference.
    cve_id: str = Field(
        pattern=r"^CVE-\d{4}-\d{4,}$"
    )

    # These fields describe the internal automotive attack record.
    title: str = Field(min_length=1, max_length=250)
    description: str = ""
    keywords: list[str] = Field(default_factory=list)
    applicable_ecu: list[str] = Field(default_factory=list)

@app.get("/health")
def health():
    try:
        client.admin.command("ping")
        return {
            "status": "healthy",
            "database": "connected",
        }

    except PyMongoError:
        raise HTTPException(
            status_code=503,
            detail="MongoDB is unavailable",
        )



@app.get("/stats")
def stats():
    try:
        return {
            "known_attacks": db.known_attacks.count_documents({}),
            "cached_cves": db.cve_cache.count_documents({}),
            "pending_lookups": db.pending_lookups.count_documents({}),
        }

    except PyMongoError:
        raise HTTPException(
            status_code=503,
            detail="Could not retrieve database statistics",
        )




@app.post("/attacks", status_code=201)
def create_attack(attack: AttackCreate):
    # Convert the validated request into a regular Python dictionary.
    document = attack.model_dump()

    # Remove accidental whitespace around the internal identifier.
    document["attack_id"] = document["attack_id"].strip()
    # Remove extra whitespace and empty entries from the ECU list.
    document["applicable_ecu"] = [
        ecu.strip()
        for ecu in document["applicable_ecu"]
        if ecu.strip()
        ]

    # Reject an ID that becomes empty after trimming whitespace.
    if not document["attack_id"]:
        raise HTTPException(
            status_code=422,
            detail="Attack ID cannot be empty",
        )

    try:
        # Insert the new attack and capture MongoDB's generated ID.
        result = db.known_attacks.insert_one(document)

        # Retrieve the saved record using its MongoDB-generated ID.
        created_attack = db.known_attacks.find_one(
            {"_id": result.inserted_id}
        )

        # Convert ObjectId into a string that FastAPI can serialize as JSON.
        if created_attack is not None:
            created_attack["_id"] = str(created_attack["_id"])

        # Return the saved record to the client.
        return {
            "message": "Attack created",
            "attack": created_attack,
        }

    except DuplicateKeyError:
        raise HTTPException(
            status_code=409,
            detail="Attack ID already exists",
        )

    except PyMongoError:
        raise HTTPException(
            status_code=503,
            detail="Could not save attack",
        )



@app.post("/attacks/from-cve", status_code=202)
def create_attack_from_cve(attack: ApprovedCVEAttack):
    
    document = attack.model_dump()

    
    document["cve_id"] = document["cve_id"].strip().upper()
    document["title"] = document["title"].strip()


    document["applicable_ecu"] = [
        ecu.strip()
        for ecu in document["applicable_ecu"]
        if ecu.strip()
    ]

    
    document["keywords"] = [
        keyword.strip()
        for keyword in document["keywords"]
        if keyword.strip()
    ]

    
    if not document["title"]:
        raise HTTPException(
            status_code=422,
            detail="Attack title cannot be empty",
        )

    try:
        
        existing = db.known_attacks.find_one(
            {"cve_id": document["cve_id"]},
            {"_id": 0, "attack_id": 1},
        )

        
        if existing:
            raise HTTPException(
                status_code=409,
                detail=(
                    "This CVE is already linked to internal Attack ID "
                    + existing["attack_id"]
                ),
            )

        
        existing_job = jobs.find_one(
            {
                "payload.cve_id": document["cve_id"],
                "status": {"$in": ["Pending", "Processing"]},
            },
            {"_id": 0, "job_id": 1, "status": 1},
        )

        
        if existing_job:
            return {
                "message": "A background job already exists for this CVE",
                "job_id": existing_job["job_id"],
                "status": existing_job["status"],
            }

        
        job_id = str(uuid.uuid4())

        # Record the current time in UTC for job tracking.
        now = datetime.now(timezone.utc)

        
        job_document = {
            "job_id": job_id,
            "job_type": "create_internal_attack",
            "status": "Pending",
            "attempts": 0,
            "payload": document,
            "created_at": now,
            "updated_at": now,
        }

        
        jobs.insert_one(job_document)

        # Return the job identifier immediately; do not create the attack here.
        return {
            "message": "Approved CVE queued for background processing",
            "job_id": job_id,
            "status": "Pending",
        }

    
    except HTTPException:
        raise

    
    except DuplicateKeyError:
        raise HTTPException(
            status_code=409,
            detail="A duplicate background job was detected",
        )

    
    except PyMongoError:
        raise HTTPException(
            status_code=503,
            detail="Could not queue the approved CVE",
        )


@app.get("/jobs/{job_id}")
def get_job_status(job_id: str):
    try:
        # Find the job using its public identifier.
        job = jobs.find_one(
            {"job_id": job_id},
            {"_id": 0},
        )

        # Return 404 if no job matches the requested identifier.
        if job is None:
            raise HTTPException(
                status_code=404,
                detail="Background job not found",
            )

        
        return {
            "job_id": job["job_id"],
            "status": job["status"],
            "attempts": job.get("attempts", 0),
            "attack_id": job.get("attack_id"),
            "last_error": job.get("last_error"),
            "created_at": job.get("created_at"),
            "updated_at": job.get("updated_at"),
        }

    
    except HTTPException:
        raise

   
    except PyMongoError:
        raise HTTPException(
            status_code=503,
            detail="Could not retrieve background job status",
        )

    
@app.get("/attacks/search")
def search_attacks(
    query: str = Query(min_length=1, max_length=100)
):
    query = query.strip()
    if not query:
        raise HTTPException(
            status_code=400,
            detail="Search query cannot be empty",
        )

    try:
        attack = db.known_attacks.find_one(
            {"attack_id": query},
            {"_id": 0},
        )
        if attack:
            return {
                "source": "known_attacks",
                "count": 1,
                "results": [attack],
            }
        # Escape the query so special characters are treated literally in regex.
        from re import escape

        safe_query = escape(query)
        results = list(
            db.known_attacks.find(
                {
                    "$or": [
                        {
                            "title": {
                                "$regex": safe_query,
                                "$options": "i",
                            }
                        },
                        {
                            "description": {
                                "$regex": safe_query,
                                "$options": "i",
                            }
                        },
                        {
                            "keywords": {
                                "$regex": safe_query,
                                "$options": "i",
                            }
                        },
                    ]
                },
                {"_id": 0},
            ).limit(20)
        )
        return {
            "source": "known_attacks",
            "count": len(results),
            "results": results,
        }

    except PyMongoError:
        raise HTTPException(
            status_code=503,
            detail="Could not search the attack database",
        )


