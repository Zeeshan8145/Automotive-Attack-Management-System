import os
# Import re for validating CVE identifiers and matching whole words or phrases.
import re
import time
import logging
from datetime import datetime, timezone, timedelta
from pymongo import MongoClient, ASCENDING, ReturnDocument
from pymongo.errors import PyMongoError, DuplicateKeyError

MONGO_URL = os.getenv(
    "MONGO_URL",
    "mongodb://localhost:27017",
)

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "3"))

MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", "5"))

LEASE_SECONDS = int(os.getenv("LEASE_SECONDS", "60"))
WORKER_ID = os.getenv(
    "WORKER_ID",
    f"worker-{os.getpid()}",
)

client = MongoClient(
    MONGO_URL,
    serverSelectionTimeoutMS=5000,
)
db = client["automotive_cybersecurity"]
jobs = db["attack_jobs"]
attacks = db["known_attacks"]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def initialize_worker():
    client.admin.command("ping")
    jobs.create_index(
        [("status", ASCENDING), ("created_at", ASCENDING)]
    )

    jobs.create_index(
        [("lease_until", ASCENDING)]
    )
    attacks.create_index(
        [("cve_id", ASCENDING)],
        unique=True,
        partialFilterExpression={
            "cve_id": {"$type": "string"}
        },
    )

    existing_ids = attacks.find(
        {
            "attack_id": {
                "$regex": r"^AUTO-ATTACK-\d+$"
            }
        },
        {
            "attack_id": 1,
            "_id": 0,
        },
    )

    highest_id = max(
        (
            int(record["attack_id"].rsplit("-", 1)[1])
            for record in existing_ids
        ),
        default=0,
    )
    db.attack_id_counters.update_one(
        {"_id": "internal_attack"},
        {"$max": {"sequence": highest_id}},
        upsert=True,
    )
    logger.info("Worker initialized as %s", WORKER_ID)



def calculate_threat_score(cve_id, description):
    match = re.fullmatch(
        r"CVE-(\d{4})-\d{4,}",
        cve_id,
        flags=re.IGNORECASE,
    )
    if not match:
        raise ValueError("Invalid CVE ID")
    year = int(match.group(1))

    current_year = datetime.now(timezone.utc).year
    if year < 2000:
        year_points = 2
    elif year <= 2004:
        year_points = 3
    elif year <= 2014:
        year_points = 4
    elif year <= current_year:
        year_points = 5
    else:
        raise ValueError(
            "CVE year cannot be later than the current year"
        )

    text = description or ""

    breakdown = {
        "cve_year": {
            "year": year,
            "points": year_points,
        },
        "description_rules": [],
    }

    total = year_points

    if re.search(
        r"\b(remote attack|automotive attack)\b",
        text,
        flags=re.IGNORECASE,
    ):
       
        total += 3

   
        breakdown["description_rules"].append({
            "rule": "remote attack or automotive attack",
            "points": 3,
        })
    if re.search(
        r"\b(root access|privilege)\b",
        text,
        flags=re.IGNORECASE,
    ):
     
        total += 2

       
        breakdown["description_rules"].append({
            "rule": "root access or privilege",
            "points": 2,
        })

    return {
        "threat_score": total,
        "threat_score_breakdown": breakdown,
        "threat_score_calculated_at": datetime.now(timezone.utc),
    }



def recover_abandoned_jobs():
    now = datetime.now(timezone.utc)


    expired_jobs = jobs.find({
        "status": "Processing",
        "lease_until": {"$lte": now},
    })

    for job in expired_jobs:

        attempts = job.get("attempts", 0)

     
        new_status = (
            "Failed" if attempts >= MAX_ATTEMPTS else "Pending"
        )

        jobs.update_one(
            {
                "_id": job["_id"],
                "status": "Processing",
                "lease_until": {"$lte": now},
            },
            {
                "$set": {
                    "status": new_status,
                    "last_error": "Worker lease expired",
                    "updated_at": now,
                },
                # Remove ownership and lease information because the
                # previous worker no longer owns this job.
                "$unset": {
                    "lease_until": "",
                    "claimed_by": "",
                },
            },
        )


def claim_job():
    now = datetime.now(timezone.utc)

    return jobs.find_one_and_update(
        {
            "status": "Pending",
            "attempts": {"$lt": MAX_ATTEMPTS},
        },
        {
            "$set": {
                "status": "Processing",
                "claimed_by": WORKER_ID,
                "claimed_at": now,
            
                "lease_until": now + timedelta(
                    seconds=LEASE_SECONDS
                ),
                "updated_at": now,
            },
  
            "$inc": {
                "attempts": 1,
            },
        },
 
        sort=[("created_at", ASCENDING)],

        return_document=ReturnDocument.AFTER,
    )




def generate_attack_id():
    counter = db.attack_id_counters.find_one_and_update(
        {"_id": "internal_attack"},
        {"$inc": {"sequence": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )


    return f"AUTO-ATTACK-{counter['sequence']:03d}"


def process_job(job):
    job_id = job["_id"]

 
    now = datetime.now(timezone.utc)

    try:
        payload = job["payload"]
        cve_id = str(
            payload.get("cve_id", "")
        ).strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            raise ValueError("Invalid CVE identifier")

        # Normalize the title and description.
        title = str(payload.get("title", "")).strip()
        description = str(
            payload.get("description", "")
        ).strip()
        if not title:
            raise ValueError("Attack title cannot be empty")

        keywords = [
            str(value).strip()
            for value in payload.get("keywords", [])
            if str(value).strip()
        ]
        applicable_ecu = [
            str(value).strip()
            for value in payload.get("applicable_ecu", [])
            if str(value).strip()
        ]

        score = calculate_threat_score(cve_id, description)

        existing = attacks.find_one({"cve_id": cve_id})

        if existing:
            attack_id = existing["attack_id"]

        else:
 
            attack_id = generate_attack_id()
            attack_document = {
                "attack_id": attack_id,
                "cve_id": cve_id,
                "title": title,
                "description": description,
                "keywords": keywords,
                "applicable_ecu": applicable_ecu,
                **score,
                "created_at": now,
                "created_by_job_id": str(job_id),
            }

            try:
                attacks.insert_one(attack_document)

            except DuplicateKeyError:
                existing = attacks.find_one({"cve_id": cve_id})

                if existing is None:
                    raise

                attack_id = existing["attack_id"]

        jobs.update_one(
            {
                "_id": job_id,
                "status": "Processing",
                "claimed_by": WORKER_ID,
            },
            {
                "$set": {
                    "status": "Completed",
                    "attack_id": attack_id,
                    "updated_at": datetime.now(timezone.utc),
                },
                "$unset": {
                    "lease_until": "",
                    "claimed_by": "",
                },
            },
        )
        logger.info(
            "Completed job %s -> %s",
            job_id,
            attack_id,
        )

    except (ValueError, KeyError, TypeError) as exc:
        jobs.update_one(
            {
                "_id": job_id,
                "status": "Processing",
                "claimed_by": WORKER_ID,
            },
            {
                "$set": {
                    "status": "Failed",
                    "last_error": str(exc),
                    "updated_at": datetime.now(timezone.utc),
                },
                "$unset": {
                    "lease_until": "",
                    "claimed_by": "",
                },
            },
        )
        logger.exception("Job %s failed validation", job_id)

    except PyMongoError as exc:
        attempts = job.get("attempts", 1)

        new_status = (
            "Failed" if attempts >= MAX_ATTEMPTS else "Pending"
        )
        jobs.update_one(
            {
                "_id": job_id,
                "status": "Processing",
                "claimed_by": WORKER_ID,
            },
            {
                "$set": {
                    "status": new_status,
                    "last_error": str(exc)[:1000],
                    "updated_at": datetime.now(timezone.utc),
                },
                "$unset": {
                    "lease_until": "",
                    "claimed_by": "",
                },
            },
        )
        logger.exception("Database error processing job %s", job_id)

def main():
    initialize_worker()

    logger.info("Background worker started")

    while True:
        try:
     
            recover_abandoned_jobs()
            job = claim_job()


            if job is None:
                time.sleep(POLL_INTERVAL)
                continue
            process_job(job)

        except PyMongoError:
 
            logger.exception("MongoDB unavailable; retrying")
            time.sleep(POLL_INTERVAL)

        except Exception:
            logger.exception("Unexpected worker error")
            time.sleep(POLL_INTERVAL)
            
if __name__ == "__main__":
    try:
        # Start the worker's queue-processing loop.
        main()
    finally:
        # Close the MongoDB client when the process exits.
        client.close()
