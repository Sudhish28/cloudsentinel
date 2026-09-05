"""Normalize an exported CloudTrail Records JSON file and send in batches."""
import argparse
import json
import os
from urllib.request import Request, urlopen


def normalize(record):
    identity = record.get("userIdentity", {})
    response = record.get("responseElements") or {}
    return dict(event_id=record["eventID"], timestamp=record["eventTime"],
                principal=identity.get("arn") or identity.get("principalId") or "unknown",
                action=record["eventName"], source_ip=record.get("sourceIPAddress", "unknown"),
                region=record.get("awsRegion", "unknown"),
                success=not bool(record.get("errorCode")) and response.get("ConsoleLogin") != "Failure")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    args = parser.parse_args()
    with open(args.file, encoding="utf-8") as source:
        events = sorted([normalize(r) for r in json.load(source)["Records"]], key=lambda e: e["timestamp"])
    for offset in range(0, len(events), 500):
        req = Request(os.getenv("API_URL", "http://localhost:8000") + "/api/events",
                      data=json.dumps({"events": events[offset:offset+500]}).encode(),
                      headers={"Content-Type": "application/json", "X-API-Key": os.environ["API_KEY"]})
        with urlopen(req, timeout=60) as response:
            print(response.read().decode())
