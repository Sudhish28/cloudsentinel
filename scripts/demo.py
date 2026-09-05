"""Send deterministic, synthetic events. Re-running is idempotent."""
import json
import os
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen

start = datetime(2026, 1, 15, 2, 0, tzinfo=timezone.utc)
events = []
for i in range(35):
    events.append(dict(event_id=f"demo-{i}", timestamp=(start + timedelta(seconds=i)).isoformat(),
                       principal="demo-analyst", action="ConsoleLogin" if i < 6 else "GetObject",
                       success=i >= 5, bytes_transferred=150_000_000 if i == 34 else 1000,
                       source_ip="192.0.2.10", region="us-east-1"))
events.append(dict(event_id="demo-iam", timestamp=(start + timedelta(minutes=2)).isoformat(),
                   principal="demo-admin", action="AttachUserPolicy", success=True))
req = Request(os.getenv("API_URL", "http://localhost:8000") + "/api/events",
              data=json.dumps({"events": events}).encode(),
              headers={"Content-Type": "application/json", "X-API-Key": os.environ["API_KEY"]})
with urlopen(req, timeout=30) as response:
    print(response.read().decode())
