"""Explainable rules and a deterministic synthetic-baseline Isolation Forest."""
import math
import random
from sklearn.ensemble import IsolationForest


def features(event):
    hour = event.timestamp.hour
    return [math.sin(hour * math.pi / 12), math.cos(hour * math.pi / 12),
            math.log1p(event.bytes_transferred), int(not event.success)]


class Detector:
    version = "synthetic-iforest-v1"

    def __init__(self):
        rng = random.Random(42)
        baseline = []
        for _ in range(1000):
            hour = rng.randint(8, 18)
            baseline.append([math.sin(hour * math.pi / 12), math.cos(hour * math.pi / 12),
                             math.log1p(rng.randint(100, 100000)), int(rng.random() < .02)])
        self.model = IsolationForest(n_estimators=100, contamination=.03, random_state=42).fit(baseline)

    def detect(self, event, history):
        reasons = []
        def add(category, technique, severity, evidence):
            reasons.append(dict(category=category, technique=technique, severity=severity, evidence=evidence))
        if event.action == "ConsoleLogin" and (event.timestamp.hour < 6 or event.timestamp.hour >= 22):
            add("Unusual authentication", "T1078.004", 50, "Console login outside 06:00–22:00 UTC; heuristic requires local calibration.")
        failures = sum(not h["success"] and h["action"] == "ConsoleLogin" and
                       0 <= event.timestamp.timestamp() - h["epoch"] <= 600 for h in history)
        if event.action == "ConsoleLogin" and not event.success and failures >= 4:
            add("Repeated failed authentication", "T1110", 75, "At least five failed console logins within ten minutes for this principal.")
        if event.success and event.action in {"AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "CreateAccessKey", "UpdateAssumeRolePolicy"}:
            add("Sensitive IAM change", "T1098", 80, f"Successful {event.action}; verify authorization and policy contents.")
        if event.success and event.bytes_transferred >= 100_000_000:
            add("Abnormal data access", "T1530", 85, "Event reports at least 100 MB transferred; this does not prove exfiltration.")
        recent = sum(0 <= event.timestamp.timestamp() - h["epoch"] <= 60 for h in history)
        if recent >= 29:
            add("Unusual API volume", None, 65, "At least thirty events in one minute for this principal.")
        if event.action == "ConsoleLogin" and event.success and event.latitude is not None:
            prior = [h for h in history if h["success"] and h["action"] == "ConsoleLogin" and
                     h.get("latitude") is not None and 0 < event.timestamp.timestamp() - h["epoch"] <= 86400]
            if prior:
                h = max(prior, key=lambda x: x["epoch"])
                lat1, lat2 = math.radians(h["latitude"]), math.radians(event.latitude)
                dlat = lat2 - lat1
                dlon = math.radians(event.longitude - h["longitude"])
                a = math.sin(dlat/2)**2 + math.cos(lat1)*math.cos(lat2)*math.sin(dlon/2)**2
                km = 6371 * 2 * math.asin(min(1, math.sqrt(a)))
                speed = km / ((event.timestamp.timestamp() - h["epoch"]) / 3600)
                if km > 500 and speed > 900:
                    add("Impossible travel", "T1078.004", 90, f"Estimated {speed:.0f} km/h between supplied coordinates; verify VPN/proxy use.")
        normality = float(self.model.decision_function([features(event)])[0])
        # A bounded ranking score, deliberately NOT a calibrated probability.
        score = round(max(0, min(100, 50 - normality * 200)), 1)
        if normality < 0:
            add("ML anomaly", None, 40, "Outside the synthetic baseline; requires analyst validation.")
        return score, reasons
