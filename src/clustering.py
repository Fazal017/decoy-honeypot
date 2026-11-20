"""
Decoy Fabric v2 — actor profiling & campaign clustering.

One IP is not one attacker. A botnet is five IPs running the same
playbook; a manual actor is one IP returning over days. The job of
this module is to turn a pile of sessions into *campaigns* — groups
of sessions that were probably run by the same actor, or by the
same tooling.

Similarity between two sessions is a weighted score:

    0.50 * Jaccard(password sets)
    0.30 * Jaccard(command sets)      (1.0 if both ran no commands)
    0.20 * same fingerprint label

Two sessions with identical password lists and identical command
sets score 1.0; a Hydra botnet and a manual explorer score ~0.0.
Sessions are merged greedily (agglomerative, single-linkage) at a
threshold of 0.45 — chosen so the two campaigns in
``logs/sample_campaign.jsonl`` separate cleanly, while sessions
from the same playbook still merge despite one password rotated.

A campaign is labelled by its shape, not by a single IP:

* ``botnet``  — >=3 IPs, shared password list, fast/automated labels
* ``manual``  — 1 IP, manual label, exploratory commands
* ``scanner`` — no logins, scanner label
* ``mixed``   — everything else (reported, not forced into a box)
"""

from __future__ import annotations

from collections import Counter
from difflib import SequenceMatcher

from src.fingerprint import fingerprint_sessions

MERGE_THRESHOLD = 0.45
PW_WEIGHT = 0.50
CMD_WEIGHT = 0.30
LABEL_WEIGHT = 0.20


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def command_sequence_similarity(a: list[str], b: list[str]) -> float:
    """SequenceMatcher ratio on the joined command streams."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, " | ".join(a), " | ".join(b)).ratio()


def session_similarity(fa: dict, fb: dict) -> float:
    """Weighted similarity in [0, 1] between two fingerprinted sessions."""
    pw = jaccard(fa["password_set"], fb["password_set"])
    cmd = jaccard(fa["command_set"], fb["command_set"])
    label = 1.0 if fa["label"] == fb["label"] else 0.0
    return PW_WEIGHT * pw + CMD_WEIGHT * cmd + LABEL_WEIGHT * label


def cluster_sessions(events: list[dict],
                     threshold: float = MERGE_THRESHOLD) -> list[dict]:
    """Cluster sessions into campaigns. Returns a list of campaigns.

    Each campaign: campaign_id, session_ids, ips, passwords,
    commands, fingerprint_labels, first_seen, last_seen,
    likely_type, confidence, size.
    """
    fps = fingerprint_sessions(events)
    sids = sorted(fps.keys())
    if not sids:
        return []
    # Greedy agglomerative merging (single-linkage).
    clusters: list[set] = [{sid} for sid in sids]
    changed = True
    while changed:
        changed = False
        for i in range(len(clusters)):
            for j in range(i + 1, len(clusters)):
                # Best pair similarity across the two clusters.
                best = max(
                    session_similarity(fps[a], fps[b])
                    for a in clusters[i] for b in clusters[j])
                if best >= threshold:
                    clusters[i] |= clusters[j]
                    del clusters[j]
                    changed = True
                    break
            if changed:
                break

    campaigns = []
    for n, members in enumerate(
            sorted(clusters, key=lambda c: min(
                fps[s]["first_seen"] or "" for s in c)), 1):
        member_fps = [fps[s] for s in members]
        ips = sorted({f["src_ip"] for f in member_fps})
        passwords = sorted({p for f in member_fps for p in f["passwords"]})
        commands = Counter(c for f in member_fps for c in f["commands"])
        labels = Counter(f["label"] for f in member_fps)
        first = min(f["first_seen"] or "" for f in member_fps)
        last = max(f["last_seen"] or "" for f in member_fps)
        # Likely type from shape.
        if len(ips) >= 3 and labels.get("botnet", 0) + labels.get("hydra", 0) >= len(members) // 2:
            likely, conf = "botnet", 0.9
        elif len(ips) == 1 and labels.get("manual", 0) >= len(members) // 2:
            likely, conf = "manual", 0.85
        elif labels.get("scanner", 0) >= len(members) // 2:
            likely, conf = "scanner", 0.8
        elif labels.get("sqlmap", 0) >= len(members) // 2:
            likely, conf = "sqlmap", 0.8
        else:
            likely, conf = "mixed", 0.5
        campaigns.append({
            "campaign_id": f"CAMP-{n:02d}",
            "session_ids": sorted(members),
            "size_sessions": len(members),
            "ips": ips,
            "n_ips": len(ips),
            "passwords": passwords,
            "n_passwords": len(passwords),
            "commands": dict(commands),
            "fingerprint_labels": dict(labels),
            "first_seen": first,
            "last_seen": last,
            "likely_type": likely,
            "confidence": conf,
        })
    return campaigns


def campaign_summary(campaigns: list[dict]) -> dict:
    return {
        "n_campaigns": len(campaigns),
        "by_type": dict(Counter(c["likely_type"] for c in campaigns)),
        "largest_campaign_sessions": max(
            (c["size_sessions"] for c in campaigns), default=0),
        "total_sessions": sum(c["size_sessions"] for c in campaigns),
        "total_ips": len({ip for c in campaigns for ip in c["ips"]}),
    }
