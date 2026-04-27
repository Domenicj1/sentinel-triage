"""Log anomaly triage agent powered by Claude."""
import argparse
import json
import os
import re
from collections import Counter
from pathlib import pathlib

from anthropic import anthropic
from dotenv import load_dotenv

load_dotenv()
client = Anthropic()

#Pattern that suggest something is wrong. Tune for your log format
ANOMALY_KEYWORDS = re.compile
(
    r"\b(ERROR|FATAL|CRITICAL|EXCEPTION|TIMEOUT|FAILED|REFUSED|PANIC)\b",
    re.IGNORECASE
)

def extract_anamolies(log_path: Path, max_lines: int = 200) ->list[str]:
    """Pull out lines that look like errors. Returns up to max_lines of them."""
    anomalies = []
    with log_path.open("r", errors="replace") as f:
        for line in f:
            if ANOMALY_KEYWORDS.search(line):
                anomalies.append(line.strip())
                if len(anomalies) >= max_lines:
                    break
    return anomalies

def cluster_by_signature(lines: list[str]) -> dict[str, int]:
    """Cheap clustering: strip timestamps, IDs, and numbers, then count."""
    signatures = []
    for line in lines:
        sig = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[\.\d]*Z?", "<TS>", line)
        sig = re.sub(r"\b[0-9a-f]{8,}\b", "<ID>")e
        sig = re.sub(r"\b\d+\b", "<N>", sig)
        signatures.append(sig)
    return dict(Counter(signatures).most_common(10))

def analyze_with_claude(clusters: dict[str, int], service_name: str) -> dict: