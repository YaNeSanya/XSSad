import random
from typing import List
from urllib.parse import quote


def random_case(payload: str) -> str:
    return ''.join(ch.upper() if random.random() < 0.5 else ch.lower() for ch in payload)


def entity_encode(payload: str) -> str:
    return ''.join(f'&#x{ord(ch):x};' for ch in payload)


def percent_encode(payload: str) -> str:
    return quote(payload)


def obfuscate(payload: str) -> List[str]:
    variants = [random_case(payload), entity_encode(payload), percent_encode(payload)]
    seen = set(); result: List[str] = []
    for v in variants:
        if v not in seen:
            result.append(v); seen.add(v)
    return result