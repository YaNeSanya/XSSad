import json
import re
import sys
from typing import Any, Optional

# Загружаем сигнатуры
try:
    with open(sys.path[0] + '/db/wafSignatures.json', 'r', encoding='utf-8') as f:
        WAF_SIGNATURES = json.load(f)
except Exception:
    WAF_SIGNATURES = {}


def detect_waf(response: Any) -> Optional[str]:
    """
    Определяет WAF по сигнатурам.

    response может быть:
      - aiohttp.ClientResponse
      - словарь {'headers': ..., 'text': ...}
    Возвращает имя WAF или None.
    """
    # Извлечение кода, заголовков и тела
    try:
        status_code = str(response.status)
        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.text
    except AttributeError:
        # dict
        status_code = str(response.get('status_code', ''))
        headers = {k.lower(): v for k, v in response.get('headers', {}).items()}
        body = response.get('text', '')

    best_match = (0, None)
    # Ищем совпадения
    for name, sig in WAF_SIGNATURES.items():
        score = 0
        # код
        code_pattern = sig.get('code')
        if code_pattern and re.search(code_pattern, status_code):
            score += 0.5
        # заголовки
        header_pattern = sig.get('headers')
        if header_pattern:
            if isinstance(header_pattern, list):
                for pat in header_pattern:
                    if re.search(pat, str(headers), re.I):
                        score += 1
            else:
                if re.search(header_pattern, str(headers), re.I):
                    score += 1
        # тело
        page_pattern = sig.get('page')
        if page_pattern and re.search(page_pattern, body, re.I):
            score += 1
        if score > best_match[0]:
            best_match = (score, name)
    return best_match[1] if best_match[0] > 0 else None