import re
from typing import List, Dict


def find_dom_sinks(html: str) -> List[Dict]:
    """
    Ищет DOM-отражения (например, location.hash или document.URL) в HTML и
    возвращает список эндпоинтов для тестирования DOM-XSS.

    Возвращает список словарей с ключами:
      - type: 'dom'
      - param: имя параметра (здесь 'hash')
    """
    sinks: List[Dict] = []
    # Ищем признаки использования document.URL или location.hash
    if re.search(r"\blocation\.hash\b", html) or re.search(r"\bdocument\.URL\b", html):
        sinks.append({
            'type': 'dom',
            'param': 'hash'
        })
    return sinks