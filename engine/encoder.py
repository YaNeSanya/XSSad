from typing import List
from urllib.parse import quote

# Модуль кодирования XSS-пэйлоадов

def encode_payload(payload: str) -> List[str]:
    r"""
    Генерирует закодированные варианты переданного payload:
      - Unicode-escape (\uXXXX)
      - HTML entities (&#xNNNN;)
      - URL percent-encoding

    :param payload: оригинальный XSS-пэйлоад
    :return: список вариантов кодирования
    """
    variants: List[str] = []

    # 1) Unicode-escape каждого символа
    unicode_esc = ''.join(f"\\u{ord(ch):04x}" for ch in payload)
    variants.append(unicode_esc)

    # 2) HTML сущности
    html_ent = ''.join(f"&#x{ord(ch):x};" for ch in payload)
    variants.append(html_ent)

    # 3) URL percent-encoding
    url_enc = quote(payload, safe='')
    variants.append(url_enc)

    return variants