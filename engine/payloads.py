import os
import yaml
from typing import List, Dict
from engine.obfuscator import obfuscate

_PAYLOADS_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'payloads.yaml')
try:
    with open(_PAYLOADS_FILE, 'r', encoding='utf-8') as f:
        _ALL_PAYLOADS = yaml.safe_load(f) or {}
except Exception:
    _ALL_PAYLOADS = {}

# Базовые payloads
BASIC_PAYLOADS: List[str] = _ALL_PAYLOADS.get('basic', [])

# Полный набор категорий
_FULL_CATEGORIES = ['basic', 'url', 'attribute', 'img', 'body']


def generate_payloads(endpoint: Dict,
                      basic: bool = False,
                      obfuscate_flag: bool = False) -> List[str]:
    """
    Возвращает набор payloads для данной точки ввода:
      - базовые (basic=True)
      - полные (basic=False)
      - при obfuscate_flag=True добавляет обфусцированные варианты
      - для DOM-XSS (type=='dom') возвращаем базовые
    """
    # Для DOM-XSS используем только базовые
    if endpoint.get('type') == 'dom':
        payloads = BASIC_PAYLOADS.copy()
        if obfuscate_flag:
            obf_list = []
            for p in payloads:
                obf_list.extend(obfuscate(p))
            payloads.extend(obf_list)
        return payloads

    # Если только базовые
    if basic:
        return BASIC_PAYLOADS.copy()

    # Собираем по категориям
    cats = _FULL_CATEGORIES.copy()
    if endpoint.get('type') != 'link' and 'url' in cats:
        cats.remove('url')

    payloads: List[str] = []
    for cat in cats:
        payloads.extend(_ALL_PAYLOADS.get(cat, []))

    # Уникализация
    seen = set()
    unique = []
    for p in payloads:
        if p not in seen:
            unique.append(p)
            seen.add(p)

    # Обфускация
    if obfuscate_flag:
        for p in list(unique):
            for o in obfuscate(p):
                if o not in seen:
                    unique.append(o)
                    seen.add(o)
    return unique