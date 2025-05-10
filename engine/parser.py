from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qsl


def extract_endpoints(html: str) -> list[dict]:
    """
    Извлекает точки ввода из HTML-контента.

    Возвращает список словарей с ключами:
      - type: 'link' или 'form'
      - url: для link или action для form
      - method: 'GET' или 'POST'
      - param: имя параметра (для link)
      - value: значение параметра (для link)
      - params: словарь name->value (для form)
    """
    endpoints: list[dict] = []
    soup = BeautifulSoup(html, 'html.parser')

    # Ссылки с параметрами GET
    for a in soup.find_all('a', href=True):
        href = a['href']
        parsed = urlparse(href)
        if parsed.query:
            for key, val in parse_qsl(parsed.query, keep_blank_values=True):
                endpoints.append({
                    'type': 'link',
                    'url': href,
                    'method': 'GET',
                    'param': key,
                    'value': val
                })

    # Формы
    for form in soup.find_all('form'):
        method = form.get('method', 'get').upper()
        action = form.get('action', '')
        inputs = {}
        # собираем все <input> и <textarea>
        for tag in form.find_all(['input', 'textarea']):
            name = tag.get('name')
            if not name:
                continue
            # для чекбоксов и радио берём атрибут value, по умолчанию empty
            inputs[name] = tag.get('value', '')
        endpoints.append({
            'type': 'form',
            'url': action,
            'method': method,
            'params': inputs
        })

    return endpoints