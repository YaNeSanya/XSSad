import os
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, urlunparse
from aiohttp import ClientSession
from engine.obfuscator import obfuscate
from engine.encoder import encode_payload
from engine.dom_scanner import find_dom_xss, report_dom_findings

async def test_payload(
    session: ClientSession,
    base_url: str,
    endpoint: dict,
    original: str,
    obfuscate_flag: bool,
    encode_flag: bool
) -> tuple[bool, dict, str]:

    candidates = [original]
    if obfuscate_flag:
        for o in obfuscate(original):
            if o not in candidates:
                candidates.append(o)
    if encode_flag:
        for e in encode_payload(original):
            if e not in candidates:
                candidates.append(e)

    for payload in candidates:
        method = 'GET'; data = None
        if endpoint.get('type') == 'link':
            parsed = urlparse(endpoint['url'])
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            params[endpoint['param']] = payload
            new_q = urlencode(params)
            new_url = parsed._replace(query=new_q)
            req_url = urlunparse(new_url)
            if not req_url.startswith(('http', 'file')):
                req_url = urljoin(base_url, req_url)
        elif endpoint.get('type') == 'form':
            action = endpoint.get('url', '')
            req_url = action if action.startswith(('http','file')) else urljoin(base_url, action)
            method = endpoint.get('method','GET').upper()
            form = {k: payload for k in endpoint.get('params', {})}
            data = form
        else:
            continue

        if req_url.startswith('file://'):
            path = req_url[len('file://'):].lstrip('/\\')
            if os.path.isfile(path):
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        body = f.read()
                except:
                    continue
                if payload in body:
                    return True, {'text': body}, payload
            continue

        try:
            if method == 'GET':
                resp = await session.get(req_url, params=data)
            else:
                resp = await session.post(req_url, data=data)
            text = await resp.text(errors='ignore')
        except:
            continue

        if payload in text:
            return True, {'headers': resp.headers, 'text': text}, payload

        segments = find_dom_xss(text)
        if segments:
            report_dom_findings(text)
            return True, {'headers': resp.headers, 'text': text}, payload

    return False, {'headers': {}, 'text': ''}, original