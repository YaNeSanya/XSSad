import os
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, urlunparse
from aiohttp import ClientSession

from engine.obfuscator import obfuscate
from engine.encoder import encode_payload

async def test_payload(
    session: ClientSession,
    base_url: str,
    endpoint: dict,
    original: str,
    obfuscate_flag: bool,
    encode_flag: bool
) -> tuple[bool, dict, str]:
    """
    Отправляет варианты payload и возвращает первым удачным:
      (success, response, used_payload)
    """
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
        # строим request_url/data
        if endpoint.get("type") == "link":
            parsed = urlparse(endpoint["url"])
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            params[endpoint["param"]] = payload
            new_q = urlencode(params)
            new = parsed._replace(query=new_q)
            req = urlunparse(new)
            if not req.startswith(("http://","https://","file://")):
                req = urljoin(base_url, req)
            method = "GET"; data = None

        elif endpoint.get("type") == "form":
            action = endpoint.get("url","")
            method = endpoint.get("method","GET").upper()
            form = endpoint.get("params",{}).copy()
            for k in form: form[k] = payload
            req = action if action.startswith(("http://","https://","file://")) \
                  else urljoin(base_url, action)
            data = form

        else:
            continue

        if req.startswith("file://"):
            path = req[len("file://"):].lstrip("/\\")
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    body = f.read()
            except:
                continue
            if payload in body:
                return True, {"headers": {}, "text": body}, payload
            continue

        try:
            if method == "GET":
                resp = await session.get(req) if data is None \
                       else await session.get(req, params=data)
            else:
                resp = await session.post(req, data=data)
            text = await resp.text(errors="ignore")
            if payload in text:
                return True, {"headers": resp.headers, "text": text}, payload
        except:
            pass

    return False, {"headers": {}, "text": ""}, original