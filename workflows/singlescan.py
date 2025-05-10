import os
import json
import click
from aiohttp import ClientSession
from urllib.parse import urlparse, parse_qs

from engine.parser import extract_endpoints
from engine.payloads import generate_payloads, BASIC_PAYLOADS
from engine.logsetup import get_logger
from engine.tester import test_payload
from engine.wafdetector import detect_waf
from engine.dom_scanner import report_dom_findings  # новый импорт

logger = get_logger(__name__)

async def single_scan(
    target_url: str,
    basic: bool = False,
    obfuscate: bool = False,
    encode: bool = False,
    detect_waf: bool = False
) -> list[dict]:
    results: list[dict] = []
    logger.info(
        f"Start single_scan: {target_url} "
        f"(basic={basic}, obf={obfuscate}, enc={encode}, waf={detect_waf})"
    )

    # Получаем HTML
    if target_url.startswith("file://"):
        path = target_url[len("file://"):].lstrip('/\\')
        if not os.path.isfile(path):
            logger.error(f"File not found: {path}")
            return results
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            html = f.read()
    else:
        async with ClientSession() as session:
            try:
                async with session.get(target_url) as resp:
                    html = await resp.text(errors='ignore')
            except Exception as e:
                logger.error(f"Cannot fetch page {target_url}: {e}")
                return results

    # Статический анализ DOM-XSS
    report_dom_findings(html)

    # Динамический анализ эндпоинтов
    endpoints = extract_endpoints(html)
    # fallback: query-параметры
    if not endpoints and '?' in target_url:
        parsed = urlparse(target_url)
        qs = parse_qs(parsed.query)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        endpoints = [{'type': 'url', 'url': base, 'param': k, 'params': {k: v[0]}} for k, v in qs.items()]
    logger.info(f"Found endpoints: {len(endpoints)}")
    if not endpoints:
        return results

    async with ClientSession() as session:
        for endpoint in endpoints:
            param_id = endpoint.get('param') if endpoint.get('type') == 'link' else ','.join(endpoint.get('params', {}))
            plist = BASIC_PAYLOADS if basic else generate_payloads(endpoint)
            for p in plist:
                success, resp, used = await test_payload(
                    session, target_url, endpoint, p, obfuscate, encode
                )
                waf_name = detect_waf(resp) if detect_waf else None
                et = endpoint.get('type')
                vtype = 'stored' if et == 'form' else 'reflected'

                record = {
                    'url': target_url,
                    'endpoint_type': et,
                    'endpoint_url': endpoint.get('url'),
                    'endpoint_method': endpoint.get('method', 'GET'),
                    'endpoint_params': json.dumps(endpoint.get('params') or {endpoint.get('param'): endpoint.get('value')}),
                    'payload': used,
                    'success': success,
                    'waf': waf_name,
                    'vuln_type': vtype
                }
                results.append(record)

                if success:
                    click.secho(f"[+] {vtype.title()} XSS: {param_id} => {used}", fg="green")
                elif waf_name:
                    click.secho(f"[!] WAF ({waf_name}) on {param_id}", fg="yellow")
                else:
                    click.secho(f"[-] No XSS: {param_id}", fg="blue")
    return results