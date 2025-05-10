import asyncio
import json
import click
from aiohttp import ClientSession

from engine.crawler import crawl
from engine.parser import extract_endpoints
from engine.payloads import generate_payloads, BASIC_PAYLOADS
from engine.logsetup import get_logger
from engine.tester import test_payload
from engine.wafdetector import detect_waf

logger = get_logger(__name__)

async def full_scan(
    start_url: str,
    max_depth: int = 2,
    concurrency: int = 5,
    basic: bool = False,
    obfuscate: bool = False,
    encode: bool = False,
    detect_waf: bool = False
) -> list[dict]:
    logger.info(
        f"Start full_scan: {start_url}, depth={max_depth}, conc={concurrency}, "
        f"basic={basic}, obf={obfuscate}, enc={encode}, waf={detect_waf}"
    )

    pages = await crawl(
        start_url=start_url,
        max_depth=max_depth,
        concurrency=concurrency
    )
    logger.info(f"Found pages: {len(pages)}")
    results: list[dict] = []

    async with ClientSession() as session:
        for idx, (url, html) in enumerate(pages, 1):
            logger.info(f"({idx}/{len(pages)}) Scanning: {url}")
            endpoints = extract_endpoints(html)
            if not endpoints:
                continue

            for endpoint in endpoints:
                param_id = (endpoint.get('param')
                            if endpoint.get('type') == 'link'
                            else ','.join(endpoint.get('params', {}).keys()))

                if basic:
                    plist = BASIC_PAYLOADS
                else:
                    plist = generate_payloads(endpoint)

                for p in plist:
                    success, resp, used = await test_payload(
                        session,
                        url,
                        endpoint,
                        p,
                        obfuscate,
                        encode
                    )
                    waf_name = detect_waf(resp) if detect_waf else None

                    et = endpoint.get("type")
                    vtype = "stored" if et == "form" else "reflected"

                    record = {
                        "url": url,
                        "endpoint_type": et,
                        "endpoint_url": endpoint.get("url"),
                        "endpoint_method": endpoint.get("method", "GET"),
                        "endpoint_params": json.dumps(
                            endpoint.get("params")
                            or {endpoint.get("param"): endpoint.get("value")},
                            ensure_ascii=False
                        ),
                        "payload": used,
                        "success": success,
                        "waf": waf_name,
                        "vuln_type": vtype
                    }
                    results.append(record)

                    if success:
                        click.secho(
                            f"[+] {vtype.title()} XSS: {param_id} => {used}",
                            fg="green"
                        )
                    elif waf_name:
                        click.secho(
                            f"[!] WAF ({waf_name}) on {param_id}",
                            fg="yellow"
                        )
                    else:
                        click.secho(f"[-] No XSS: {param_id}", fg="blue")

    return results