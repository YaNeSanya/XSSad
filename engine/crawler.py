import asyncio
import logging
from typing import List, Tuple, Set
from urllib.parse import urljoin, urldefrag

from aiohttp import ClientSession, ClientError
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

async def fetch(session: ClientSession, semaphore: asyncio.Semaphore, url: str) -> Tuple[str, str]:
    """
    Загружает страницу по URL с учётом семафора и возвращает (url, html) или ('', '') при ошибке.
    """
    async with semaphore:
        try:
            async with session.get(url) as resp:
                text = await resp.text(errors='ignore')
                return url, text
        except ClientError as e:
            logger.error(f"Ошибка при загрузке {url}: {e}")
            return url, ''

async def crawl(start_url: str, max_depth: int = 2, concurrency: int = 5) -> List[Tuple[str, str]]:
    """
    Краулинг сайта в ширину до max_depth уровней.

    Возвращает список кортежей (url, html).
    """
    seen: Set[str] = set([start_url])
    results: List[Tuple[str, str]] = []
    from urllib.parse import urlparse
    # определяем корневой домен (схема + хост)
    parsed = urlparse(start_url)
    base_domain = f"{parsed.scheme}://{parsed.netloc}"
    semaphore = asyncio.Semaphore(concurrency)

    async with ClientSession() as session:
        # начинаем с первого уровня
        to_crawl = [start_url]
        # проходим строго на max_depth уровней
        for depth in range(max_depth):
            if not to_crawl:
                break
            tasks = [asyncio.create_task(fetch(session, semaphore, url)) for url in to_crawl]
            to_crawl_next: List[str] = []
            for task in asyncio.as_completed(tasks):
                url, html = await task
                results.append((url, html))
                # добавляем ссылки для следующего уровня
                # если текущий уровень меньше последнего, расширяем
                if depth < max_depth - 1 and html:
                    soup = BeautifulSoup(html, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        next_url = urljoin(url, href)
                        next_url = urldefrag(next_url)[0]
                        if next_url.startswith(base_domain) and next_url not in seen:
                            seen.add(next_url)
                            to_crawl_next.append(next_url)
            to_crawl = to_crawl_next
    return results