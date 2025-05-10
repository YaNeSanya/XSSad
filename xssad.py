import json
import csv
import asyncio
from engine.logsetup import setup_logging, get_logger
from workflows.singlescan import single_scan
from workflows.fullscan import full_scan

def prompt_menu():
    print("\n=== XSSad Scanner ===")
    print("1) Одиночное сканирование")
    print("2) Краулинг сайта")
    choice = input("Выберите тип сканирования [1-2]: ").strip()
    while choice not in ('1', '2'):
        choice = input("Введите 1 или 2: ").strip()
    return choice

def prompt_payload_mode():
    print("\n1) Быстрая проверка (только базовые payload)")
    print("2) Полная проверка (все payload + обфускация)")
    choice = input("Выберите режим payload [1-2]: ").strip()
    while choice not in ('1', '2'):
        choice = input("Введите 1 или 2: ").strip()
    return choice

def prompt_yes_no(message: str) -> bool:
    ans = input(f"{message} (y/n): ").strip().lower()
    while ans not in ('y', 'n'):
        ans = input("Введите 'y' или 'n': ").strip().lower()
    return ans == 'y'

def prompt_save():
    if not prompt_yes_no("Сохранить результаты"):
        return None, None
    fmt = None
    while fmt not in ('json', 'csv'):
        fmt = input("Формат сохранения [json/csv]: ").strip().lower()
    path = input("Имя файла для сохранения: ").strip()
    return fmt, path

async def run():
    setup_logging()
    logger = get_logger(__name__)

    target = input("Введите URL или file://путь: ").strip()

    scan_type = prompt_menu()
    is_crawl = (scan_type == '2')

    payload_mode = prompt_payload_mode()
    basic = (payload_mode == '1')
    obfuscate = not basic

    encode = prompt_yes_no("Включить кодирование payloads")
    detect_waf = prompt_yes_no("Включить обнаружение WAF")

    out_format, out_file = prompt_save()

    logger.info(
        f"Запуск: target={target}, crawl={is_crawl}, basic={basic}, "
        f"obf={obfuscate}, enc={encode}, waf={detect_waf}"
    )

    if is_crawl:
        results = await full_scan(
            start_url=target,
            max_depth=2,
            concurrency=5,
            basic=basic,
            obfuscate=obfuscate,
            encode=encode,
            detect_waf=detect_waf
        )
    else:
        results = await single_scan(
            target_url=target,
            basic=basic,
            obfuscate=obfuscate,
            encode=encode,
            detect_waf=detect_waf
        )

    if out_file and results is not None:
        logger.info(f"Сохраняем в {out_file} (формат={out_format})")
        try:
            if out_format == 'json':
                with open(out_file, 'w', encoding='utf-8') as f:
                    json.dump(results, f, ensure_ascii=False, indent=2)
            else:
                if results:
                    fieldnames = list(results[0].keys())
                    with open(out_file, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(results)
            logger.info("Результаты сохранены")
        except Exception as e:
            logger.error(f"Ошибка при сохранении: {e}")

    logger.info("Сканирование завершено")

if __name__ == '__main__':
    asyncio.run(run())