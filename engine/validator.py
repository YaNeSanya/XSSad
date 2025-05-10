import os
from urllib.parse import urlparse


def is_valid_url(value: str) -> bool:
    """
    Проверяет, что строка — корректный URL с http(s) или file схемой.
    """
    parsed = urlparse(value)
    if parsed.scheme in ('http', 'https') and parsed.netloc:
        return True
    if parsed.scheme == 'file' and parsed.path:
        return True
    return False


def validate_depth(value: int) -> int:
    """
    Проверяет, что глубина — положительное целое.
    """
    if not isinstance(value, int) or value < 1:
        raise ValueError('Depth must be a positive integer')
    return value


def validate_concurrency(value: int) -> int:
    """
    Проверяет, что concurrency — положительное целое.
    """
    if not isinstance(value, int) or value < 1:
        raise ValueError('Concurrency must be a positive integer')
    return value


def validate_output_format(value: str) -> str:
    """
    Проверяет формат сохранения — 'json' или 'csv'.
    """
    if value not in ('json', 'csv'):
        raise ValueError("Format must be 'json' or 'csv'.")
    return value


def validate_file_path(value: str) -> str:
    """
    Проверяет, что путь или file://путь существует на диске.
    """
    # Поддерживаем file:// схема
    if value.startswith('file://'):
        path = value[len('file://'):]
    else:
        path = value
    if not os.path.isfile(path):
        raise ValueError(f'File not found: {path}')
    return value