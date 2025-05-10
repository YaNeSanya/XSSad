import logging
import os
import sys

DEFAULT_LOG_LEVEL = logging.INFO


def setup_logging(level: int = DEFAULT_LOG_LEVEL, log_file: str = None) -> None:
    """
    Настраивает корневой логгер:

    - Вывод в консоль (StreamHandler).
    - При указании log_file — также в файл.
    """
    logger = logging.getLogger()
    logger.setLevel(level)

    # Очистить предыдущие обработчики
    if logger.hasHandlers():
        logger.handlers.clear()

    # Форматтер
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Консольный обработчик
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Файловый обработчик (если указан)
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(level)
        fh.setFormatter(formatter)
        logger.addHandler(fh)


def get_logger(name: str) -> logging.Logger:
    """
    Возвращает именованный логгер после настройки.

    Убедитесь, что setup_logging() был вызван до этого.
    """
    return logging.getLogger(name)