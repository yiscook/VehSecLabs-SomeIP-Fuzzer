import sys

from loguru import logger


def setup_logger(level: str = "INFO", log_file: str | None = None) -> None:
    logger.remove()
    logger.add(
        sys.stderr,
        level=level,
        colorize=True,
        format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | {message}",
    )
    if log_file:
        logger.add(log_file, rotation="10 MB", retention="7 days", encoding="utf-8")


__all__ = ["logger", "setup_logger"]
