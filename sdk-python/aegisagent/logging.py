import json
import logging
from typing import Any, Optional


class StructuredJSONFormatter(logging.Formatter):
    """Logging formatter that outputs log records as structured JSON (TASK-0193)."""

    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        style: str = "%",
    ):
        super().__init__(fmt, datefmt, style)

    def format(self, record: logging.LogRecord) -> str:
        # Base log record fields
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "filename": record.filename,
            "lineno": record.lineno,
        }

        # Extract extra fields added via `logger.info(..., extra={...})`
        # Non-standard fields are dynamically stored in the record's __dict__
        standard_fields = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "message",
        }
        for k, v in record.__dict__.items():
            if k not in standard_fields:
                log_record[k] = v

        # Add formatted exceptions or stack traces if present
        if record.exc_info:
            log_record["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            log_record["stack_info"] = self.formatStack(record.stack_info)

        return json.dumps(log_record)
