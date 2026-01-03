import time
import uuid
from fastapi import Request


def get_logging_middleware(logger):
    async def log_requests(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        start = time.perf_counter()

        try:
            response = await call_next(request)
        except Exception:
            logger.exception(
                f"{request.method} {request.url.path} request_id={request_id} unhandled_error"
            )
            raise

        duration_ms = (time.perf_counter() - start) * 1000
        response.headers["X-Request-ID"] = request_id
        logger.info(
            f"{request.method} {request.url.path} {response.status_code} "
            f"{duration_ms:.2f}ms request_id={request_id}"
        )
        return response

    return log_requests
