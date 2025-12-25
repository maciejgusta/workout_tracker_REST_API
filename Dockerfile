FROM python:3.13-slim

WORKDIR /code

ARG INSTALL_EXTRAS=""

COPY pyproject.toml README.md ./
COPY app ./app

RUN if [ -n "$INSTALL_EXTRAS" ]; then \
    pip install --no-cache-dir ".[${INSTALL_EXTRAS}]"; \
    else \
    pip install --no-cache-dir .; \
    fi

COPY . . 

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
