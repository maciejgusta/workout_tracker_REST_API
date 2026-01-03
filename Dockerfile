FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

ENV PATH="/code/.venv/bin:$PATH"

WORKDIR /code

COPY pyproject.toml uv.lock ./

ARG INSTALL_EXTRAS

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev \
    ${INSTALL_EXTRAS:+--extra "$INSTALL_EXTRAS"}

COPY . . 

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev \
    ${INSTALL_EXTRAS:+--extra "$INSTALL_EXTRAS"}

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]