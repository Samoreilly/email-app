FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_PROJECT_ENVIRONMENT=/venv
COPY --from=ghcr.io/astral-sh/uv:0.8.4 /uv /usr/local/bin/uv
WORKDIR /srv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY app ./app
COPY scripts ./scripts
ENV PATH="/venv/bin:$PATH"
RUN useradd -r -u 1000 app && mkdir -p /srv/var && chown app /srv/var
USER app
EXPOSE 8000 2525
CMD ["uvicorn", "app.web.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
