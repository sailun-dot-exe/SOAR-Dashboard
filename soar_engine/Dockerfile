FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv

COPY pyproject.toml ./
RUN mkdir app && touch app/__init__.py && pip install . && rm -rf app

COPY app ./app
COPY playbooks ./playbooks
RUN useradd -u 10001 -m soar && mkdir -p /srv/data && chown soar /srv/data
USER soar

ENV SOAR_PLAYBOOK_DIR=/srv/playbooks
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=12 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2)" || exit 1
# Single worker: HITL sweeper, correlation windows and audit-chain lock are process-local.
CMD ["uvicorn", "app.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
