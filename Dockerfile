FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /srv

# Standard-library only application: no pip install required.
COPY app/ ./app/
COPY web/ ./web/
COPY scripts/ ./scripts/
COPY tests/ ./tests/

RUN mkdir -p /srv/data \
    && chmod +x /srv/scripts/verify /srv/scripts/acceptance.py \
    && python -m compileall -q app scripts

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD python -c "import json,urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:'+__import__('os').environ.get('PORT','8080')+'/healthz',timeout=3); sys.exit(0 if json.load(r)['status']=='ok' else 1)"

CMD ["python", "-m", "app.server"]
