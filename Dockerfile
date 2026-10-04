# RFC 9591 FROST 会签核验台镜像（纯标准库，无第三方依赖）
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8080 \
    EVIDENCE_DB=/data/evidence.json

WORKDIR /srv/desk

COPY app ./app
COPY README.md ./README.md

RUN mkdir -p /data && useradd -r -u 10001 deskuser && chown -R deskuser /data /srv/desk
USER deskuser

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD python -c "import json,os,urllib.request;u='http://127.0.0.1:%s/healthz'%os.environ.get('PORT','8080');j=json.load(urllib.request.urlopen(u,timeout=2));assert j['status']=='ok'" || exit 1

CMD ["python", "-m", "app.server"]
