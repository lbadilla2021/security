FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Usuario sin privilegios. /run/probe y /data quedan suyos: el volumen con
# nombre hereda dueño y permisos de la imagen al crearse.
RUN useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /run/probe /data \
 && chown app:app /run/probe /data \
 && chmod 0700 /run/probe

WORKDIR /srv
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ /srv/

USER 10001:10001
