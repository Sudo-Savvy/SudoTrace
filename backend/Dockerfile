FROM python:3.12-slim-bookworm AS builder
WORKDIR /build
RUN pip install --no-cache-dir pip-tools==7.4.1
COPY requirements.in .
RUN pip-compile requirements.in --output-file requirements.txt
RUN python -m venv /venv && \
    /venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim-bookworm
COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH"
WORKDIR /app
COPY app/ ./app/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh && \
    groupadd --gid 1000 sudotrace && \
    useradd --uid 1000 --gid 1000 --no-create-home --shell /bin/false sudotrace && \
    mkdir -p /data && chown 1000:1000 /data
USER 1000:1000
EXPOSE 8000
CMD ["./entrypoint.sh"]
