# Optional future CPU inference container; model bundle is mounted read-only.
FROM python:3.12-slim
WORKDIR /app
RUN python -m pip install --no-cache-dir torch==2.11.0 --index-url https://download.pytorch.org/whl/cpu
RUN python -m pip install --no-cache-dir 'numpy>=2.2,<3'
COPY soc_ai /app/soc_ai
ENTRYPOINT ["python", "-m", "soc_ai", "predict"]
