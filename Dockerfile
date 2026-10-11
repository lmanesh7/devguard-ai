# DevGuard AI & Agent Container
# Python 3.12, installed packages, app, agent, and docs
FROM python:3.12-slim

WORKDIR /app

COPY agent/requirements.txt agent/requirements.txt
RUN pip install --no-cache-dir -r agent/requirements.txt

COPY app app
COPY agent agent
COPY docs/sample docs/sample

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
