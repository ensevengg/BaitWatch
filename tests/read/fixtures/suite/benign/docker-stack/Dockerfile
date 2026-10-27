FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://get.docker.com/gpg | gpg --dearmor -o /usr/share/keyrings/docker.gpg
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
CMD ["./entrypoint.sh"]
