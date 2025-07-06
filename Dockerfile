FROM python:3.9-slim
WORKDIR /app
COPY . /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=HoneyFTP" \
    && pip install --no-cache-dir twisted requests service-identity pyOpenSSL cryptography pillow openpyxl python-docx fpdf2
USER nobody
EXPOSE 2121
CMD ["python", "honeypot.py"]
