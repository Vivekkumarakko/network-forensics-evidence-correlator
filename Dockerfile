FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8000
ENV NFEC_SECURE_COOKIE=1

CMD ["sh", "-c", "waitress-serve --host=0.0.0.0 --port=${PORT} web.app:app"]
