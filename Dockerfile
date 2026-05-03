FROM python:3.13-slim

WORKDIR /app

COPY config.json .
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8085 1080

CMD ["python", "main.py"]