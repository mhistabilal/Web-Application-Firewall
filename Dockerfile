FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
EXPOSE 5001

# Start backend app on 5001 in background, then run WAF server on 5000
CMD python backend_app.py & python waf_server.py