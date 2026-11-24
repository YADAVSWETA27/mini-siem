FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 SIEM_DB=/app/siem.db

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501
# Generate demo logs, ingest + detect, then serve the dashboard.
CMD ["sh", "-c", "python cli.py demo && streamlit run dashboard.py --server.address=0.0.0.0 --server.port=8501"]
