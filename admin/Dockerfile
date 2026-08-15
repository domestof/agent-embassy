FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py auth.py catalog_store.py schema_types.py test_console.py log_tail.py keycloak_client.py openbao_client.py tier1_client.py tier3_client.py agent_client.py ./
COPY templates/ templates/
COPY static/ static/

EXPOSE 8002

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
