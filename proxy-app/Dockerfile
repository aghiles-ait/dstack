FROM python:3.11-slim

WORKDIR /app

# Installer les dépendances
RUN pip install --no-cache-dir flask requests

# Copier l'application
COPY app.py .

EXPOSE 80

CMD ["python", "app.py"]
