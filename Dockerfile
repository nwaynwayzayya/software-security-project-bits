# NoteVault runtime image: no application secret is stored in the image.
FROM python:3.12.8-slim-bookworm

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

COPY app.py .
RUN useradd --create-home --uid 10001 notevault
USER 10001:10001

EXPOSE 8080
CMD ["python", "app.py"]
