# NoteVault runtime image: no application secret is stored in the image.
FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

COPY app.py .
RUN useradd --create-home --uid 10001 notevault
USER 10001:10001

EXPOSE 8080
CMD ["python", "app.py"]
