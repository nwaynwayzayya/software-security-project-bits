# NoteVault runtime image: no application secret is stored in the image.
FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337

WORKDIR /app
COPY requirements.txt .
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

COPY app.py .
RUN useradd --create-home --uid 10001 notevault
USER 10001:10001

EXPOSE 8080
CMD ["python", "app.py"]
