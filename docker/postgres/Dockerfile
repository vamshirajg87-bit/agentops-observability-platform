FROM postgres:17.11

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      postgresql-17-pgvector=0.8.6-1.pgdg13+2 \
 && rm -rf /var/lib/apt/lists/*
