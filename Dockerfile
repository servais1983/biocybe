# BioCybe — Image Docker multi-stage
# ==================================
# Stage 1 (builder) : compile yara-python et résout toutes les deps dans une wheelhouse.
# Stage 2 (runtime) : python:slim minimal + utilisateur non-root + binaire YARA système.
#
# Cible : déploiement SOC/conteneurs. Linux x86_64.
#
# Build :   docker build -t biocybe:latest .
# Run scan: docker run --rm -v "$PWD/samples:/samples:ro" biocybe:latest scan /samples
# Run API : docker run -d -p 8080:8080 --name biocybe biocybe:latest

ARG PYTHON_VERSION=3.12

# ---------- Stage 1: builder ----------
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Toolchain de build au cas où une dépendance n'a pas de wheel pour
# notre combinaison Python/Linux. yara-python 4.5+ a des wheels manylinux
# qui embarquent libyara statiquement, donc pas besoin de libyara-dev ici.
# libmagic-dev permet de compiler python-magic si l'extra fileanalysis
# est demandé.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache friendly : copier seulement la déclaration des deps en premier
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Installer dans un préfixe isolé qu'on copiera dans le runtime
RUN python -m pip install --upgrade pip wheel setuptools \
 && pip install --prefix=/install ".[soc]"

# ---------- Stage 2: runtime ----------
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

# ARG global non visible dans le stage : redéclarer pour ${PYTHON_VERSION}
ARG PYTHON_VERSION=3.12

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/biocybe/bin:$PATH" \
    PYTHONPATH="/opt/biocybe/lib/python${PYTHON_VERSION}/site-packages"

# Runtime libs uniquement. libyara est embarqué dans la wheel
# yara-python pour Linux/manylinux, donc pas besoin du paquet système.
# libmagic1 est requis seulement si l'extra fileanalysis a été installé.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 biocybe \
    && useradd --system --uid 10001 --gid biocybe --home /opt/biocybe --create-home biocybe

# Copier l'install Python depuis le builder
COPY --from=builder /install /opt/biocybe

# Copier la config et les règles livrées
COPY --chown=biocybe:biocybe config/ /opt/biocybe/config/
COPY --chown=biocybe:biocybe rules/  /opt/biocybe/rules/

# Volumes de données persistantes (à monter en prod)
VOLUME ["/opt/biocybe/quarantine", "/opt/biocybe/db", "/opt/biocybe/logs"]

WORKDIR /opt/biocybe
USER biocybe

# Healthcheck minimal : la CLI se lance sans erreur
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD biocybe --help > /dev/null 2>&1 || exit 1

# tini = PID 1 propre, gère les signaux pour les daemons
ENTRYPOINT ["tini", "--", "biocybe"]
CMD ["--help"]
