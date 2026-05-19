# BioCybe — Image Docker multi-stage
# ==================================
# Cible : déploiement SOC/conteneurs Linux x86_64.
#
# Build : docker build -t biocybe:latest .
# Build avec ML : docker build --build-arg BIOCYBE_EXTRAS=ml -t biocybe:latest .
# Build full SOC : docker build --build-arg BIOCYBE_EXTRAS=soc -t biocybe:latest .
#
# Run scan : docker run --rm -v "$PWD/samples:/samples:ro" biocybe:latest scan /samples
# Run daemon : docker run -d biocybe:latest
#
# Par défaut on installe le CORE seulement (image légère, build rapide).
# Les extras (ml, web, fileanalysis, network, soc, all) sont opt-in via
# --build-arg BIOCYBE_EXTRAS=... pour matcher la philosophie pip extras.

ARG PYTHON_VERSION=3.12
ARG BIOCYBE_EXTRAS=

# ---------- Stage 1: builder ----------
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ARG BIOCYBE_EXTRAS

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Toolchain de build pour les deps qui n'auraient pas de wheel.
# yara-python 4.5+ a des wheels manylinux, donc pas besoin de libyara-dev.
# libmagic-dev pour compiler python-magic si l'extra fileanalysis est demandé.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Création d'un venv dans /opt/biocybe qui sera copié tel quel
# dans le stage runtime. Approche standard et prédictible (contrairement
# à pip --prefix qui dépend de la version Python exacte).
RUN python -m venv /opt/biocybe
ENV PATH="/opt/biocybe/bin:$PATH"

RUN pip install --upgrade pip wheel setuptools

# Cache friendly : sources copiées en dernier
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Si BIOCYBE_EXTRAS est défini, on installe `.[extras]`, sinon juste `.`
# Le shell évalue le `[...]` correctement avec ou sans extras.
RUN if [ -n "$BIOCYBE_EXTRAS" ]; then \
        pip install ".[${BIOCYBE_EXTRAS}]"; \
    else \
        pip install "."; \
    fi

# Sanity check côté builder : la CLI fonctionne
RUN biocybe --help > /dev/null && biocybe scan --help > /dev/null

# ---------- Stage 2: runtime ----------
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/biocybe/bin:$PATH" \
    VIRTUAL_ENV="/opt/biocybe"

# Runtime libs uniquement. libmagic1 utile si fileanalysis installé,
# inoffensif sinon (quelques Ko). tini = PID 1 propre pour le daemon.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 biocybe \
    && useradd --system --uid 10001 --gid biocybe \
        --home-dir /home/biocybe --create-home biocybe

# Le venv complet est copié — biocybe binary + tous les site-packages.
COPY --from=builder --chown=biocybe:biocybe /opt/biocybe /opt/biocybe

# Config + règles livrées (sous /home/biocybe pour cohérence avec WORKDIR
# et permissions user). L'utilisateur peut override via -v en prod.
COPY --chown=biocybe:biocybe config/ /home/biocybe/config/
COPY --chown=biocybe:biocybe rules/  /home/biocybe/rules/

# Phase 3.b : précompile le cache YARA (.yarc) à l'image build pour
# démarrage runtime quasi-instantané (~200 ms). Sans ce cache, le 1er
# démarrage avec 700+ règles communautaires peut prendre 1-5 min.
# Le `chown` après est pour s'assurer que le user biocybe peut lire
# le cache généré par root.
RUN cd /home/biocybe && \
    mkdir -p db/signatures/yara && \
    cp rules/yara/*.yar db/signatures/yara/ && \
    /opt/biocybe/bin/biocybe intel rules build-cache --skip-sync && \
    chown -R biocybe:biocybe /home/biocybe/db

# Volumes pour la persistance (à monter en prod : -v biocybe-data:/home/biocybe/db)
VOLUME ["/home/biocybe/quarantine", "/home/biocybe/db", "/home/biocybe/logs"]

# Port HTTP exposé pour `biocybe api serve` (requiert build avec
# --build-arg BIOCYBE_EXTRAS=web pour avoir Flask + waitress installés)
EXPOSE 8080

WORKDIR /home/biocybe
USER biocybe

# Healthcheck : la CLI répond
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD biocybe --help > /dev/null 2>&1 || exit 1

# tini en PID 1 = gestion propre des signaux pour le daemon
ENTRYPOINT ["tini", "--", "biocybe"]
CMD ["--help"]
