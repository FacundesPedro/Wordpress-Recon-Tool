FROM python:3.13-slim-trixie AS builder

WORKDIR /build
COPY . .
RUN pip install --no-cache-dir build && python -m build --wheel


FROM python:3.13-slim-trixie

# Build-time options
# - INSTALL_TOOLS: install nmap, ffuf, nuclei, wpscan and opendoor (opt-in)
# - INSTALL_RECOMMENDED_WORDLISTS: bake SecLists plugin/theme lists (default on)
ARG INSTALL_TOOLS=false
ARG INSTALL_RECOMMENDED_WORDLISTS=true
ARG FFUF_VERSION=2.3.0
ARG NUCLEI_VERSION=3.11.1
ARG WPSCAN_VERSION=4.1.0
ARG OPENDOOR_VERSION=5.18.0
ARG TARGETARCH
ARG SECLISTS_PLUGINS_URL=https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt
ARG SECLISTS_THEMES_URL=https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wp-themes.fuzz.txt

# Runtime libraries for WeasyPrint PDF output (Debian trixie package names)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libharfbuzz-subset0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r recon && useradd -r -m -g recon recon

WORKDIR /app
COPY --from=builder /build/dist /tmp/dist
RUN pip install --no-cache-dir --find-links /tmp/dist "wordpress-recon-tool[pdf]" \
    && rm -rf /tmp/dist

# External tools (opt-in via --build-arg INSTALL_TOOLS=true)
RUN if [ "$INSTALL_TOOLS" = "true" ]; then \
        set -eux; \
        arch="${TARGETARCH:-}"; \
        case "$arch" in \
            amd64|arm64) ;; \
            *) \
                arch="$(uname -m)"; \
                case "$arch" in \
                    x86_64) arch=amd64 ;; \
                    aarch64|arm64) arch=arm64 ;; \
                    *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
                esac ;; \
        esac; \
        apt-get update; \
        apt-get install -y --no-install-recommends \
            nmap ruby ruby-dev build-essential libcurl4-openssl-dev curl ca-certificates; \
        gem install --no-document wpscan -v "$WPSCAN_VERSION"; \
        apt-get purge -y ruby-dev build-essential; \
        apt-get autoremove -y; \
        rm -rf /var/lib/apt/lists/*; \
        curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${arch}.tar.gz" \
            | tar -xz -C /usr/local/bin ffuf; \
        curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${arch}.zip"; \
        python -m zipfile -e /tmp/nuclei.zip /usr/local/bin; \
        rm -f /tmp/nuclei.zip; \
        chmod +x /usr/local/bin/nuclei /usr/local/bin/ffuf; \
        pip install --no-cache-dir pipx; \
        pipx install --global opendoor=="$OPENDOOR_VERSION"; \
        HOME=/home/recon wpscan --update; \
        HOME=/home/recon nuclei -update-templates; \
    fi

# Built-in wordlists are always shipped
COPY wordlists/ wordlists/
COPY main.py config.py ./
COPY base/ base/
COPY core/ core/
COPY modules/ modules/
COPY steps/ steps/
COPY utils/ utils/
ENV PYTHONPATH=/app

# Recommended production wordlists (SecLists), opt-out via
# --build-arg INSTALL_RECOMMENDED_WORDLISTS=false. Downloaded into
# wordlists/external/ so ~/.config/recon-wp/wordlists/ overrides still win.
RUN if [ "$INSTALL_RECOMMENDED_WORDLISTS" = "true" ]; then \
        set -e; \
        mkdir -p wordlists/external/plugins; \
        [ -s wordlists/external/plugins/plugin_fallback.txt ] || \
            python -c "import urllib.request; urllib.request.urlretrieve('${SECLISTS_PLUGINS_URL}', 'wordlists/external/plugins/plugin_fallback.txt')"; \
        [ -s wordlists/external/plugins/theme_fallback.txt ] || \
            python -c "import urllib.request; urllib.request.urlretrieve('${SECLISTS_THEMES_URL}', 'wordlists/external/plugins/theme_fallback.txt')"; \
    fi

RUN chown -R recon:recon /app/wordlists /home/recon
USER recon

ENTRYPOINT ["wp-recon"]
CMD ["main", "--help"]
