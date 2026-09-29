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
ARG SECLISTS_DIRECTORIES_URL=https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt
ARG SECLISTS_FILES_URL=https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt

RUN groupadd -r recon && useradd -r -m -g recon recon

WORKDIR /app

# Base runtime dependencies (always installed)
# - ca-certificates/openssl: kept current so TLS verification works against
#   valid public chains without --insecure
# - whois: required by the passive WHOIS step
# - dnsutils: provides `dig`, required by the passive DNS + email-security steps
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates openssl whois dnsutils \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build-time TLS smoke test: fail the build if the CA store cannot verify a
# known-good public chain. Prevents shipping an image where HTTPS scans abort
# with "unable to get local issuer certificate".
RUN python -c "import urllib.request; urllib.request.urlopen('https://pypi.org/simple/', timeout=30); print('TLS CA store OK')"

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
            nmap ruby ruby-dev build-essential libcurl4-openssl-dev curl; \
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
        HOME=/home/recon nuclei -update-templates -ud /home/recon/nuclei-templates; \
        echo "--- installed tool versions ---"; \
        nmap --version | head -1; \
        ffuf -V; \
        dig -v 2>&1 | head -1; \
        HOME=/home/recon nuclei -version; \
        HOME=/home/recon wpscan --version; \
        opendoor --version || true; \
    fi

# Install the application wheel. Kept AFTER the (slow, source-independent)
# external-tool install so that code-only changes do not invalidate the tool
# layer and force a full rebuild.
COPY --from=builder /build/dist /tmp/dist
RUN pip install --no-cache-dir --find-links /tmp/dist "wordpress-recon-tool[pdf]" \
    && pip install --no-cache-dir --upgrade certifi \
    && rm -rf /tmp/dist

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
        mkdir -p wordlists/external/plugins wordlists/external/ffuf; \
        [ -s wordlists/external/plugins/plugin_fallback.txt ] || \
            python -c "import urllib.request; urllib.request.urlretrieve('${SECLISTS_PLUGINS_URL}', 'wordlists/external/plugins/plugin_fallback.txt')"; \
        [ -s wordlists/external/plugins/theme_fallback.txt ] || \
            python -c "import urllib.request; urllib.request.urlretrieve('${SECLISTS_THEMES_URL}', 'wordlists/external/plugins/theme_fallback.txt')"; \
        [ -s wordlists/external/ffuf/directories.txt ] || \
            python -c "import urllib.request; urllib.request.urlretrieve('${SECLISTS_DIRECTORIES_URL}', 'wordlists/external/ffuf/directories.txt')"; \
        [ -s wordlists/external/ffuf/files.txt ] || \
            python -c "import urllib.request; urllib.request.urlretrieve('${SECLISTS_FILES_URL}', 'wordlists/external/ffuf/files.txt')"; \
    fi

# Writable default output dir + a stable HOME so external tools (ffuf, nuclei)
# find their config under /home/recon even when started without a login shell.
RUN mkdir -p /app/reports && chown -R recon:recon /app/wordlists /app/reports /home/recon
ENV HOME=/home/recon
USER recon

ENTRYPOINT ["wp-recon"]
CMD ["main", "--help"]
