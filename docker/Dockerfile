# ReconEngine Docker Image
# Base: Kali Linux Rolling
# Build:  docker build -t recon-engine -f docker/Dockerfile .
# Run:    docker run --rm -v $(pwd)/output:/app/output -v $(pwd)/scopes:/app/scopes \
#           recon-engine --csv /app/scopes/scope.csv --profile fast

FROM kalilinux/kali-rolling

# System packages incl. gcc for aiohttp C extensions
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    nmap amass whatweb theharvester \
    python3 python3-pip python3-venv \
    golang-go git curl wget jq dnsutils ca-certificates \
    gcc python3-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Go environment
ENV GOPATH=/root/go
ENV PATH="${GOPATH}/bin:${PATH}"

# Go tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/d3mondev/puredns/v2@latest
RUN go install github.com/ffuf/ffuf/v2@latest
RUN go install github.com/sensepost/gowitness@latest
RUN go install github.com/tomnomnom/gf@latest
RUN go install github.com/tomnomnom/anew@latest
RUN go install github.com/tomnomnom/waybackurls@latest

# gf community patterns
RUN mkdir -p /root/.gf \
    && git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns \
    && cp /tmp/gf-patterns/*.json /root/.gf/ \
    && rm -rf /tmp/gf-patterns

# paramspider — install from source (no stable PyPI release)
RUN git clone https://github.com/devanshbatham/paramspider /tmp/paramspider \
    && pip3 install /tmp/paramspider --break-system-packages --no-cache-dir -q \
    && rm -rf /tmp/paramspider

# Nuclei templates
RUN nuclei -update-templates -silent || true

# Python deps (after gcc is available so aiohttp compiles cleanly)
COPY requirements.txt /app/requirements.txt
RUN pip3 install --break-system-packages --no-cache-dir -r /app/requirements.txt

# Copy source last (preserves Docker layer cache on code changes)
WORKDIR /app
COPY . /app

VOLUME ["/app/output"]
ENTRYPOINT ["python3", "main.py"]
