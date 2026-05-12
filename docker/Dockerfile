# ReconEngine Docker Image
# Base: Kali Linux Rolling
# Includes: Go tools + Python tools + nmap + amass

FROM kalilinux/kali-rolling

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    nmap amass whatweb python3 python3-pip python3-venv \
    golang-go git curl wget jq dnsutils ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/ffuf/ffuf/v2@latest
RUN go install github.com/sensepost/gowitness@latest
RUN go install github.com/tomnomnom/gf@latest
RUN go install github.com/tomnomnom/anew@latest
RUN go install github.com/tomnomnom/waybackurls@latest

RUN mkdir -p /root/.gf \
    && git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns \
    && cp /tmp/gf-patterns/*.json /root/.gf/ \
    && rm -rf /tmp/gf-patterns

RUN nuclei -update-templates -silent || true

COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt

WORKDIR /app
COPY . /app

VOLUME ["/app/output"]
ENTRYPOINT ["python3", "main.py"]
