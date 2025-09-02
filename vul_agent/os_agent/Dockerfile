# Dockerfile for Vulnerability Agent (OS Agent)
# Change the FROM line to test different OS images (e.g., ubuntu, debian, alpine)
FROM ubuntu:22.04

WORKDIR /agent

# Install Python and required system packages
RUN apt-get update && \
    apt-get install -y python3 python3-pip curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 9000

CMD ["python3", "vul_agent.py", "--scan"]
