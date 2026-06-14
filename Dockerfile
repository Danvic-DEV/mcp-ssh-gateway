# Dockerfile for mcp-ssh-gateway

# Use a lightweight and stable Python base
FROM python:3.10-slim

# Set default environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src

# Set the working directory
WORKDIR /app

# Install ssh-keygen for first-run keypair generation
RUN apt-get update \
	&& apt-get install -y --no-install-recommends openssh-client \
	&& rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire source code (including src/)
COPY . /app

# Add startup entrypoint that ensures a persistent SSH key exists
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Persist generated SSH keys outside the writable container layer
VOLUME ["/app/ssh_keys"]

# Startup command. Runs the MCP server
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-m", "ssh_mcp_server.server"]
