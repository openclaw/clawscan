FROM python:3.12-slim

ENV PATH="/root/.local/bin:${PATH}" \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir --upgrade pip uv \
    && python -m pip install --no-cache-dir \
      "git+https://github.com/NVIDIA/skillspector.git" \
      "cisco-ai-skill-scanner" \
    && uv tool install "snyk-agent-scan@latest" \
    && ln -sf /root/.local/bin/snyk-agent-scan /usr/local/bin/snyk-agent-scan

RUN npm install -g @anthropic-ai/claude-code @openai/codex agentverus-scanner socket

WORKDIR /workspace
