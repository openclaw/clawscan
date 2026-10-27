FROM python:3.12-slim

ARG SKILLSPECTOR_REF=95a52d89fa16f608f0b18ccee76b0918ea4b7eef
ARG AIG_SKILL_SCAN_REF=a5c5a72c2e5b88fc6e5b27e0c86110943c4d350b
ARG CISCO_AI_SKILL_SCANNER_VERSION=2.2.0
ARG SNYK_AGENT_SCAN_VERSION=0.6.8
ARG CLAUDE_CODE_VERSION=2.1.309
ARG OPENAI_CODEX_VERSION=0.164.0
ARG AGENTVERUS_SCANNER_VERSION=0.8.1
ARG SOCKET_CLI_VERSION=1.4.2

ENV SKILLSPECTOR_BUILD_REVISION=$SKILLSPECTOR_REF

ENV PATH="/root/.local/bin:${PATH}" \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY patches/ /tmp/clawscan-patches/
COPY tests/ /tmp/clawscan-adapter-tests/

# Exact upstream pins fail closed if a transport patch stops applying.
RUN git init /tmp/skillspector \
    && git -C /tmp/skillspector remote add origin https://github.com/NVIDIA/skillspector.git \
    && git -C /tmp/skillspector fetch --depth 1 origin "$SKILLSPECTOR_REF" \
    && git -C /tmp/skillspector checkout --detach FETCH_HEAD \
    && git -C /tmp/skillspector apply --check /tmp/clawscan-patches/skillspector-responses.patch \
    && git -C /tmp/skillspector apply /tmp/clawscan-patches/skillspector-responses.patch \
    && git init /tmp/aig \
    && git -C /tmp/aig remote add origin https://github.com/Tencent/AI-Infra-Guard.git \
    && git -C /tmp/aig fetch --depth 1 origin "$AIG_SKILL_SCAN_REF" \
    && git -C /tmp/aig checkout --detach FETCH_HEAD \
    && git -C /tmp/aig apply --check /tmp/clawscan-patches/aig-responses.patch \
    && git -C /tmp/aig apply /tmp/clawscan-patches/aig-responses.patch

RUN python -m pip install --no-cache-dir --upgrade pip uv \
    && python -m pip install --no-cache-dir /tmp/skillspector pytest \
      "cisco-ai-skill-scanner==$CISCO_AI_SKILL_SCANNER_VERSION" \
    && python -m pytest -q /tmp/clawscan-adapter-tests/test_skillspector_responses.py /tmp/clawscan-adapter-tests/test_skillspector_applicability.py /tmp/clawscan-adapter-tests/test_skillspector_accounting.py /tmp/clawscan-adapter-tests/test_skillspector_frontmatter_json.py \
    && uv tool install /tmp/aig/skill-scan --with pytest \
    && /root/.local/share/uv/tools/aig-skill-scan/bin/python -m pytest -q /tmp/clawscan-adapter-tests/test_aig_responses.py \
    && uv tool install "snyk-agent-scan==$SNYK_AGENT_SCAN_VERSION" \
    && ln -sf /root/.local/bin/snyk-agent-scan /usr/local/bin/snyk-agent-scan \
    && rm -rf /tmp/skillspector /tmp/aig /tmp/clawscan-patches /tmp/clawscan-adapter-tests

RUN ln -sf /root/.local/bin/aig-skill-scan /usr/local/bin/aig-skill-scan

RUN npm install -g \
      "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
      "@openai/codex@${OPENAI_CODEX_VERSION}" \
      "agentverus-scanner@${AGENTVERUS_SCANNER_VERSION}" \
      "socket@${SOCKET_CLI_VERSION}"

WORKDIR /workspace
