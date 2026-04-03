ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

WORKDIR /app

# Install dependencies for the agent
# Using aliyun mirror for stability in CN
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    poppler-utils \
    libsndfile1 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir qwen-agent openai requests httpx numpy pandas scipy matplotlib soundfile -i https://mirrors.aliyun.com/pypi/simple/

# Create workspace directory for Code Interpreter
RUN mkdir -p /app/workspace && chmod 777 /app/workspace

# The runner script will be mounted or copied here
COPY agent_runner.py /app/agent_runner.py

CMD ["python", "/app/agent_runner.py"]
