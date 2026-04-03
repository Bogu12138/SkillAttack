# OpenClaw Simulator Environment

This directory contains the Docker configuration for running OpenClaw as a persistent simulator service for SkillRT.

## Setup

1.  **Build and Start the Container**:
    ```bash
    cd sandbox/openclaw
    docker-compose up -d --build
    ```

2.  **Verify Installation**:
    ```bash
    docker exec skillrt-openclaw openclaw --version
    ```

3.  **Configuration**:
    - The OpenClaw configuration and data are persisted in the `./data` directory (mapped to `/root/.openclaw`).
    - You can exec into the container to configure gateways:
      ```bash
      docker exec -it skillrt-openclaw bash
      # Inside container:
      openclaw gateway add ...
      ```

## Usage in SkillRT

The `OpenClawSimulator` in `stages/simulator/openclaw.py` connects to this container.
It expects the container named `skillrt-openclaw` to be running.

You can customize the command executed in the container by editing `configs/stages.yaml`:

```yaml
simulator:
  impl: simulator.openclaw
  container_name: skillrt-openclaw
  command_template: "openclaw gateway call chat.send --input '@{json_file}'"
```
