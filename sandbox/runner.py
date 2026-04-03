import os
import sys
import shutil
import tempfile
import socket
import subprocess
from typing import Dict, Any, Optional
from urllib.parse import urlparse

class SandboxRunner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.execution_mode = "docker"
        import docker as docker_mod
        self.docker = docker_mod
        self.client = docker_mod.from_env()
        self.image_tag = "skill-redteam-sandbox"
        self._ensure_image()

    def _ensure_image(self):
        # Only build the docker image if not exists
        if not self.client or not self.docker:
            return
        force_rebuild = bool(self.config.get("rebuild_image")) or os.environ.get("REBUILD_SANDBOX_IMAGE") == "1"
        try:
            self.client.images.get(self.image_tag)
        except self.docker.errors.ImageNotFound:
            print(f"Image {self.image_tag} not found, building...")
            self._build_image()
            return
        if force_rebuild:
            print(f"Rebuilding image {self.image_tag}...")
            self._build_image()

    def _build_image(self):
        # Build the docker image if not exists
        if not self.client:
            raise RuntimeError("Docker client not initialized.")
        dockerfile_path = os.path.dirname(os.path.abspath(__file__))
        
        # We need to copy agent_runner.py to Docker build context (if it's not already there)
        # But Dockerfile expects agent_runner.py in context.
        # Dockerfile is in sandbox/, agent_runner.py is in sandbox/.
        
        build_network_mode = str(self.config.get("build_network_mode", "host")).strip() or "host"
        build_nocache = bool(self.config.get("build_nocache", False))
        build_pull = bool(self.config.get("build_pull", True))
        base_image_cfg = os.environ.get("SANDBOX_BASE_IMAGE") or self.config.get("base_image") or ""
        base_image_cfg = str(base_image_cfg).strip()
        base_image_explicit = bool(base_image_cfg)
        base_image = base_image_cfg or "python:3.12-slim"

        def run_build(buildargs: Dict[str, str]) -> None:
            for chunk in self.client.api.build(
                path=dockerfile_path,
                tag=self.image_tag,
                network_mode=build_network_mode,
                nocache=build_nocache,
                pull=build_pull,
                buildargs=buildargs,
                decode=True,
            ):
                if not isinstance(chunk, dict):
                    continue
                error = chunk.get("error")
                if error:
                    raise RuntimeError(str(error).strip())
                stream = chunk.get("stream")
                if isinstance(stream, str) and stream:
                    sys.stdout.write(stream)
                    sys.stdout.flush()

        try:
            run_build({"BASE_IMAGE": base_image})
        except Exception as e:
            msg = str(e)
            if (
                (not base_image_explicit)
                and ("registry-1.docker.io" in msg or "EOF" in msg or "tls" in msg.lower())
            ):
                mirror = "docker.m.daocloud.io/library/python:3.12-slim"
                print(f"Retrying build with BASE_IMAGE={mirror}...")
                run_build({"BASE_IMAGE": mirror})
                return
            print(f"Error building docker image: {e}")
            raise e

    def _get_default_gateway(self) -> Optional[str]:
        try:
            output = subprocess.check_output(["ip", "route"], text=True)
        except Exception:
            return None

        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("default "):
                continue
            parts = line.split()
            if "via" in parts:
                via_index = parts.index("via")
                if via_index + 1 < len(parts):
                    return parts[via_index + 1]
        return None

    def _tcp_connectable(self, host: str, port: int, timeout_sec: float) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout_sec):
                return True
        except Exception:
            return False

    def _inject_proxy_env(self, env_vars: Dict[str, str]) -> Dict[str, str]:
        proxy_keys = [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ]

        merged = dict(env_vars or {})
        no_proxy_default = "localhost,127.0.0.1,::1,host.docker.internal,172.16.0.0/12,10.0.0.0/8,192.168.0.0/16"

        base_url = None
        for k, v in merged.items():
            if not isinstance(v, str):
                continue
            if k == "QWEN_BASE_URL" or k.endswith("_BASE_URL") or k.endswith("BASE_URL"):
                if v.strip():
                    base_url = v.strip()
                    break

        if base_url:
            try:
                host = (urlparse(base_url).hostname or "").lower()
            except Exception:
                host = ""
            if host == "dashscope.aliyuncs.com" or host.endswith(".dashscope.aliyuncs.com"):
                for key in proxy_keys:
                    merged.pop(key, None)
                return merged

        def normalize_proxy_env(values: Dict[str, str]) -> Dict[str, str]:
            if "HTTP_PROXY" in values and "http_proxy" not in values:
                values["http_proxy"] = values["HTTP_PROXY"]
            if "http_proxy" in values and "HTTP_PROXY" not in values:
                values["HTTP_PROXY"] = values["http_proxy"]

            if "HTTPS_PROXY" in values and "https_proxy" not in values:
                values["https_proxy"] = values["HTTPS_PROXY"]
            if "https_proxy" in values and "HTTPS_PROXY" not in values:
                values["HTTPS_PROXY"] = values["https_proxy"]

            if "ALL_PROXY" in values and "all_proxy" not in values:
                values["all_proxy"] = values["ALL_PROXY"]
            if "all_proxy" in values and "ALL_PROXY" not in values:
                values["ALL_PROXY"] = values["all_proxy"]

            if "NO_PROXY" in values and "no_proxy" not in values:
                values["no_proxy"] = values["NO_PROXY"]
            if "no_proxy" in values and "NO_PROXY" not in values:
                values["NO_PROXY"] = values["no_proxy"]

            values.setdefault(
                "NO_PROXY",
                os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or no_proxy_default,
            )
            values.setdefault("no_proxy", values.get("NO_PROXY", ""))
            return values

        has_explicit_proxy = any(
            key in merged and str(merged.get(key, "")).strip() for key in proxy_keys if key != "NO_PROXY" and key != "no_proxy"
        )
        if has_explicit_proxy:
            return normalize_proxy_env(merged)

        inherited_any = False
        for key in proxy_keys:
            value = os.environ.get(key)
            if value and key not in merged:
                merged[key] = value
                inherited_any = True
        if inherited_any:
            return normalize_proxy_env(merged)

        proxy_port = int(self.config.get("proxy_port", 7890))
        proxy_host = str(self.config.get("proxy_host", "")).strip() or self._get_default_gateway()
        if not proxy_host:
            return merged

        if not self._tcp_connectable(proxy_host, proxy_port, timeout_sec=0.2):
            return merged

        proxy_url = f"http://{proxy_host}:{proxy_port}"

        merged.setdefault("HTTP_PROXY", proxy_url)
        merged.setdefault("HTTPS_PROXY", proxy_url)
        merged.setdefault("ALL_PROXY", proxy_url)
        merged.setdefault("NO_PROXY", no_proxy_default)
        return normalize_proxy_env(merged)

    def run_agent(self, skill_content: str, prompt: str, run_id: str, env_vars: Dict[str, str]) -> Dict[str, Any]:
        """
        Runs the agent inside the sandbox.
        skill_content: Content of the skill (SKILL.md or script)
        prompt: User prompt for the agent
        run_id: Unique run ID
        env_vars: Environment variables (API Key, Base URL, etc.)
        """
        # Create a temp directory for this run
        # Use a local directory instead of /tmp to avoid potential Docker mount issues
        temp_root = os.path.join(os.getcwd(), "data", "temp")
        os.makedirs(temp_root, exist_ok=True)
        # tempfile.mkdtemp will create a directory with secure permissions (0700) by default
        # We need to make sure Docker can access it.
        temp_dir = tempfile.mkdtemp(dir=temp_root)
        try:
            os.chmod(temp_dir, 0o777)
        except Exception:
            pass
        
        try:
            input_dir = os.path.join(temp_dir, "input")
            os.makedirs(input_dir, mode=0o777, exist_ok=True)
            output_dir = os.path.join(temp_dir, "output")
            os.makedirs(output_dir, mode=0o777, exist_ok=True)
            
            # Write skill and prompt to files
            with open(os.path.join(input_dir, "skill.md"), "w") as f:
                f.write(skill_content)
            
            with open(os.path.join(input_dir, "prompt.txt"), "w") as f:
                f.write(prompt)
                
            # Ensure permissions for Docker mount
            try:
                os.chmod(temp_dir, 0o777)
                os.chmod(input_dir, 0o777)
                os.chmod(output_dir, 0o777)
                os.chmod(os.path.join(input_dir, "skill.md"), 0o666)
                os.chmod(os.path.join(input_dir, "prompt.txt"), 0o666)
            except Exception:
                pass
                
            effective_env = self._inject_proxy_env(env_vars)

            # Run the container
            # Mount input_dir to /app/input, output_dir to /app/output
            # Network: We must enable network if the Agent calls external API
            # User config says network_enabled: false by default, but for API call it MUST be true.
            # We assume if env_vars contain API URL, we need network.
            network_mode = "host"
            
            # We also need to copy agent_runner.py? No, it's baked into image.
            
            if not self.client:
                raise RuntimeError("Docker execution requested but docker client not initialized.")

            container = self.client.containers.run(
                image=self.image_tag,
                command=["python", "/app/agent_runner.py"],
                volumes={
                    input_dir: {'bind': '/app/input', 'mode': 'ro'},
                    output_dir: {'bind': '/app/output', 'mode': 'rw'},
                },
                environment=effective_env,
                network_mode=network_mode,
                detach=True,
                # dns=['8.8.8.8', '8.8.4.4'] # Use Google DNS to avoid DNS issues in containers
            )
            
            timeout = self.config.get("timeout_sec", 120)
            try:
                result = container.wait(timeout=timeout)
            except Exception:
                try:
                    container.kill()
                except Exception:
                    pass
                result = {"StatusCode": -1}
            finally:
                try:
                    stdout_bytes = container.logs(stdout=True, stderr=False)
                    stderr_bytes = container.logs(stdout=False, stderr=True)
                except Exception:
                    stdout_bytes = b""
                    stderr_bytes = b""
                
                try:
                    container.remove(force=True)
                except Exception:
                    pass

            # Read logs directly from container logs
            # Or we could have redirected stdout/stderr to files in agent_runner.py
            # But simpler to just get container logs.
            # But logs is bytes.
            
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            
            # Docker API returns multiplexed stream.
            
            return {
                "stdout_content": stdout,
                "stderr_content": stderr,
                "file_changes_content": "[]", # Placeholder
                "summary": f"Exit Code: {result.get('StatusCode')}"
            }
            
        finally:
            if self.config.get("cleanup_after_run", True):
                shutil.rmtree(temp_dir)
