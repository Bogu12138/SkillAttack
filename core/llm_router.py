import json
import re
import os
import time
import uuid
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse

import requests
from openai import OpenAI
from core.config_loader import ConfigLoader

# Eval platform defaults (from api_try.py)
_EVAL_OPENAI_BASE_URL = os.environ.get("EVAL_OPENAI_BASE_URL", "")
_EVAL_PASSTHROUGH_BASE_URL = os.environ.get("EVAL_PASSTHROUGH_BASE_URL", "")

class LLMRouter:
    def __init__(self):
        self.config_loader = ConfigLoader()
        self._clients = {}

    @staticmethod
    def _is_local_base_url(base_url: Optional[str]) -> bool:
        if not base_url:
            return False
        try:
            host = (urlparse(str(base_url)).hostname or "").lower()
        except Exception:
            return False
        if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}:
            return True
        return host.startswith("172.17.")

    def _get_client(self, profile_name: str):
        if profile_name in self._clients:
            return self._clients[profile_name]

        profile = self.config_loader.get_model_profile(profile_name)
        if not profile:
            raise ValueError(f"Model profile '{profile_name}' not found.")

        provider = profile.get("provider")
        api_key_env = str(profile.get("api_key_env") or "").strip()
        api_key = profile.get("api_key")
        if isinstance(api_key, str):
            api_key = api_key.strip()
        if not api_key:
            api_key = os.getenv(api_key_env) if api_key_env else None
        if isinstance(api_key, str):
            api_key = api_key.strip()

        base_url_env = str(profile.get("base_url_env") or "").strip()
        base_url = profile.get("base_url")
        if isinstance(base_url, str):
            base_url = base_url.strip()
        if not base_url:
            base_url = os.getenv(base_url_env) if base_url_env else None
        if isinstance(base_url, str):
            base_url = base_url.strip()
        try:
            timeout_seconds = float(profile.get("timeout_seconds", 60))
        except Exception:
            timeout_seconds = 60.0
        if timeout_seconds <= 0:
            timeout_seconds = 60.0
        try:
            max_retries = int(profile.get("max_retries", 2))
        except Exception:
            max_retries = 2
        if max_retries < 0:
            max_retries = 0

        if provider == "eval_platform":
            # eval_platform uses app_id + app_key, not a single api_key
            client = EvalPlatformClient(profile)
            self._clients[profile_name] = (client, profile)
            return client, profile

        if not api_key:
            # Local OpenAI-compatible servers usually accept a dummy key.
            if self._is_local_base_url(base_url):
                api_key = os.getenv("LOCAL_LLM_API_KEY", "local-qwen")
            else:
                raise ValueError(f"API key not found. Please set the environment variable '{api_key_env}' as defined in models.yaml.")
        try:
            str(api_key).encode("ascii")
        except Exception:
            raise ValueError("API key contains non-ASCII characters.")

        if provider == "tencent_gemini":
            client = TencentGeminiClient(
                api_url=str(base_url or os.environ.get("TENCENT_GEMINI_BASE_URL", "")),
                api_key=api_key,
                model_name=str(profile.get("model") or "api_google_gemini-2.5-pro"),
                model_marker=str(profile.get("model_marker") or profile.get("model") or "api_google_gemini-2.5-pro"),
                timeout=int(timeout_seconds),
                max_retries=max_retries,
            )
            self._clients[profile_name] = (client, profile)
            return client, profile
        elif provider == "openai" or provider == "openai_compatible":
            extra_headers = profile.get("extra_headers")
            client_kwargs = {
                "api_key": api_key,
                "base_url": base_url,
                "timeout": timeout_seconds,
                "max_retries": max_retries,
            }
            if isinstance(extra_headers, dict) and extra_headers:
                client_kwargs["default_headers"] = {
                    str(k): str(v) for k, v in extra_headers.items()
                }
            client = OpenAI(**client_kwargs)
            self._clients[profile_name] = (client, profile)
            return client, profile
        else:
            raise NotImplementedError(f"Provider '{provider}' not supported yet.")

    def chat_completion(self, profile_name: str, messages: list, **kwargs) -> str:
        client, profile = self._get_client(profile_name)

        if isinstance(client, (TencentGeminiClient, EvalPlatformClient)):
            try:
                result = client.chat(messages)
                if result is None:
                    raise RuntimeError(f"API returned None for {profile_name}")
                return result
            except Exception as e:
                print(f"Error calling LLM {profile_name}: {e}")
                raise e

        # OpenAI-compatible path
        params = {
            "model": profile.get("model"),
            "temperature": profile.get("temperature", 0.7),
            "max_tokens": profile.get("max_tokens", 1000),
            "timeout": profile.get("request_timeout_seconds", profile.get("timeout_seconds", 60)),
        }
        profile_extra_body = profile.get("extra_body")
        if isinstance(profile_extra_body, dict) and profile_extra_body:
            params["extra_body"] = dict(profile_extra_body)
        params.update(kwargs)

        # Force-disable thinking/reasoning when requested by model profile.
        if profile.get("thinking") is False:
            existing_extra_body = params.get("extra_body")
            if not isinstance(existing_extra_body, dict):
                existing_extra_body = {}
            existing_extra_body = dict(existing_extra_body)
            existing_extra_body["enable_thinking"] = False
            params["extra_body"] = existing_extra_body

        try:
            response = client.chat.completions.create(
                messages=messages,
                **params
            )
            return response.choices[0].message.content
        except Exception as e:
            # Simple error handling
            print(f"Error calling LLM {profile_name}: {e}")
            raise e


class TencentGeminiClient:
    """Tencent internal Gemini 2.5 API client (non-OpenAI-compatible)."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        model_name: str,
        model_marker: str,
        timeout: int = 7200,
        max_retries: int = 3,
    ):
        self.api_url = api_url
        self.api_key = api_key
        self.model_name = model_name
        self.model_marker = model_marker
        self.timeout = timeout
        self.max_retries = max_retries
        self.headers = {"Content-Type": "application/json"}

    def chat(self, messages: List[Dict[str, str]]) -> Optional[str]:
        system_prompt = ""
        user_prompt = ""
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "system":
                system_prompt = content
            elif role == "user":
                if user_prompt:
                    user_prompt += "\n\n"
                user_prompt += content
            elif role == "assistant":
                if user_prompt:
                    user_prompt += "\n\n[Previous Assistant Response]:\n"
                user_prompt += content

        data = {
            "bid": "skillrt",
            "server": "open_api",
            "services": [],
            "bid_2": "SkillRT",
            "bid_3": "Judge",
            "request_id": f"skillrt_{uuid.uuid4()}",
            "session_id": f"session_{uuid.uuid4()}",
            "api_key": self.api_key,
            "model_name": self.model_name,
            "model_marker": self.model_marker,
            "system": system_prompt,
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "value": user_prompt}],
                }
            ],
            "params": {"generationConfig": {"maxOutputTokens": 65536}},
            "general_params": {},
            "timeout": self.timeout,
            "seed": 1234,
            "extension": {},
            "stream": False,
        }

        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    self.api_url,
                    headers=self.headers,
                    json=data,
                    timeout=self.timeout,
                )
                if response.status_code == 200:
                    result = self._parse_response(response.text, attempt)
                    if result:
                        return result
                else:
                    print(f"  [Attempt {attempt+1}] Tencent API status: {response.status_code}")
            except requests.exceptions.Timeout:
                print(f"  [Attempt {attempt+1}] Tencent API timeout after {self.timeout}s")
            except requests.exceptions.RequestException as e:
                print(f"  [Attempt {attempt+1}] Tencent API request error: {e}")

            if attempt < self.max_retries - 1:
                wait_time = 2 ** attempt
                time.sleep(wait_time)

        return None

    @staticmethod
    def _parse_response(response_text: str, attempt: int) -> Optional[str]:
        try:
            res = json.loads(response_text)
        except json.JSONDecodeError as e:
            print(f"  [Attempt {attempt+1}] Failed to parse Tencent API response: {e}")
            return None

        if res.get("code") != 0:
            print(f"  [Attempt {attempt+1}] Tencent API error code={res.get('code')}, msg={res.get('msg', '')}")
            return None

        if "answer" in res and isinstance(res["answer"], list) and res["answer"]:
            item = res["answer"][0]
            if isinstance(item, dict) and "value" in item:
                return item["value"]
            if isinstance(item, str):
                return item

        for path in [("data", "response"), ("response",), ("choices", 0, "message", "content")]:
            value = res
            try:
                for key in path:
                    value = value[key] if isinstance(key, int) else value.get(key)
                    if value is None:
                        break
                if value:
                    return value
            except (IndexError, KeyError, TypeError):
                continue

        print(f"  [Attempt {attempt+1}] Unknown Tencent API response structure: {list(res.keys())}")
        return None


class EvalPlatformClient:
    """Tencent eval platform client supporting passthrough/openai/openai_chat protocols (from api_try.py)."""

    def __init__(self, profile: Dict[str, Any]):
        self.app_id = str(profile.get("app_id") or "")
        self.app_key = str(profile.get("app_key") or "")
        self.model = str(profile.get("model") or "")
        self.model_full_name = str(profile.get("model_full_name") or self.model)
        self.protocol = str(profile.get("protocol") or "passthrough")
        self.api_type = str(profile.get("api_type") or "responses")
        self.eval_provider = str(profile.get("eval_provider") or "openai")
        self.endpoint = str(profile.get("endpoint") or "/v1/responses")
        self.timeout = int(profile.get("timeout_seconds", 300))
        self.max_retries = int(profile.get("max_retries", 5))
        self.openai_base_url = str(profile.get("openai_base_url") or _EVAL_OPENAI_BASE_URL)
        self.passthrough_base_url = str(profile.get("passthrough_base_url") or _EVAL_PASSTHROUGH_BASE_URL)

    @staticmethod
    def _strip_think_block(text: str) -> str:
        return re.sub(r"^\s*<think>[\s\S]*?</think>\s*", "", text, count=1)

    def chat(self, messages: List[Dict[str, str]]) -> Optional[str]:
        last_exc = None
        for attempt in range(self.max_retries):
            try:
                if self.protocol == "openai":
                    return self._call_openai_responses(messages)
                elif self.protocol == "openai_chat":
                    return self._call_openai_chat(messages)
                elif self.protocol == "passthrough":
                    return self._call_passthrough(messages)
                else:
                    raise ValueError(f"Unknown eval_platform protocol: {self.protocol}")
            except Exception as e:
                last_exc = e
                err_str = str(e).lower()
                retryable = any(kw in err_str for kw in [
                    "rate", "limit", "429", "500", "502", "503", "504",
                    "timeout", "connection",
                ])
                if retryable and attempt < self.max_retries - 1:
                    delay = 2 * (2 ** attempt)
                    print(f"  [Attempt {attempt+1}] Eval platform error: {e}, retrying in {delay}s...")
                    time.sleep(delay)
                else:
                    break
        if last_exc:
            raise last_exc
        return None

    def _call_openai_responses(self, messages: List[Dict[str, str]]) -> str:
        client = OpenAI(
            api_key=f"{self.app_id}:{self.app_key}",
            base_url=self.openai_base_url,
            timeout=self.timeout,
        )
        response = client.responses.create(
            model=self.model_full_name,
            input=messages,
        )
        return response.output_text

    def _call_openai_chat(self, messages: List[Dict[str, str]]) -> str:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.app_id}:{self.app_key}",
        }
        body = {"model": self.model_full_name, "messages": messages, "stream": False}
        base = self.openai_base_url.rstrip("/").rsplit("/v1", 1)[0]
        r = requests.post(f"{base}/v1/chat/completions", headers=headers, json=body, timeout=self.timeout)
        result = r.json()
        if r.status_code != 200:
            raise RuntimeError(f"openai_chat error (HTTP {r.status_code}): {json.dumps(result, ensure_ascii=False)[:500]}")
        choices = result.get("choices", [])
        if choices:
            content = choices[0].get("message", {}).get("content", "")
            if content:
                return self._strip_think_block(content)
        return json.dumps(result, ensure_ascii=False, indent=2)

    def _call_passthrough(self, messages: List[Dict[str, str]]) -> str:
        bearer = f"{self.app_id}:{self.app_key}?provider={self.eval_provider}&model={self.model}&timeout={self.timeout}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer}",
        }
        if self.api_type == "responses":
            body: Dict[str, Any] = {"model": self.model, "input": messages}
        else:
            body = {"model": self.model, "messages": messages, "stream": False}

        r = requests.post(
            f"{self.passthrough_base_url}{self.endpoint}",
            headers=headers, json=body, timeout=self.timeout,
        )
        result = r.json()
        if r.status_code != 200:
            raise RuntimeError(f"passthrough error (HTTP {r.status_code}): {json.dumps(result, ensure_ascii=False)[:500]}")

        if self.api_type == "responses":
            for item in result.get("output", []):
                if item.get("type") == "message":
                    for c in item.get("content", []):
                        if c.get("type") == "output_text" and c.get("text"):
                            return c["text"]
        else:
            choices = result.get("choices", [])
            if choices:
                content = choices[0].get("message", {}).get("content", "")
                if content:
                    return self._strip_think_block(content)

        return json.dumps(result, ensure_ascii=False, indent=2)
