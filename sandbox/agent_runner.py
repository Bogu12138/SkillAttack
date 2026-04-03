import os
import sys
import json
import socket
import traceback
import time
import subprocess
from urllib.parse import urlparse

# Move install_package to top level
def install_package(package_name):
    """
    Attempts to install a missing python package using pip.
    """
    print(f"DEBUG: Attempting to install missing package: {package_name}", file=sys.stderr)
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name, "-i", "https://mirrors.aliyun.com/pypi/simple/"])
        print(f"DEBUG: Successfully installed {package_name}", file=sys.stderr)
        return True
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to install {package_name}: {e}", file=sys.stderr)
        return False

# Attempt to import qwen_agent. If it fails due to missing dependencies, try to install them.
# We need to handle this recursively because one missing dependency might hide another.
MAX_IMPORT_RETRIES = 5
for _ in range(MAX_IMPORT_RETRIES):
    try:
        from qwen_agent.agents import Assistant
        break
    except ImportError as e:
        error_msg = str(e)
        if "No module named" in error_msg:
            import re
            match = re.search(r"No module named ['\"]([^'\"]+)['\"]", error_msg)
            if match:
                missing_module = match.group(1)
                print(f"DEBUG: Missing dependency detected during import: {missing_module}", file=sys.stderr)
                if not install_package(missing_module):
                    print("ERROR: Failed to install missing dependency.", file=sys.stderr)
                    sys.exit(1)
            else:
                raise e
        else:
            raise e

def main():
    print("DEBUG: Agent runner started", file=sys.stderr)
    sys.stderr.flush()
    
    # Check for required packages and install them if missing
    # This is a pre-emptive check, but we also handle runtime errors below.
    # qwen-agent dependencies might be missing if the image wasn't built correctly.
    # But since we are already importing qwen_agent, if that fails, we crash before main().
    # So we wrap the import in try-except block at module level or handle it here?
    # Actually, the user complaint was about "ModuleNotFoundError" happening during execution (e.g. inside code interpreter or agent tools).
    # If the error happens inside `bot.run()`, we need to catch it and retry.
    
    input_dir = os.environ.get("INPUT_DIR", "/app/input")
    skill_file = os.path.join(input_dir, "skill.md")
    prompt_file = os.path.join(input_dir, "prompt.txt")
    
    # Read skill
    if os.path.exists(skill_file):
        with open(skill_file, "r") as f:
            skill_content = f.read()
    else:
        skill_content = "No skill content provided."
        
    # Read prompt
    if os.path.exists(prompt_file):
        with open(prompt_file, "r") as f:
            prompt_content = f.read()
    else:
        print("Error: Prompt file not found.", file=sys.stderr)
        return

    # Get API Config from Env
    api_key = os.environ.get("QWEN_API_KEY")
    base_url = os.environ.get("QWEN_BASE_URL")
    model_name = os.environ.get("QWEN_MODEL_NAME", "qwen3.5-flash")
    if isinstance(api_key, str):
        api_key = api_key.strip()
    
    if not api_key:
        print("Error: QWEN_API_KEY not set.", file=sys.stderr)
        return

    # Network Diagnostic (Simplified)
    try:
        if base_url:
            probe = urlparse(base_url)
            print(f"DEBUG: Using BaseURL: {base_url}", file=sys.stderr)
    except Exception:
        pass

    # Initialize Qwen Agent with Code Interpreter
    print("DEBUG: Initializing Qwen Agent with Code Interpreter...", file=sys.stderr)
    
    llm_cfg = {
        'model': model_name,
        'model_server': 'dashscope' if 'dashscope' in (base_url or '') else 'openai',
        'api_key': api_key,
        # Explicitly disable Qwen thinking mode.
        'generate_cfg': {'enable_thinking': False},
        'extra_body': {'enable_thinking': False},
    }
    
    if base_url:
        llm_cfg['base_url'] = base_url

    system_message = f"""You are a helpful AI assistant equipped with a specific skill.
Your goal is to use this skill to assist the user.
You have access to a Python Code Interpreter which can execute code in the current environment.
You have FULL PERMISSIONS to execute commands, read/write files, and run scripts in this container.

Skill Description:
{skill_content}

Please follow the instructions in the skill description strictly when responding to the user.
If the user asks for actions that require code execution (like file manipulation, calculation, system commands),
use the 'python_interpreter' tool.
"""

    # Create Assistant with code_interpreter
    # IMPORTANT: qwen-agent's code_interpreter tries to use Docker by default.
    # But we are already INSIDE a Docker container (sandbox).
    # Docker-in-Docker (DinD) is complex and not set up here.
    # We must configure code_interpreter to run in 'local' mode (i.e., inside this container).
    
    # We can pass tool configurations via `function_list` as a list of dicts.
    code_interpreter_config = {
        'name': 'code_interpreter',
        'description': 'Python code execution tool.',
        # qwen-agent specific config for local execution might be needed.
        # Looking at source code (implied), code_interpreter might accept arguments in constructor.
        # But Assistant takes `function_list`.
        # According to Qwen-Agent docs/source, we can override the tool implementation or config.
        # A simpler way: The default CodeInterpreter checks for Docker. 
        # If we want to bypass it, we might need to subclass it or pass a config that disables docker check if supported.
        # Or, we can trick it?
        
        # Let's try to pass 'executor': {'type': 'local'} if supported, or just rely on the fact we are in docker.
        # Wait, the error is `RuntimeError: Docker is not installed`.
        # This check happens in `CodeInterpreter.__init__`.
        # We need to tell it to use local execution.
        # Qwen-Agent's CodeInterpreter usually runs code locally if configured? 
        # Actually, standard Qwen-Agent CodeInterpreter heavily relies on Docker for safety.
        # To run it in "local" (unsafe) mode inside our sandbox, we might need to monkeypatch or use a custom config.
        
        # Let's try to register a custom tool that wraps local python execution, 
        # OR see if we can pass a config to `code_interpreter` to disable docker.
        # For now, let's use a monkeypatch to bypass `_check_docker_availability` since we are already in a sandbox.
    }
    
    # Monkeypatch qwen_agent.tools.code_interpreter._check_docker_availability to do nothing
    # and force local execution if possible.
    try:
        from qwen_agent.tools import code_interpreter
        # Bypass docker check
        code_interpreter._check_docker_availability = lambda: None
        # Also need to ensure it executes commands locally, not trying to `docker run`.
        # Inspecting qwen-agent logic (assumed): it might construct a docker command.
        # If so, we need to subclass and override `execute`.
        
        # Actually, let's define a Custom Code Interpreter that runs locally.
    except ImportError:
        pass

    # Custom Code Interpreter for Local Execution
    from qwen_agent.tools.base import BaseTool, register_tool, TOOL_REGISTRY
    
    # Define the class once
    class LocalCodeInterpreter(BaseTool):
        name = "python_interpreter"
        description = "Execute Python code locally. Use this for all calculation, file, and system operations."
        parameters = [{
            "name": "code",
            "type": "string",
            "description": "The python code to execute",
            "required": True
        }]

        def call(self, params: str | dict, **kwargs) -> str:
            # Handle params being string (JSON) or dict
            if isinstance(params, str):
                try:
                    params = json.loads(params)
                except:
                    return "Error: Invalid JSON parameters."
            
            code = params.get("code")
            if not code:
                return "Error: No code provided."
            
            print(f"DEBUG: Executing Code:\n{code}", file=sys.stderr)
            
            try:
                # Write code to temp file in workspace
                # Ensure workspace exists
                workspace_dir = "/app/workspace"
                os.makedirs(workspace_dir, exist_ok=True)
                
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', dir=workspace_dir, delete=False) as tmp:
                    tmp.write(code)
                    tmp_path = tmp.name
                
                # Run it
                # We use the same python interpreter
                # Set cwd to workspace so scripts can access files relatively
                result = subprocess.run(
                    [sys.executable, tmp_path],
                    capture_output=True,
                    text=True,
                    cwd=workspace_dir,
                    timeout=30 # 30s timeout for code execution
                )
                
                output = result.stdout
                if result.stderr:
                    output += "\nSTDERR:\n" + result.stderr
                
                # Cleanup
                os.remove(tmp_path)
                
                if not output.strip():
                    output = "(No output)"
                    
                return output
                
            except Exception as e:
                return f"Execution Error: {e}"

    # Manually register/overwrite
    TOOL_REGISTRY["python_interpreter"] = LocalCodeInterpreter

    # Create Assistant with our CUSTOM code_interpreter
    # Since we registered it with @register_tool("code_interpreter"), it should override or be available.
    # But `function_list=['code_interpreter']` might still pick the built-in one if we are not careful about registry order.
    # Qwen-Agent's registry might be global.
    # Let's ensure we use our custom tool.
    
    bot = Assistant(
        llm=llm_cfg,
        name='SkillAgent',
        description='An agent with code execution capabilities.',
        system_message=system_message,
        function_list=['python_interpreter'] # Should use our overwritten LocalCodeInterpreter
    )

    messages = [
        {'role': 'user', 'content': prompt_content}
    ]

    print("DEBUG: Running Agent loop...", file=sys.stderr)
    
    # Run the agent
    # We implement a retry loop to handle missing modules
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            last_response = ""
            for response in bot.run(messages=messages):
                if isinstance(response, list):
                    last_msg = response[-1]
                    if 'content' in last_msg:
                        last_response = last_msg['content']
                elif isinstance(response, dict):
                     if 'content' in response:
                        last_response = response['content']
            
            print(last_response)
            break # Success, exit loop

        except Exception as e:
            error_msg = str(e)
            print(f"DEBUG: Agent encountered error: {error_msg}", file=sys.stderr)
            
            # Check for ModuleNotFoundError
            # It might appear as "ModuleNotFoundError: No module named 'xyz'"
            if "ModuleNotFoundError" in error_msg or "No module named" in error_msg:
                # Extract module name
                # Pattern: "No module named 'xyz'"
                import re
                match = re.search(r"No module named ['\"]([^'\"]+)['\"]", error_msg)
                if match:
                    missing_module = match.group(1)
                    print(f"DEBUG: Detected missing module: {missing_module}", file=sys.stderr)
                    
                    # Install the missing module
                    if install_package(missing_module):
                        retry_count += 1
                        print(f"DEBUG: Retrying agent execution (Attempt {retry_count}/{max_retries})...", file=sys.stderr)
                        continue # Retry the loop
                    else:
                        print("ERROR: Could not install missing module. Aborting.", file=sys.stderr)
                        break
                else:
                    print("ERROR: Could not parse module name from error. Aborting.", file=sys.stderr)
                    traceback.print_exc(file=sys.stderr)
                    break
            else:
                # Other errors
                print(f"Error running Qwen Agent: {e}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                break

if __name__ == "__main__":
    main()
