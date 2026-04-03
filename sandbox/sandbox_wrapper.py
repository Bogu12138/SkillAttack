import sys
import os
import subprocess
import traceback

def main():
    # Expect skill.py and prompt.txt to be in /app/input/
    skill_path = "/app/input/skill.py"
    prompt_path = "/app/input/prompt.txt"
    
    output_dir = "/app/output/"
    os.makedirs(output_dir, exist_ok=True)
    
    stdout_file = os.path.join(output_dir, "stdout.txt")
    stderr_file = os.path.join(output_dir, "stderr.txt")
    
    try:
        if not os.path.exists(skill_path):
            with open(stderr_file, "w") as f:
                f.write(f"Skill file not found at {skill_path}")
            return

        if not os.path.exists(prompt_path):
            with open(stderr_file, "w") as f:
                f.write(f"Prompt file not found at {prompt_path}")
            return

        with open(prompt_path, "r") as f:
            prompt = f.read()

        # Execute the skill. We assume the skill is a python script that takes prompt as arg or stdin.
        # Let's assume it takes prompt as stdin for now, or arguments.
        # The document says "Simulator: AttackCase + Skill -> SimulationResult"
        # "在沙箱中执行 prompt + skill"
        
        # Simple execution model: python skill.py < prompt
        
        with open(stdout_file, "w") as out_f, open(stderr_file, "w") as err_f:
            process = subprocess.Popen(
                ["python", skill_path],
                stdin=subprocess.PIPE,
                stdout=out_f,
                stderr=err_f,
                text=True
            )
            process.communicate(input=prompt)
            
    except Exception:
        with open(stderr_file, "a") as f:
            f.write(traceback.format_exc())

if __name__ == "__main__":
    main()
