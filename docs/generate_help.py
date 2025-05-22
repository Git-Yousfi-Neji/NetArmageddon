import re
import subprocess
from pathlib import Path

COMMANDS = ["main", "dhcp", "arp", "traffic", "deauth"]  # Added 'main'
README_FILE = Path("README.md")
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m')


def fetch_help(cmd: str) -> str:
    """Get help text for main command or subcommands"""
    args = ["python", "-m", "netarmageddon"]
    if cmd != "main":
        args.append(cmd)
    args.append("-h")

    result = subprocess.run(
        args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True
    )
    clean_output = ANSI_ESCAPE.sub('', result.stdout)
    return "\n".join(f"  {line}" for line in clean_output.splitlines())


def replace_block(text: str, cmd: str, snippet: str) -> str:
    pattern = rf"(<!-- USAGE:{cmd}:start -->)(.*?)(<!-- USAGE:{cmd}:end -->)"
    replacement = rf"\1\n```console\n{snippet}\n```\n\3"
    return re.sub(pattern, replacement, text, flags=re.DOTALL)


# Read and process
readme_text = README_FILE.read_text(encoding="utf-8")
for command in COMMANDS:
    help_text = fetch_help(command)
    readme_text = replace_block(readme_text, command, help_text)

README_FILE.write_text(readme_text, encoding="utf-8")
print("✅ README updated with main help and subcommands!")
