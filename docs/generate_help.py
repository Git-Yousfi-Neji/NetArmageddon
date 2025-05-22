import re
import subprocess
from pathlib import Path
from netarmageddon.utils.output_manager import print_error, print_debug

README_FILE = Path("README.md")
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m')


def get_supported_features() -> list[str]:
    print_debug("Getting supported feaures...")
    result = subprocess.run(
        ["python", "-m", "netarmageddon", "-h"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True,
    )
    clean_help = ANSI_ESCAPE.sub('', result.stdout)

    command_match = re.search(r'{([a-z,]+)}', clean_help)
    if not command_match:
        raise ValueError("Could not find supported feature in help output")

    commands = command_match.group(1).split(',')
    commands = ["netarmageddon"] + commands
    print_debug(f"Found {commands}")
    return commands


def fetch_help(cmd: str) -> str:
    """Get help text for a command"""
    args = ["python", "-m", "netarmageddon"]
    if cmd != "netarmageddon":
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


try:
    COMMANDS = get_supported_features()
except Exception as e:
    print_error(f"⚠️ Error detecting commands: {e}")
    COMMANDS = ["netarmageddon", "dhcp", "arp", "traffic", "deauth"]

# Process README
readme_text = README_FILE.read_text(encoding="utf-8")
for command in COMMANDS:
    help_text = fetch_help(command)
    readme_text = replace_block(readme_text, command, help_text)

README_FILE.write_text(readme_text, encoding="utf-8")
print_debug(f"✅ README updated with commands: {', '.join(COMMANDS)}")
