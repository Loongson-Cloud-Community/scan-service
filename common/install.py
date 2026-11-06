"""Install the stdlib-only client into the image's Python import directory."""

from pathlib import Path
import shutil
import sysconfig


if __name__ == "__main__":
    source = Path(__file__).resolve().parent / "scan_agent_events"
    target = Path(sysconfig.get_path("purelib")) / source.name
    shutil.copytree(source, target, dirs_exist_ok=True)
