import argparse
import subprocess
from pathlib import Path

from run.cage import DEFAULT_IMAGE


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the trusted RUN cage image.")
    parser.add_argument("command", choices=["build"])
    parser.parse_args()
    subprocess.run(
        ["docker", "build", "--tag", DEFAULT_IMAGE, str(Path(__file__).resolve().parent)],
        check=True,
    )


if __name__ == "__main__":
    main()
