"""Semper USB — entry point."""
import sys
import yaml
from pathlib import Path


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    config = load_config()
    print("Semper USB starting...")
    # Daemon + GUI event loop wired in Task 12


if __name__ == "__main__":
    main()
