import subprocess


def main() -> None:
    raise SystemExit(subprocess.call(["ruff", "format", "."]))


if __name__ == "__main__":
    main()
