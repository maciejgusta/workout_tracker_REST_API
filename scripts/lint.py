import subprocess


def main() -> None:
    raise SystemExit(subprocess.call(["ruff", "check", "."]))


if __name__ == "__main__":
    main()
