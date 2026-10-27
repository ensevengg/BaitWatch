"""Parse and validate CSV files."""
import argparse


def validate(row: list[str]) -> bool:
    return len(row) == 4 and all(row)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    with open(args.input) as f:
        for line in f:
            row = line.rstrip("\n").split(",")
            print(row, validate(row))


if __name__ == "__main__":
    main()
