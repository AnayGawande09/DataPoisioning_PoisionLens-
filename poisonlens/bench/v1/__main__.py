"""CLI entrypoint for PoisonLens pipeline."""

import argparse
from poisonlens.bench.v1.orchestrator import run_pipeline


def main():
    parser = argparse.ArgumentParser(description="PoisonLens End-to-End Pipeline Runner")
    parser.add_argument("--config", type=str, required=True, help="Path to config YAML file")
    args = parser.parse_args()

    run_pipeline(args.config)


if __name__ == "__main__":
    main()
