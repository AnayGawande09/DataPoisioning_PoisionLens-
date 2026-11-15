"""DEV ONLY. Benchmark harness: synthetic attacks, CIFAR-10 loader and the v1 experiment pipeline.

Used to validate detectors (build plan Phase 12). Product code (``backend``,
``poisonlens.pipeline`` and every other ``poisonlens`` subpackage) must never
import from here; ``tests/test_bench_isolation.py`` enforces it.
"""
