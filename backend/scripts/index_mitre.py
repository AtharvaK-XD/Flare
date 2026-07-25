"""Index the MITRE ATT&CK corpus into Chroma.

Usage: python -m scripts.index_mitre [--force]
"""

from __future__ import annotations

import argparse
import asyncio
import time

from app.rag.chunker import chunk_corpus
from app.rag.indexer import build_index
from app.rag.mitre_loader import load_corpus


async def main() -> None:
    parser = argparse.ArgumentParser(description="Build the MITRE ATT&CK vector index")
    parser.add_argument("--force", action="store_true", help="rebuild even if up-to-date")
    args = parser.parse_args()

    docs = load_corpus()
    chunks = chunk_corpus(docs)
    print(f"corpus:  {len(docs)} techniques, {len(chunks)} chunks")

    t0 = time.perf_counter()
    stats = await build_index(force=args.force)
    print(f"elapsed: {time.perf_counter() - t0:.1f}s")
    print("stats:")
    for key, value in stats.items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    asyncio.run(main())
