"""Scratch demo — replay the bundled CICIDS subset at 5 eps, print alerts.

Not part of the app; just proves the replay engine end-to-end.
"""

from __future__ import annotations

import asyncio

from app.ingestion.replay import ReplayEngine
from app.schemas import NormalizedAlert


async def main() -> None:
    async def on_alert(a: NormalizedAlert) -> None:
        print(
            f"[{a.timestamp:%H:%M:%S}] {a.source:10} {a.ground_truth_label or '-':16} "
            f"{a.src_ip}:{a.src_port} -> {a.dst_ip}:{a.dst_port}  iocs={a.extracted_iocs}"
        )

    eng = ReplayEngine(on_alert)
    await eng.start("cicids2017", events_per_second=5)
    while eng.status().state.value == "running":
        await asyncio.sleep(0.2)
    st = eng.status()
    print(f"\nstate={st.state.value} emitted={st.emitted}")
    await eng.stop()


if __name__ == "__main__":
    asyncio.run(main())
