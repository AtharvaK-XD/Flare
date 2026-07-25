"""MITRE retriever — attack-type-filtered semantic search over the Chroma index.

Filtering the query by the technique ids for a given AttackType is a large
precision win on a ~30-doc corpus; unfiltered search over this little data is
unreliable. A missing/empty index degrades remediation quality — it never raises.
"""

from __future__ import annotations

import asyncio
from functools import partial
from typing import Any

from app.core.logging import get_logger
from app.rag.indexer import get_embedding_model
from app.rag.mitre_loader import techniques_for
from app.schemas import AttackType, MitreTechnique

log = get_logger(__name__)

EXCERPT_MAX = 500


def _truncate(text: str, limit: int = EXCERPT_MAX) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit]
    space = cut.rfind(" ")
    if space > 0:
        cut = cut[:space]
    return cut.rstrip() + "…"


class MitreRetriever:
    def __init__(self, collection: Any = None) -> None:
        self._collection = collection

    async def _get_collection(self) -> Any:
        if self._collection is not None:
            return self._collection
        from app.store.chroma import get_collection

        return await get_collection()

    async def retrieve(
        self, query: str, attack_type: AttackType | None = None, k: int = 4
    ) -> list[MitreTechnique]:
        """Retrieve grounding techniques WITHOUT blocking the event loop.

        chromadb's client is synchronous — ``count`` and ``query`` both do disk
        I/O and HNSW search on the calling thread. Called bare from a coroutine
        they stall every other alert, every SSE subscriber and the heartbeat for
        the duration. Each one goes through ``asyncio.to_thread``, as the
        embedding encode already did.
        """
        col = await self._get_collection()
        if await asyncio.to_thread(col.count) == 0:
            log.warning("rag.empty_index")
            return []

        q_emb = (await asyncio.to_thread(get_embedding_model().encode, [query]))[0].tolist()

        ids_filter = techniques_for(attack_type)
        where = {"technique_id": {"$in": ids_filter}} if ids_filter else None
        n = max(k * 3, 6)

        res = await asyncio.to_thread(
            partial(col.query, query_embeddings=[q_emb], n_results=n, where=where)
        )
        if where is not None and not (res.get("ids") and res["ids"][0]):
            log.info("rag.filter_fallback", attack_type=str(attack_type))
            res = await asyncio.to_thread(
                partial(col.query, query_embeddings=[q_emb], n_results=n)
            )

        return self._to_techniques(res, k)

    def _to_techniques(self, res: dict, k: int) -> list[MitreTechnique]:
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]

        out: list[MitreTechnique] = []
        seen: set[str] = set()
        for i, meta in enumerate(metas):
            tid = str(meta.get("technique_id"))
            if tid in seen:
                continue
            seen.add(tid)
            distance = dists[i] if i < len(dists) else None
            log.info("rag.hit", technique_id=tid, distance=distance)
            out.append(
                MitreTechnique(
                    id=tid,
                    name=str(meta.get("technique_name", "")),
                    tactic=str(meta.get("tactic", "")),
                    url=str(meta.get("url", "")),
                    excerpt=_truncate(docs[i] if i < len(docs) else ""),
                )
            )
            if len(out) >= k:
                break
        return out
