"""The ``@traced`` node decorator — the pipeline's observability spine.

Every pipeline node is wrapped by this. It guarantees that *exactly one*
``TraceNode`` is appended to ``state["trace"]`` per node invocation — on success,
on skip, and even when the node body raises despite the no-raise rule. A missing
trace entry makes the frontend transparency panel lie about what ran, and that
panel is a judged feature, so the guarantee is absolute.

Nodes are written as ``async def node(state, tr)`` where ``tr`` is a
:class:`NodeTrace` the node mutates (provider, tokens, status, note). LangGraph
only ever sees the wrapped single-argument callable.
"""

from __future__ import annotations

import functools
import time
from collections.abc import Awaitable, Callable
from typing import Any, Literal

from app.agent.state import TriageState
from app.core.logging import bind_request_context, get_logger
from app.core.metrics import metrics
from app.providers.base import CompletionResult
from app.schemas import TraceNode

log = get_logger(__name__)

TraceStatus = Literal["ok", "skipped", "failed"]

NodeImpl = Callable[[TriageState, "NodeTrace"], Awaitable["dict[str, Any] | None"]]
WrappedNode = Callable[[TriageState], Awaitable["dict[str, Any]"]]


class NodeTrace:
    """Mutable per-invocation trace scratchpad a node fills in as it works."""

    def __init__(self, node: str) -> None:
        self.node = node
        self.status: TraceStatus = "ok"
        self.provider: str | None = None
        self.model: str | None = None
        self.tokens_in: int | None = None
        self.tokens_out: int | None = None
        self.note: str | None = None

    def from_completion(self, result: CompletionResult) -> None:
        """Absorb provider/model/token attribution from an LLM call."""
        self.provider = result.provider
        self.model = result.model
        self.tokens_in = result.tokens_in
        self.tokens_out = result.tokens_out

    def mark_failed(self, note: str) -> None:
        self.status = "failed"
        self.note = note

    @property
    def provider_label(self) -> str | None:
        if self.provider and self.model:
            return f"{self.provider}:{self.model}"
        return self.provider


def traced(node_name: str) -> Callable[[NodeImpl], WrappedNode]:
    """Wrap a node body so it always emits precisely one ``TraceNode``."""

    def decorator(fn: NodeImpl) -> WrappedNode:
        @functools.wraps(fn)
        async def wrapper(state: TriageState) -> dict[str, Any]:
            tr = NodeTrace(node_name)
            alert = state.get("alert")
            bind_request_context(alert_id=getattr(alert, "id", None))

            start = time.monotonic()
            try:
                result = await fn(state, tr)
                if result is None:
                    result = {}
            except Exception as exc:  # noqa: BLE001 — nodes must never take down the graph
                log.error("agent.node_unhandled", node=node_name, error=str(exc))
                tr.mark_failed(f"unhandled error: {exc}")
                result = {"errors": [f"{node_name}: {exc}"]}

            duration_ms = int((time.monotonic() - start) * 1000)
            entry = TraceNode(
                node=node_name,  # type: ignore[arg-type]
                status=tr.status,
                provider=tr.provider_label,
                duration_ms=duration_ms,
                tokens_in=tr.tokens_in,
                tokens_out=tr.tokens_out,
                note=tr.note,
            )
            # Node-level wall-clock metric (provider/token stats are recorded by
            # the provider under its own key; 0 tokens here avoids double-count).
            metrics.record_call(
                "agent", "-", node_name, float(duration_ms), 0, 0, ok=(tr.status == "ok")
            )

            existing = result.get("trace") or []
            result["trace"] = [*existing, entry]
            log.info(
                "agent.node_done",
                node=node_name,
                status=tr.status,
                duration_ms=duration_ms,
                provider=tr.provider_label,
            )
            return result

        return wrapper

    return decorator


__all__ = ["NodeTrace", "traced", "TraceStatus"]
