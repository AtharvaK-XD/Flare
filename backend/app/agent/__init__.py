"""Flare triage agent — LangGraph orchestration over Phases 1-7.

Public surface: ``run_triage(alert, config=None)`` runs one alert through the
pipeline and returns its final ``TriageState``; ``build_graph()`` exposes the
compiled graph for advanced callers (workers, eval replay).
"""

from __future__ import annotations

from app.agent.graph import build_graph, run_triage
from app.agent.state import TriageState

__all__ = ["build_graph", "run_triage", "TriageState"]
