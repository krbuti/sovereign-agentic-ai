"""
minigraph.py - dependency-free stand-in for the subset of the LangGraph 1.x API used by
sovereign_agents.py, so the agent graph runs where `pip install langgraph` is impossible.

Mirrored API (names/signatures follow LangGraph docs):
    from langgraph.graph import StateGraph, START, END
    from langgraph.types import Command, interrupt
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.errors import GraphRecursionError

Semantics mirrored (deliberately, because the agent code depends on them):
  * state reducers via typing.Annotated[type, reducer]
  * nodes return a partial-state dict or Command(goto=..., update=...)
  * interrupt(value) pauses the run; invoke() returns state + "__interrupt__"
  * invoke(Command(resume=v), config) re-runs the interrupted node FROM ITS START and
    interrupt() returns v (so code before interrupt() must be idempotent)
  * a checkpointer + config["configurable"]["thread_id"] are required for interrupts
  * config["recursion_limit"] (default 25) bounds super-steps -> GraphRecursionError
NOT mirrored: parallel branches/fan-out, subgraphs, streaming, multiple interrupts per node,
time travel. This is a test harness, not a LangGraph replacement.
"""
from __future__ import annotations

import contextvars
import copy
import typing
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Optional

START = "__start__"
END = "__end__"


class GraphRecursionError(RuntimeError):
    pass


@dataclass
class Interrupt:
    value: Any
    id: str


class Command:
    def __init__(self, *, goto: Optional[str] = None, update: Optional[dict] = None, resume: Any = None):
        self.goto, self.update, self.resume = goto, update or {}, resume

    def __class_getitem__(cls, item):  # allow Command[Literal[...]] annotations
        return cls


class _GraphInterrupt(Exception):
    def __init__(self, value):
        super().__init__("graph interrupted")
        self.value = value


_RESUME: contextvars.ContextVar = contextvars.ContextVar("resume", default=None)
_NO_RESUME = object()


def interrupt(value: Any) -> Any:
    box = _RESUME.get()
    if box is not None and box[0] is not _NO_RESUME:
        v = box[0]
        box[0] = _NO_RESUME          # consume: one interrupt per node in this shim
        return v
    raise _GraphInterrupt(value)


class InMemorySaver:
    def __init__(self):
        self.storage: dict[str, dict] = {}

    def put(self, thread_id: str, checkpoint: dict) -> None:
        self.storage[thread_id] = copy.deepcopy(checkpoint)

    def get(self, thread_id: str) -> Optional[dict]:
        cp = self.storage.get(thread_id)
        return copy.deepcopy(cp) if cp else None


@dataclass
class StateSnapshot:
    values: dict
    next: tuple


class StateGraph:
    def __init__(self, state_schema: type):
        self.schema = state_schema
        self.nodes: dict[str, Callable] = {}
        self.edges: dict[str, str] = {}
        self.cond: dict[str, tuple[Callable, Optional[dict]]] = {}
        self.reducers: dict[str, Callable] = {}
        for name, hint in typing.get_type_hints(state_schema, include_extras=True).items():
            if typing.get_origin(hint) is typing.Annotated:
                for meta in hint.__metadata__:
                    if callable(meta):
                        self.reducers[name] = meta

    def add_node(self, name: str, fn: Callable) -> "StateGraph":
        self.nodes[name] = fn
        return self

    def add_edge(self, src: str, dst: str) -> "StateGraph":
        self.edges[src] = dst
        return self

    def add_conditional_edges(self, src: str, path: Callable, path_map: Optional[dict] = None) -> "StateGraph":
        self.cond[src] = (path, path_map)
        return self

    def compile(self, checkpointer: Optional[InMemorySaver] = None) -> "CompiledGraph":
        return CompiledGraph(self, checkpointer)


class CompiledGraph:
    def __init__(self, g: StateGraph, saver: Optional[InMemorySaver]):
        self.g, self.saver = g, saver

    def _apply(self, state: dict, update: dict) -> dict:
        for k, v in (update or {}).items():
            if k in self.g.reducers and k in state:
                state[k] = self.g.reducers[k](state[k], v)
            else:
                state[k] = v
        return state

    def _next(self, node: str, state: dict, result: Any) -> str:
        if isinstance(result, Command) and result.goto:
            return result.goto
        if node in self.g.cond:
            fn, pmap = self.g.cond[node]
            r = fn(state)
            return pmap[r] if pmap else r
        if node in self.g.edges:
            return self.g.edges[node]
        return END

    def get_state(self, config: dict) -> StateSnapshot:
        cp = self.saver.get(config["configurable"]["thread_id"]) if self.saver else None
        if not cp:
            return StateSnapshot({}, ())
        return StateSnapshot(cp["state"], () if cp["next"] == END else (cp["next"],))

    def invoke(self, inp: Any, config: Optional[dict] = None) -> dict:
        config = config or {}
        limit = config.get("recursion_limit", 25)
        thread_id = config.get("configurable", {}).get("thread_id")
        resume_box = None
        if isinstance(inp, Command) and inp.resume is not None:
            if not (self.saver and thread_id):
                raise ValueError("resume requires a checkpointer and thread_id")
            cp = self.saver.get(thread_id)
            if not cp or not cp.get("interrupted"):
                raise ValueError("no interrupted run to resume on this thread")
            state, node = cp["state"], cp["next"]
            resume_box = [inp.resume]
        else:
            prior = self.saver.get(thread_id) if (self.saver and thread_id) else None
            state = prior["state"] if prior else {}
            state = self._apply(state, {k: v for k, v in inp.items()})
            # initialise reducer fields that are missing
            for k in self.g.reducers:
                state.setdefault(k, [])
            node = self.g.edges[START]
        steps = 0
        while node != END:
            steps += 1
            if steps > limit:
                raise GraphRecursionError(f"Recursion limit of {limit} reached without hitting a stop condition")
            token = _RESUME.set(resume_box)
            try:
                result = self.g.nodes[node](state)
            except _GraphInterrupt as gi:
                if not (self.saver and thread_id):
                    raise ValueError("interrupt() requires a checkpointer and thread_id")
                intr = Interrupt(gi.value, uuid.uuid4().hex[:8])
                self.saver.put(thread_id, {"state": state, "next": node, "interrupted": True})
                return {**state, "__interrupt__": [intr]}
            finally:
                _RESUME.reset(token)
            resume_box = None
            update = result.update if isinstance(result, Command) else result
            state = self._apply(state, update)
            node = self._next(node, state, result)
            if self.saver and thread_id:
                self.saver.put(thread_id, {"state": state, "next": node, "interrupted": False})
        return state
