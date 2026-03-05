"""Simple synchronous pub/sub event bus."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Event:
    name: str
    data: dict = field(default_factory=dict)


class EventBus:
    def __init__(self):
        self._subscribers: dict[str, list[Callable]] = {}

    def subscribe(self, event_name: str, callback: Callable[[Event], None]) -> None:
        self._subscribers.setdefault(event_name, []).append(callback)

    def emit(self, event: Event) -> None:
        for cb in self._subscribers.get(event.name, []):
            cb(event)
