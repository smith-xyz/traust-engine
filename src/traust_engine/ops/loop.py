"""One pass of the continuous-ops loop: reap expired leases, tick, admit."""

from __future__ import annotations

from collections.abc import Callable
from typing import Generic, TypeVar
from urllib.parse import urlsplit
from uuid import UUID

from traust_core.v1.context import Clock, Router, Services
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import every_item
from traust_core.v1.models.inventory import RecordedRelease, RepositoryFilter
from traust_core.v1.models.operations import OrderRequest

from traust_engine.ops.admission import Admission, AdmissionReport
from traust_engine.ops.controller import Controller, TickReport
from traust_engine.ops.pack import Pack

S = TypeVar("S")


class PassReport(Model):
    requeued: int
    tick: TickReport
    admission: AdmissionReport


class ShadowReport(Model):
    tick: TickReport
    due: tuple[OrderRequest, ...]


class EngineLoop(Generic[S]):
    def __init__(
        self,
        services: Services,
        clock: Clock,
        pack: Pack,
        router: Router[S, RecordedRelease] | None = None,
        state_of: Callable[[UUID], S] | None = None,
    ) -> None:
        self._services = services
        self._controller = Controller(
            pack, services.ops, clock, router, state_of, services.feed, services.portfolio
        )
        self._admission = Admission(pack, services.ops, services.spend, clock)

    def run_once(self) -> PassReport:
        requeued = self._services.ops.requeue_expired()
        hosts = self._hosts()
        tick = self._controller.tick(hosts.keys())
        return PassReport(requeued=requeued, tick=tick, admission=self._admission.admit(hosts))

    def shadow_once(self) -> ShadowReport:
        """The orders a pass would plan, with nothing reaped, planned or admitted: run beside cron
        (whose runs are recorded orders) until the cutover."""
        tick, due, _ = self._controller.due(self._hosts().keys())
        return ShadowReport(tick=tick, due=tuple(due))

    def _hosts(self) -> dict[UUID, str]:
        portfolio = self._services.portfolio
        repositories = every_item(lambda p: portfolio.list_repositories(RepositoryFilter(), p))
        return {r.id: urlsplit(r.url).hostname or "" for r in repositories if r.id}
