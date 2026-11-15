"""Clearance-aware access: who may see which policy chunks and which projects' live state,
and which actions their role permits."""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import config


@dataclass
class Principal:
    user: str
    role: str
    projects: list[str] = field(default_factory=list)

    @property
    def clearance(self) -> int:
        return config.ROLE_CLEARANCE.get(self.role, 0)

    @property
    def permissions(self) -> set[str]:
        return config.ROLE_PERMISSIONS.get(self.role, set())

    def can(self, permission: str) -> bool:
        return permission in self.permissions

    def require(self, permission: str) -> None:
        if not self.can(permission):
            raise PermissionError(f"role '{self.role}' lacks permission '{permission}'")

    def can_see_project(self, project: str) -> bool:
        return "*" in self.projects or project in self.projects

    def visible_projects(self) -> list[str]:
        return self.projects


def resolve(user: str) -> Principal:
    u = config.USERS.get(user)
    if not u:
        # Unknown users get the least privilege: public clearance, no projects, no permissions.
        return Principal(user=user, role="unknown", projects=[])
    return Principal(user=user, role=u["role"], projects=list(u["projects"]))
