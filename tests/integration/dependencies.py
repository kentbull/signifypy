"""Pinned source dependencies for the live integration harness."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IntegrationDependency:
    name: str
    repo: str
    ref: str
    path_name: str
    env_root: str
    env_ref: str


KERIPY = IntegrationDependency(
    name="KERIpy",
    repo="https://github.com/WebOfTrust/keripy.git",
    ref="cbbf700fa8091587b96b5475c5f50d1d8bf3ca40",
    path_name="keripy",
    env_root="SIGNIFYPY_INTEGRATION_KERIPY_ROOT",
    env_ref="SIGNIFYPY_INTEGRATION_KERIPY_REF",
)

KERIA = IntegrationDependency(
    name="KERIA",
    repo="https://github.com/kentbull/keria.git",
    ref="d38b603f7ecc7653956143d3719c94bac0f7c45c",
    path_name="keria",
    env_root="SIGNIFYPY_INTEGRATION_KERIA_ROOT",
    env_ref="SIGNIFYPY_INTEGRATION_KERIA_REF",
)

VLEI = IntegrationDependency(
    name="vLEI",
    repo="https://github.com/WebOfTrust/vLEI.git",
    ref="f514b9431c5f965b5f7f64a8693e19df2f181564",
    path_name="vLEI",
    env_root="SIGNIFYPY_INTEGRATION_VLEI_ROOT",
    env_ref="SIGNIFYPY_INTEGRATION_VLEI_REF",
)

INTEGRATION_DEPENDENCIES = (KERIPY, KERIA, VLEI)
