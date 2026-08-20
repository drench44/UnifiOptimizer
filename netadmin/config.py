"""Runtime configuration for netadmin.

Settings are assembled from three places, highest priority first:

1. explicit keyword arguments (tests, overrides),
2. process environment + ``data/secrets.env`` (controller credentials),
3. the ``netadmin:`` section of ``data/config.yaml`` (structural defaults).

Credentials (``UNIFI_HOST`` / ``UNIFI_USERNAME`` / ``UNIFI_PASSWORD`` /
``UNIFI_SITE`` and the optional ``UNIFI_API_KEY``) live only in
``data/secrets.env`` (chmod 600, gitignored) and are read at runtime. Nothing
is instantiated at import time; call :func:`get_settings`.
"""

from __future__ import annotations

import os
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

import yaml
from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
CONFIG_YAML = DATA_DIR / "config.yaml"
SECRETS_ENV = DATA_DIR / "secrets.env"
DEFAULT_DB_PATH = DATA_DIR / "netadmin.db"
DEFAULT_LOG_DIR = PROJECT_ROOT / "Logging"

# --------------------------------------------------------------------------- #
# Scheduler misfire policy (shared by ingest and detect wiring)
# --------------------------------------------------------------------------- #
# How late a scheduled run may fire before APScheduler skips it. The library
# default is 1 second, which turns any event-loop stall (analysis jobs run sync
# store work on the loop thread) into silently skipped cycles: a ~30 s stall
# each 5-minute tick starved ``sle_minutes`` completely — every due time landed
# inside the stall, every run was discarded, and /api/health read it stale with
# zero recorded failures. With ``coalesce=True`` a generous grace is safe: a
# late job runs once, immediately, instead of not at all.
MISFIRE_GRACE_S = 60

# Cron jobs (and interval jobs with hours-long periods) get up to an hour: a
# stall or restart over their one due time should delay the run, not lose a
# whole period.
CRON_MISFIRE_GRACE_S = 3600


def misfire_grace_for(interval_s: int) -> int:
    """Misfire grace scaled to an interval job's period.

    Never below :data:`MISFIRE_GRACE_S`; half the period for long intervals so a
    stall over the due time of a 6 h or 24 h job cannot silently cost a whole
    period; capped at :data:`CRON_MISFIRE_GRACE_S`.
    """
    return max(MISFIRE_GRACE_S, min(int(interval_s) // 2, CRON_MISFIRE_GRACE_S))


class PollIntervals(BaseModel):
    """Collector cadences in seconds (section 5.2). Offsets keep them unaligned."""

    device_s: int = 60  # stat/device
    sta_s: int = 60  # stat/sta
    health_s: int = 60  # stat/health
    event_catchup_s: int = 300  # stat/event dedupe sweep
    probe_s: int = 60  # DNS / ICMP active probes
    alarm_s: int = 900  # list/alarm, stat/anomalies
    report_5min_s: int = 21_600  # stat/report/5minutes.* (6 h)
    report_daily_s: int = 86_400  # stat/report/hourly.*, daily.*
    rogueap_s: int = 86_400  # stat/rogueap (within=24)


class Retention(BaseModel):
    """Per-tier retention (section 4). Daily rollups are kept forever."""

    raw_days: int = 30
    hourly_months: int = 18
    daily_forever: bool = True
    # Hour of day (UTC, 0-23) the nightly retention prune job fires.
    prune_hour: int = 3


class ProbeConfig(BaseModel):
    """Active-probe targets (section 5.4).

    The controller exposes no DNS/DHCP timing, so a local prober measures it.
    ``gateway_ip`` is the ICMP/TCP RTT target; ``gateway_resolver`` is the
    resolver the DNS probe times (typically the gateway IP). Both are optional:
    when neither is set nor discoverable from inventory, the probe runner idles
    honestly rather than fabricating a target. ``anchor`` is the public resolver
    used as the "is it me or my ISP" comparison.
    """

    enabled: bool = True
    gateway_ip: str | None = None
    gateway_resolver: str | None = None
    anchor: str = "1.1.1.1"


class Backfill(BaseModel):
    """Controller-retention caps used by startup backfill (section 5.3).

    These are conservative defaults; the ingest layer verifies them per install
    at runtime because Network 9.x "auto" retention defaults are unpublished.
    """

    fivemin_hours: int = 24
    hourly_days: int = 7
    daily_days: int = 31


class DetectConfig(BaseModel):
    """Detection-engine scheduler cadences (section 6).

    The three detector tiers plus the incremental baseline update, all wired onto
    the daemon's one AsyncIOScheduler by :func:`netadmin.ingest.factory.build_components`.
    Per-detector *thresholds* live in :attr:`Settings.thresholds` keyed by
    ``detector_key`` (e.g. ``thresholds["wired.bad_cable"]["errors_per_min"]``);
    this block is only the *how often* the engine runs.
    """

    fast_s: int = 60  # FAST tier: every collector fast cadence
    window_s: int = 900  # WINDOW tier: 15-minute rolling window
    daily_hour: int = 3  # DAILY tier: UTC hour for config audits
    baseline_s: int = 300  # EWMA / rolling-quantile incremental update cadence


class CorrelateConfig(BaseModel):
    """Correlation-engine scheduler cadence + temporal guard (section 17).

    The correlation pass groups the confirmed open-issue set into **incidents**
    (one root cause + its symptoms) on a concrete topological/causal-rule basis.
    It runs as one more job on the daemon's single scheduler, offset *after* the
    detector passes so it reasons over the issues those passes just wrote. The
    pass is pure logic over the store and idempotent, so an interval cadence
    (recompute from scratch each tick) is the whole contract — it needs no hook
    into the detect passes beyond running shortly after them.

    ``temporal_slack_s`` is the guard that keeps grouping conservative: a symptom
    whose ``first_seen`` predates its candidate root by more than this window is
    *not* attributed to it (a symptom cannot precede its cause). Mirrors
    :class:`netadmin.correlate.models.CorrelationConfig`, which the factory builds
    from this block.
    """

    enabled: bool = True  # off -> no correlate job is scheduled; incidents go stale
    interval_s: int = 60  # recompute cadence; offset after the detect passes
    temporal_slack_s: int = 900  # symptom-may-predate-root slack (the temporal guard)


class SleRuntimeConfig(BaseModel):
    """SLE minutes-job scheduler cadence + default scoring window (section 8).

    The classifier *thresholds* (coverage floor, sticky RSSI, cu_total, ...) and the
    headline blend *weights* are read from ``settings.thresholds["sle"]`` by
    :class:`~netadmin.sle.classifiers.SleConfig` and
    :func:`~netadmin.sle.scores.load_weights`; this block is only the job cadence
    and the window ``GET /api/sle`` scores over by default.
    """

    minutes_s: int = 300  # 5-minute-bucket job cadence
    score_window_s: int = 86_400  # default /api/sle look-back window (24 h)


class HaConfig(BaseModel):
    """Home Assistant MQTT-discovery integration (section 11).

    Structural config only, and **off by default**: the daemon publishes nothing
    to MQTT until an operator sets ``enabled: true``. Broker *credentials* never
    live here (nor in ``config.yaml``) — they are read from the environment /
    ``data/secrets.env`` (``HA_MQTT_HOST`` / ``HA_MQTT_PORT`` / ``HA_MQTT_USERNAME``
    / ``HA_MQTT_PASSWORD``) through :attr:`Settings.mqtt`. This block carries only
    the non-secret topology of the integration: the discovery prefix HA listens on,
    the base topic our own state/event topics hang off, and the state-refresh
    cadence.
    """

    enabled: bool = False
    discovery_prefix: str = "homeassistant"  # HA's MQTT-discovery listen prefix
    base_topic: str = "netadmin"  # our state/event/availability topic root
    node_id: str = "netadmin"  # discovery node id + object_id prefix
    device_name: str = "UnifiOptimizer"  # HA device friendly display name (entities group under it)
    state_refresh_s: int = 60  # periodic score/count republish cadence


class MqttCredentials(BaseModel):
    """A grouped, read-only view of the MQTT broker credentials (section 11).

    Read from the environment / ``data/secrets.env`` only, mirroring
    :class:`UnifiCredentials`. ``host`` unset means the integration stays inert
    even when ``ha.enabled`` is true — an honest no-op over a half-configured
    connection.
    """

    host: str | None = None
    port: int = 1883
    username: str | None = None
    password: str | None = None

    @property
    def is_configured(self) -> bool:
        """True when at least a broker host is known (auth may be anonymous)."""
        return bool(self.host)


class UnifiCredentials(BaseModel):
    """A grouped, read-only view of the controller credentials."""

    host: str | None = None
    username: str | None = None
    password: str | None = None
    site: str = "default"
    api_key: str | None = None

    @property
    def is_configured(self) -> bool:
        """True when enough is present to attempt a connection."""
        return bool(self.host) and bool(self.api_key or (self.username and self.password))


class _YamlNetadminSource(PydanticBaseSettingsSource):
    """Feed the ``netadmin:`` section of ``data/config.yaml`` into Settings."""

    def __init__(self, settings_cls: type[BaseSettings], yaml_path: Path) -> None:
        super().__init__(settings_cls)
        self._data: dict[str, Any] = self._load(yaml_path)

    @staticmethod
    def _load(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        with path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
        section = raw.get("netadmin", {}) if isinstance(raw, dict) else {}
        return section if isinstance(section, dict) else {}

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        return self._data.get(field_name), field_name, False

    def __call__(self) -> dict[str, Any]:
        return dict(self._data)


class Settings(BaseSettings):
    """Top-level netadmin configuration.

    Credential fields default to ``None`` so the package imports and tests
    collect without ``data/secrets.env`` present; the ingest layer enforces
    presence before connecting.
    """

    model_config = SettingsConfigDict(
        env_file=str(SECRETS_ENV),
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
    )

    # --- controller credentials (from data/secrets.env / environment) ---
    unifi_host: str | None = None
    unifi_username: str | None = None
    unifi_password: str | None = None
    unifi_site: str = "default"
    unifi_api_key: str | None = None

    # --- MQTT broker credentials (section 11; from data/secrets.env / environment,
    #     read as HA_MQTT_HOST / HA_MQTT_PORT / HA_MQTT_USERNAME / HA_MQTT_PASSWORD).
    #     Never yaml, never code — grouped for the HA publisher via ``.mqtt``. ---
    ha_mqtt_host: str | None = None
    ha_mqtt_port: int = 1883
    ha_mqtt_username: str | None = None
    ha_mqtt_password: str | None = None

    # --- storage / runtime ---
    db_path: Path = DEFAULT_DB_PATH
    log_dir: Path = DEFAULT_LOG_DIR
    log_level: str = "INFO"
    site_id: str = "default"

    # --- API server (daemon bind + CLI status target; section 12) ---
    server_host: str = "127.0.0.1"
    server_port: int = 8765
    web_dist_path: str | None = None  # built SPA dir; default web/dist relative to cwd
    # Optional static API token. When set (via ``NETADMIN_API_TOKEN`` in
    # ``data/secrets.env`` / the environment — never yaml, never code), every
    # ``/api/*`` route except ``GET /api/health`` and the ``/ws`` socket require it
    # (``Authorization: Bearer <token>`` / ``?token=``, constant-time compared).
    # Unset (the default) means open access with a startup WARNING. Named to match
    # the env var like the other secrets (``unifi_host`` -> ``UNIFI_HOST``); read
    # through the :attr:`api_token` property so callers never touch the raw field.
    netadmin_api_token: str | None = None
    # Pinned CORS origins (section 12); ``*`` is stripped by the server, never
    # allowed. Empty -> the server's localhost dev defaults.
    cors_origins: list[str] = Field(default_factory=list)

    # --- structural config (from data/config.yaml -> netadmin:) ---
    poll: PollIntervals = Field(default_factory=PollIntervals)
    retention: Retention = Field(default_factory=Retention)
    backfill: Backfill = Field(default_factory=Backfill)
    probe: ProbeConfig = Field(default_factory=ProbeConfig)
    detect: DetectConfig = Field(default_factory=DetectConfig)
    correlate: CorrelateConfig = Field(default_factory=CorrelateConfig)
    sle: SleRuntimeConfig = Field(default_factory=SleRuntimeConfig)
    ha: HaConfig = Field(default_factory=HaConfig)

    # WAN plan rate (Mbps), the optional "under load" gate for the bufferbloat
    # detector / SLE. Default ``None`` means "auto": the gate is disabled and
    # bufferbloat stays honestly UNKNOWN. On a Starlink uplink this is the correct
    # default — throughput varies so widely that a fixed plan rate does not
    # represent saturation, and there is no UniFi WAN-throughput series to measure
    # against anyway. Set an explicit value only on a non-Starlink link that exposes
    # ``wan_xput_*`` and has a real provisioned rate. No other WAN detector relies
    # on these keys; latency/loss are judged from rolling probe baselines instead.
    wan_plan_down_mbps: float | None = None
    wan_plan_up_mbps: float | None = None

    # Per-detector / per-classifier threshold overrides, keyed by ``detector_key``
    # (section 6) — e.g. ``{"wired.bad_cable": {"errors_per_min": 20}}``. Detectors
    # ship their own dataclass/literal defaults and read overrides through
    # ``DetectorContext.threshold(key, name, default)``; the SLE classifiers read
    # ``thresholds["sle"]`` and the scorer reads ``thresholds["sle"]["weights"]``.
    thresholds: dict[str, Any] = Field(default_factory=dict)

    @property
    def unifi(self) -> UnifiCredentials:
        """Grouped credential view for the ingest layer."""
        return UnifiCredentials(
            host=self.unifi_host,
            username=self.unifi_username,
            password=self.unifi_password,
            site=self.unifi_site,
            api_key=self.unifi_api_key,
        )

    @property
    def api_token(self) -> str | None:
        """The static API token, or ``None`` for open access (section 12).

        Whitespace-only is treated as unset so a blank line in ``secrets.env``
        does not silently lock the API behind an unusable token.
        """
        token = self.netadmin_api_token
        token = token.strip() if token else None
        return token or None

    @property
    def mqtt(self) -> MqttCredentials:
        """Grouped MQTT-broker credential view for the HA publisher (section 11)."""
        return MqttCredentials(
            host=self.ha_mqtt_host,
            port=self.ha_mqtt_port,
            username=self.ha_mqtt_username,
            password=self.ha_mqtt_password,
        )

    @model_validator(mode="after")
    def _db_path_env_override(self) -> "Settings":
        """Let ``NETADMIN_DB_PATH`` point the daemon at a different database.

        The generic (prefixless) env name for this field would collide with common
        shell variables, so we read an explicitly-namespaced one here. This is what
        makes ``NETADMIN_DB_PATH=data/netadmin-demo.db netadmin daemon`` work for the
        demo/quickstart and the restore-verify in docs/BACKUP.md, without editing
        data/config.yaml.
        """
        override = os.environ.get("NETADMIN_DB_PATH")
        if override:
            self.db_path = Path(override)
        return self

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        yaml_source = _YamlNetadminSource(settings_cls, CONFIG_YAML)
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            yaml_source,
            file_secret_settings,
        )


# --------------------------------------------------------------------------- #
# secrets.env writer (first-run setup; ARCHITECTURE.md 18)
# --------------------------------------------------------------------------- #
# Characters that force a value to be double-quoted so a dotenv parser reads it
# back intact (whitespace, comment marker, quotes, backslash).
_SECRET_QUOTE_TRIGGERS = frozenset(" \t#\"'\\")

# Line-breaking / terminating control characters that can never be represented on
# a single ``KEY=VALUE`` line: a newline or CR would split the value into a second
# (attacker-controlled) assignment when the file is parsed back, and a NUL
# truncates it. Neither the double-quoted nor the bare path can hold these safely,
# so the writer rejects them outright at the security boundary rather than emitting
# a file that a dotenv reader would parse into extra keys. This is the invariant
# "a value with a newline must not inject a second key", enforced at the writer.
_SECRET_FORBIDDEN_CHARS = ("\n", "\r", "\x00")


class SecretValueError(ValueError):
    """A secret value cannot be safely serialised into ``secrets.env``.

    Raised when a value carries a line-breaking / terminating control character
    (see :data:`_SECRET_FORBIDDEN_CHARS`). Carries no value text so the offending
    secret is never surfaced in a traceback or log.
    """


def _reject_forbidden_chars(value: str) -> None:
    """Raise :class:`SecretValueError` if ``value`` holds a forbidden control char.

    The message never includes the value itself (it may be a credential); it names
    only the class of character, so a stack trace can be logged without leaking.
    """
    for ch in _SECRET_FORBIDDEN_CHARS:
        if ch in value:
            names = {"\n": "newline", "\r": "carriage return", "\x00": "NUL"}
            raise SecretValueError(
                f"secret value contains a forbidden {names[ch]} character and cannot "
                "be written to secrets.env"
            )


def _needs_quoting(value: str) -> bool:
    return value == "" or any(ch in _SECRET_QUOTE_TRIGGERS for ch in value)


def _format_env_value(value: str) -> str:
    """Render a value for a dotenv line, double-quoting + escaping when needed.

    Plain values (the common case: a URL host, a URL-safe API key/token) are
    written bare so an existing hand-edited ``secrets.env`` keeps its style; a
    value containing whitespace / ``#`` / quotes (e.g. a password) is
    double-quoted with ``\\`` and ``"`` escaped so python-dotenv round-trips it.

    Values carrying a line-breaking control character (newline / CR / NUL) are
    **rejected** (:class:`SecretValueError`): they cannot be represented on one
    ``KEY=VALUE`` line and would otherwise split into a second assignment when the
    file is parsed back — the secrets-injection boundary this writer guards.
    """
    _reject_forbidden_chars(value)
    if not _needs_quoting(value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _split_env_line(line: str) -> Any:
    """Return the KEY of a ``KEY=VALUE`` assignment line, or ``None`` otherwise.

    Comment lines, blank lines, and anything without an ``=`` are preserved
    verbatim (they return ``None`` and are copied through untouched).
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None
    key = stripped.split("=", 1)[0].strip()
    # An ``export KEY=...`` prefix is tolerated for reads; normalise to the bare key.
    if key.startswith("export ") or key.startswith("export\t"):
        key = key.split(None, 1)[1].strip()
    return key or None


def write_secrets(updates: Mapping[str, str], *, path: Path = SECRETS_ENV) -> Path:
    """Merge ``updates`` into ``data/secrets.env`` atomically, chmod 600.

    First-run setup uses this to persist the controller credential and the minted
    UI token (ARCHITECTURE.md 18). Contract:

    * **Creates** the file (and parent dir) when absent, always ``0o600``.
    * **Preserves** every other key, plus comments and ordering; an existing key is
      updated in place, a new key is appended.
    * **Atomic**: written to a temp file in the same directory and ``os.replace``d,
      so a crash never leaves a half-written secrets file.
    * **Never logs values** — this function performs no logging at all.

    Values are written bare when safe and double-quoted when they contain
    whitespace / ``#`` / quotes, so a dotenv reader round-trips them. Returns the
    path written.
    """
    updates = {str(k): str(v) for k, v in updates.items()}
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    remaining = dict(updates)
    out_lines: list[str] = []
    if path.exists():
        existing = path.read_text(encoding="utf-8").splitlines()
        for line in existing:
            key = _split_env_line(line)
            if key is not None and key in remaining:
                out_lines.append(f"{key}={_format_env_value(remaining.pop(key))}")
            else:
                out_lines.append(line)
    # Append any keys not already present, in the caller's order.
    for key, value in remaining.items():
        out_lines.append(f"{key}={_format_env_value(value)}")

    body = "\n".join(out_lines) + "\n"

    # Atomic replace via a same-dir temp file created 0600 (mkstemp default).
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".secrets-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except BaseException:
        # Best-effort cleanup of the temp file on any failure; never mask the error.
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)
    return path


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide Settings singleton (cached)."""
    return Settings()


__all__ = [
    "PROJECT_ROOT",
    "DATA_DIR",
    "CONFIG_YAML",
    "SECRETS_ENV",
    "PollIntervals",
    "Retention",
    "Backfill",
    "ProbeConfig",
    "DetectConfig",
    "CorrelateConfig",
    "SleRuntimeConfig",
    "HaConfig",
    "MqttCredentials",
    "UnifiCredentials",
    "Settings",
    "get_settings",
    "write_secrets",
    "SecretValueError",
]
