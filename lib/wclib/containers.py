"""Shared container helpers: file discovery, image classification, ports, secret names."""

from __future__ import annotations

import re
from dataclasses import dataclass

DOCKERFILE_RE = re.compile(r"(^|/)(Dockerfile|Containerfile)(\.[\w.-]+)?$|\.(dockerfile|containerfile)$", re.I)
COMPOSE_RE = re.compile(r"(^|/)((docker-)?compose|[\w.-]+\.compose)(\.[\w.-]+)?\.ya?ml$", re.I)

DB_IMAGES = re.compile(r"(^|/)(postgres|postgis|timescale\w*|mysql|mariadb|percona|mongo|redis|valkey|keydb|dragonfly\w*|memcached|"
                       r"elasticsearch|opensearch|clickhouse|cassandra|scylla|couchdb|rabbitmq|nats|minio|meilisearch|typesense|"
                       r"qdrant|influxdb|neo4j|supabase/postgres|bitnami/(postgresql|mysql|redis|mongodb|mariadb))(:|@|$)", re.I)
PROXY_IMAGES = re.compile(r"(^|/)(traefik|caddy|nginx|haproxy|envoy|coollabsio/coolify-proxy)(:|@|$)", re.I)
ADMIN_IMAGES = re.compile(r"(^|/)(adminer|pgadmin\w*|phpmyadmin|mongo-express|redis-commander|redisinsight|portainer\w*|dozzle|"
                          r"mailpit|mailhog|grafana|prometheus|kibana|metabase|uptime-kuma)(:|@|$)", re.I)
SECRET_NAME = re.compile(r"(SECRET|PASSWORD|PASSWD|PASSPHRASE|TOKEN|PRIVATE_KEY|API_KEY|ACCESS_KEY|SECRET_KEY|CREDENTIAL|AUTH_KEY|"
                         r"DATABASE_URL|DB_URL|CONNECTION_STRING|DSN|_PAT$|^PAT$)", re.I)
NOT_SECRET_NAME = re.compile(r"(_FILE$|^NEXT_PUBLIC_|PUBLIC|_PATH$|_DIR$|_URL_PATH$|_TTL$|_EXPIR|_LENGTH$|_TIMEOUT$|_HEADER$|_NAME$|_FORMAT$)", re.I)
HOST_SYSTEM_PATHS = re.compile(r"^(/|/etc(/.*)?|/root(/.*)?|/home|/var/run|/run|/proc(/.*)?|/sys(/.*)?|/boot(/.*)?|/dev(/.*)?|/usr(/.*)?|/bin|/sbin|/lib(/.*)?|C:\\?)$", re.I)
COOLIFY_HINT = re.compile(r"SERVICE_(PASSWORD|USER|BASE64|FQDN|URL|REALBASE64)_|coolify", re.I)
DEV_FILE = re.compile(r"(^|[./-])(dev|development|local|test|ci|e2e|smoke)([./-]|$)", re.I)


def is_secret_name(name: str) -> bool:
    return bool(SECRET_NAME.search(name)) and not NOT_SECRET_NAME.search(name)


def classify(service_name: str, image: str | None) -> str:
    img = image or ""
    if DB_IMAGES.search(img) or re.fullmatch(r"(db|database|postgres|pg|mysql|redis|cache|mongo|valkey)\d*", service_name, re.I) and not img:
        return "db"
    if PROXY_IMAGES.search(img):
        return "proxy"
    if ADMIN_IMAGES.search(img):
        return "admin"
    return "app"


@dataclass
class Published:
    host_ip: str | None   # None = all interfaces
    host_port: str | None
    container_port: str
    raw: str

    @property
    def all_interfaces(self) -> bool:
        return self.host_ip in (None, "", "0.0.0.0", "::", "[::]", "*")

    @property
    def localhost(self) -> bool:
        return (self.host_ip or "").strip("[]") in ("127.0.0.1", "::1", "localhost")


def parse_port(entry) -> Published | None:
    """Compose short ('8080:80', '127.0.0.1:8080:80', '80', '[::1]:5432:5432/tcp') or long syntax."""
    if isinstance(entry, dict):
        target = str(entry.get("target", ""))
        published = entry.get("published")
        if published in (None, ""):
            return Published(entry.get("host_ip"), None, target, str(entry))
        return Published(entry.get("host_ip"), str(published), target, str(entry))
    s = str(entry).strip().split("/")[0]
    m = re.match(r"^(\[[^\]]+\]|[^:]*?):?(\$\{[^}]*\}|[\d-]+)?:(\$\{[^}]*\}|[\d-]+)$", s)
    if s.count(":") == 0 or (s.startswith("${") and s.count(":") <= 1 and s.endswith("}")):
        return Published(None, None, s, str(entry))  # container port only -> random host port on all interfaces
    parts = re.split(r":(?![^{]*\})", s)
    if len(parts) == 2:
        return Published(None, parts[0], parts[1], str(entry))
    if len(parts) >= 3:
        return Published(":".join(parts[:-2]).strip("[]") or None, parts[-2], parts[-1], str(entry))
    return None


def is_interpolated(value) -> bool:
    return isinstance(value, str) and "${" in value


def env_items(env) -> list[tuple[str, object]]:
    """Compose environment as (name, value) pairs; list form 'K=V' / 'K' supported."""
    if isinstance(env, dict):
        return list(env.items())
    out = []
    if isinstance(env, list):
        for item in env:
            s = str(item)
            k, _, v = s.partition("=")
            out.append((k, v if "=" in s else None))
    return out
