#!/usr/bin/env python3
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import urllib.parse
import urllib.request

# List of upstream subscription URLs or local file paths to aggregate & deduplicate
UPSTREAM_SOURCES = [
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/1.2.txt"
]

GEOIP_DB_PATH = "GeoLite2-Country.mmdb"
GEOIP_DB_URL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb"

DNS_THREADS = 32
DNS_TIMEOUT = 3.0

GEO_CACHE = {}
GEO_LOCK = threading.Lock()
INIT_LOCK = threading.Lock()
GEOIP_READER = None
GEOIP_INIT_ATTEMPTED = False

# Query keys that convey no routing semantics and cause false uniqueness
IGNORE_QUERY_KEYS = {
    "remarks",
    "remark",
    "ps",
    "group",
    "title",
    "name",
    "sub",
    "tag",
    "flag",
}

# Alias mappings to normalize transport and security options
QUERY_KEY_ALIASES = {
    "peer": "sni",
    "servername": "sni",
    "server_name": "sni",
    "host": "sni",
    "net": "type",
    "network": "type",
    "transport": "type",
    "servicename": "service_name",
    "service_name": "path",
    "insecure": "allowinsecure",
    "allow_insecure": "allowinsecure",
    "fingerprint": "fp",
    "publickey": "pbk",
    "public_key": "pbk",
    "shortid": "sid",
    "short_id": "sid",
    "spiderx": "spx",
    "spider_x": "spx",
    "packetencoding": "penc",
    "packet_encoding": "penc",
}

DEFAULT_PORTS = {
    "vmess": 443,
    "vless": 443,
    "trojan": 443,
    "ss": 8388,
    "ssr": 8388,
    "tuic": 443,
    "hysteria": 443,
    "hysteria2": 443,
    "hy2": 443,
    "wireguard": 51820,
    "snell": 443,
}


def generate_mirror_urls(url: str) -> list[str]:
    """
    Generates CDN mirror fallbacks for GitHub raw URLs (e.g. jsDelivr, Fastly, GitHack, Ghproxy, Statically).
    Non-GitHub URLs will simply return a single-item list containing the original URL.
    """
    url = url.strip()
    mirrors = [url]  # Primary URL always attempted first

    raw_match = re.match(
        r"^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.*)$",
        url,
    )
    blob_match = re.match(
        r"^https?://github\.com/([^/]+)/([^/]+)/raw/(?:refs/heads/)?([^/]+)/(.*)$",
        url,
    )

    match = raw_match or blob_match
    if match:
        owner, repo, branch, path = match.groups()
        cdn_templates = [
            f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}",
            f"https://fastly.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}",
            f"https://raw.githack.com/{owner}/{repo}/{branch}/{path}",
            f"https://ghproxy.net/https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}",
            f"https://cdn.statically.io/gh/{owner}/{repo}/{branch}/{path}",
        ]
        for cdn_url in cdn_templates:
            if cdn_url not in mirrors:
                mirrors.append(cdn_url)

    return mirrors


def decode_base64_flexible(data: str) -> str:
    """Decodes base64 with URL-safe variants, missing padding, and whitespace handling."""
    if not data:
        return ""
    data = re.sub(r"\s+", "", data).replace("-", "+").replace("_", "/")
    pad = len(data) % 4
    if pad:
        data += "=" * (4 - pad)
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def clean_path(path: str) -> str:
    if not path:
        return "/"
    path = urllib.parse.unquote(path).strip()
    if not path.startswith("/"):
        path = "/" + path
    return re.sub(r"/+", "/", path)


def normalize_uuid(val: str) -> str:
    v = val.lower().strip()
    clean = v.replace("-", "")
    if len(clean) == 32 and all(c in "0123456789abcdef" for c in clean):
        return f"{clean[:8]}-{clean[8:12]}-{clean[12:16]}-{clean[16:20]}-{clean[20:]}"
    return v


def safe_split_uri(url: str):
    scheme = ""
    if "://" in url:
        scheme, url = url.split("://", 1)

    url = url.split("#", 1)[0]
    query = ""
    if "?" in url:
        url, query = url.split("?", 1)

    path = ""
    if "/" in url:
        url, path = url.split("/", 1)
        path = "/" + path

    userinfo = ""
    host_port = url
    if "@" in url:
        userinfo, host_port = url.rsplit("@", 1)

    host = host_port
    port = ""
    if host_port.startswith("["):
        if "]:" in host_port:
            host, port = host_port.split("]:", 1)
            host = host + "]"
        elif host_port.endswith("]"):
            host = host_port
    else:
        if ":" in host_port:
            host, port = host_port.rsplit(":", 1)

    return scheme.lower(), userinfo, host.strip("[]").lower(), port, path, query


def normalize_query(query_dict: dict) -> tuple[dict, str]:
    normalized_dict = {}
    for k, values in query_dict.items():
        k_clean = k.lower().strip()
        if k_clean in IGNORE_QUERY_KEYS:
            continue
        canon_key = QUERY_KEY_ALIASES.get(k_clean, k_clean)
        val = values[0].strip() if values else ""
        val = urllib.parse.unquote(val).strip()

        if canon_key == "allowinsecure":
            val = "1" if val.lower() in ("1", "true", "yes") else "0"
        elif canon_key == "type":
            val = val.lower()
            if val in ("websocket", "ws"):
                val = "ws"
            elif val in ("http", "h2"):
                val = "http"
        elif canon_key == "path":
            val = clean_path(val)

        if val:
            normalized_dict[canon_key] = val

    canonical_qs = urllib.parse.urlencode(
        sorted(normalized_dict.items()), doseq=True
    )
    return normalized_dict, canonical_qs


@dataclass(order=True)
class AddressSortKey:
    address_type: int  # 0: IPv4, 1: IPv6, 2: Domain
    ip_int: int
    domain_hierarchy: list[str]
    port: int

    @classmethod
    def from_address(cls, host: str, port: int):
        host = host.strip("[]").strip()
        try:
            ip_obj = ipaddress.ip_address(host)
            if ip_obj.version == 4:
                return cls(
                    address_type=0,
                    ip_int=int(ip_obj),
                    domain_hierarchy=[],
                    port=port,
                )
            else:
                return cls(
                    address_type=1,
                    ip_int=int(ip_obj),
                    domain_hierarchy=[],
                    port=port,
                )
        except ValueError:
            parts = [p.lower() for p in host.split(".") if p]
            hierarchy = list(reversed(parts))
            return cls(
                address_type=2,
                ip_int=0,
                domain_hierarchy=hierarchy,
                port=port,
            )


@dataclass
class CanonicalNode:
    raw_uri: str
    protocol: str
    host: str
    port: int
    userinfo: str
    path: str
    params: dict = field(default_factory=dict)
    canonical_query: str = ""

    sort_key: AddressSortKey = None
    strict_key: str = ""
    semantic_key: str = ""

    def __post_init__(self):
        self.sort_key = AddressSortKey.from_address(self.host, self.port)
        self.build_keys()

    def build_keys(self):
        self.strict_key = (
            f"{self.protocol}|{self.host}|{self.port}|{self.userinfo}|"
            f"{self.path}|{self.canonical_query}"
        )

        sni = self.params.get("sni") or self.params.get("host") or self.host
        net_type = self.params.get("type", "tcp")
        self.semantic_key = (
            f"{self.protocol}|{self.userinfo}|{sni}|{self.port}|{net_type}|{self.path}"
        )


def parse_vmess(uri: str) -> CanonicalNode | None:
    raw = uri[8:].split("#")[0].strip()
    raw = urllib.parse.unquote(raw)
    json_str = (
        raw if raw.startswith("{") else decode_base64_flexible(raw)
    )
    if not json_str:
        return None

    try:
        cfg = json.loads(json_str)
        if not isinstance(cfg, dict):
            return None

        host = str(cfg.get("add") or cfg.get("address") or "").strip().lower()
        if not host:
            return None

        try:
            port = int(cfg.get("port", DEFAULT_PORTS["vmess"]))
        except (ValueError, TypeError):
            port = DEFAULT_PORTS["vmess"]

        uuid = normalize_uuid(str(cfg.get("id") or cfg.get("uuid") or ""))
        net = (
            str(cfg.get("net") or cfg.get("network") or "tcp").strip().lower()
        )
        if net == "websocket":
            net = "ws"

        tls = (
            str(cfg.get("tls") or cfg.get("security") or "none")
            .strip()
            .lower()
        )
        scy = str(cfg.get("scy") or "auto").strip().lower()
        sni = str(cfg.get("sni") or cfg.get("host") or "").strip().lower()
        path = clean_path(str(cfg.get("path") or "/"))
        aid = str(cfg.get("aid") or cfg.get("alterId") or "0").strip()
        type_val = (
            str(cfg.get("type") or cfg.get("headerType") or "none")
            .strip()
            .lower()
        )

        params = {
            "type": net,
            "tls": tls,
            "scy": scy,
            "sni": sni,
            "aid": aid,
            "header_type": type_val,
        }
        _, canon_q = normalize_query({k: [v] for k, v in params.items()})

        return CanonicalNode(
            raw_uri=uri,
            protocol="vmess",
            host=host,
            port=port,
            userinfo=uuid,
            path=path,
            params=params,
            canonical_query=canon_q,
        )
    except Exception:
        return None


def parse_shadowsocks(uri: str) -> CanonicalNode | None:
    raw = uri[5:].split("#")[0].strip()
    query_part = ""
    if "?" in raw:
        raw, query_part = raw.split("?", 1)

    method, password, hostport = "", "", ""

    if "@" in raw:
        userinfo, hostport = raw.rsplit("@", 1)
        decoded_u = decode_base64_flexible(userinfo)
        if ":" in decoded_u:
            method, password = decoded_u.split(":", 1)
        elif ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            return None
    else:
        decoded = decode_base64_flexible(raw)
        if "@" in decoded:
            userinfo, hostport = decoded.rsplit("@", 1)
            if ":" in userinfo:
                method, password = userinfo.split(":", 1)
            else:
                return None
        else:
            return None

    _, _, host, port_str, _, _ = safe_split_uri(f"ss://{hostport}")
    if not host:
        return None

    try:
        port = int(port_str) if port_str else DEFAULT_PORTS["ss"]
    except ValueError:
        port = DEFAULT_PORTS["ss"]

    q_dict = urllib.parse.parse_qs(query_part)
    params, canon_q = normalize_query(q_dict)

    userinfo = f"{method.lower().strip()}:{password.strip()}"
    return CanonicalNode(
        raw_uri=uri,
        protocol="ss",
        host=host,
        port=port,
        userinfo=userinfo,
        path="",
        params=params,
        canonical_query=canon_q,
    )


def parse_ssr(uri: str) -> CanonicalNode | None:
    raw = uri[6:].split("#")[0].strip()
    decoded = decode_base64_flexible(raw)
    if not decoded:
        return None

    main_part, query_part = (
        decoded.split("/?", 1) if "/?" in decoded else (decoded, "")
    )
    parts = main_part.split(":")
    if len(parts) < 6:
        return None

    host = parts[0].strip("[]").lower()
    try:
        port = int(parts[1])
    except ValueError:
        port = DEFAULT_PORTS["ssr"]

    protocol = parts[2].lower().strip()
    method = parts[3].lower().strip()
    obfs = parts[4].lower().strip()
    password = decode_base64_flexible(parts[5])

    q_dict = urllib.parse.parse_qs(query_part)
    obfsparam = decode_base64_flexible(q_dict.get("obfsparam", [""])[0])
    protoparam = decode_base64_flexible(q_dict.get("protoparam", [""])[0])

    params = {
        "proto": protocol,
        "method": method,
        "obfs": obfs,
        "obfsparam": obfsparam,
        "protoparam": protoparam,
    }
    _, canon_q = normalize_query({k: [v] for k, v in params.items()})

    return CanonicalNode(
        raw_uri=uri,
        protocol="ssr",
        host=host,
        port=port,
        userinfo=password,
        path="",
        params=params,
        canonical_query=canon_q,
    )


def parse_standard_uri(uri: str) -> CanonicalNode | None:
    scheme, userinfo, host, port_str, path, query = safe_split_uri(uri)
    if not host:
        return None

    if scheme in ("hy2", "hysteria2"):
        scheme = "hysteria2"

    try:
        port = (
            int(port_str) if port_str else DEFAULT_PORTS.get(scheme, 443)
        )
    except ValueError:
        port = DEFAULT_PORTS.get(scheme, 443)

    userinfo = normalize_uuid(userinfo)
    path = clean_path(path)
    q_dict = urllib.parse.parse_qs(query)
    params, canon_q = normalize_query(q_dict)

    return CanonicalNode(
        raw_uri=uri,
        protocol=scheme,
        host=host,
        port=port,
        userinfo=userinfo,
        path=path,
        params=params,
        canonical_query=canon_q,
    )


def parse_canonical_node(line: str) -> CanonicalNode | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    lower = line.lower()
    if lower.startswith("vmess://"):
        return parse_vmess(line)
    elif lower.startswith("ss://"):
        return parse_shadowsocks(line)
    elif lower.startswith("ssr://"):
        return parse_ssr(line)
    elif lower.startswith(
        (
            "vless://",
            "trojan://",
            "tuic://",
            "hysteria://",
            "hysteria2://",
            "hy2://",
            "wireguard://",
            "snell://",
        )
    ):
        return parse_standard_uri(line)

    return None


# GeoIP & DNS Resolution Subsystem

def ensure_geoip_db():
    if os.path.exists(GEOIP_DB_PATH) and os.path.getsize(GEOIP_DB_PATH) > 100000:
        return True

    print("Downloading GeoLite2 Country database...")
    tmp_path = f"{GEOIP_DB_PATH}.tmp"
    try:
        req = urllib.request.Request(
            GEOIP_DB_URL, headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()

        with open(tmp_path, "wb") as f:
            f.write(data)

        os.replace(tmp_path, GEOIP_DB_PATH)
        print("GeoLite2 Country database downloaded successfully.")
        return True
    except Exception as e:
        print(f"Warning: Failed to download GeoIP database: {e}")
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        return False


def init_geoip_reader():
    global GEOIP_READER, GEOIP_INIT_ATTEMPTED
    if GEOIP_INIT_ATTEMPTED:
        return GEOIP_READER

    with INIT_LOCK:
        if GEOIP_INIT_ATTEMPTED:
            return GEOIP_READER

        GEOIP_INIT_ATTEMPTED = True
        if ensure_geoip_db() and os.path.exists(GEOIP_DB_PATH):
            try:
                import geoip2.database

                GEOIP_READER = geoip2.database.Reader(GEOIP_DB_PATH)
            except Exception as e:
                print(f"Warning: Could not initialize geoip2 reader: {e}")
        return GEOIP_READER


def get_country_flag(country_code: str) -> str:
    if not country_code or len(country_code) != 2 or not country_code.isalpha():
        return "🌐"
    return "".join(chr(127397 + ord(c)) for c in country_code.upper())


def resolve_single_host(host: str) -> str | None:
    if not host:
        return None
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def resolve_geo_for_host(host: str) -> tuple[str, str]:
    if not host:
        return "UN", "🌐"

    with GEO_LOCK:
        if host in GEO_CACHE:
            return GEO_CACHE[host]

    ip = resolve_single_host(host)
    if not ip:
        res = ("UN", "🌐")
        with GEO_LOCK:
            GEO_CACHE[host] = res
        return res

    reader = init_geoip_reader()
    country_code = None

    if reader is not None:
        try:
            resp = reader.country(ip)
            country_code = resp.country.iso_code
        except Exception:
            pass

    if not country_code or len(country_code) != 2:
        country_code = "UN"
    else:
        country_code = country_code.upper()

    res = (country_code, get_country_flag(country_code))
    with GEO_LOCK:
        GEO_CACHE[host] = res
    return res


def prefetch_dns_and_geo(hosts: set[str]):
    init_geoip_reader()
    print(f"Resolving GeoIP data for {len(hosts)} unique hosts...")
    with ThreadPoolExecutor(max_workers=DNS_THREADS) as executor:
        list(executor.map(resolve_geo_for_host, hosts))


# Unpacking & Sanitization Subsystem

def unpack_sub_content(content: str) -> list[str]:
    schemes = (
        "vmess://",
        "vless://",
        "ss://",
        "ssr://",
        "trojan://",
        "tuic://",
        "hysteria://",
        "hysteria2://",
        "hy2://",
        "wireguard://",
        "snell://",
    )

    if not any(scheme in content.lower() for scheme in schemes):
        decoded = decode_base64_flexible(content)
        if any(scheme in decoded.lower() for scheme in schemes):
            content = decoded

    lines = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if not any(line.lower().startswith(s) for s in schemes):
            dec = decode_base64_flexible(line)
            if any(s in dec.lower() for s in schemes):
                lines.extend(unpack_sub_content(dec))
                continue

        lines.append(line)
    return lines


def fetch_source_lines(source: str) -> list[str]:
    """Fetches subscription lines from a local file or remote URL (with CDN mirror fallbacks)."""
    source = source.strip()
    if source.startswith(("http://", "https://")):
        urls_to_try = generate_mirror_urls(source)
        last_exception = None

        for idx, url in enumerate(urls_to_try):
            try:
                if idx > 0:
                    print(f"  -> Attempting CDN mirror fallback [{idx}]: {url}")
                req = urllib.request.Request(
                    url, headers={"User-Agent": "Mozilla/5.0"}
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    content = resp.read().decode("utf-8", errors="ignore").strip()
                    if content:
                        return unpack_sub_content(content)
                    else:
                        raise ValueError("Received empty response")
            except Exception as e:
                last_exception = e
                print(f"  -> Fetch failed for '{url}': {e}")

        raise RuntimeError(
            f"All URL mirrors failed for '{source}'. Last error: {last_exception}"
        )

    elif os.path.exists(source):
        with open(source, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
        return unpack_sub_content(content)
    else:
        raise ValueError(f"Source not found or invalid scheme: '{source}'")


def sanitize_node(node: CanonicalNode, idx: int) -> str:
    code, flag = resolve_geo_for_host(node.host)
    proto_label = node.protocol.upper()
    node_name = f"{flag} {code} | {proto_label}-{idx:04d}"

    if node.protocol == "vmess":
        raw = node.raw_uri[8:].split("#")[0].strip()
        raw = urllib.parse.unquote(raw)
        json_str = (
            raw if raw.startswith("{") else decode_base64_flexible(raw)
        )
        if json_str:
            try:
                cfg = json.loads(json_str)
                if isinstance(cfg, dict):
                    cfg["ps"] = node_name
                    b64_val = base64.b64encode(
                        json.dumps(cfg, ensure_ascii=False).encode("utf-8")
                    ).decode("utf-8")
                    return f"vmess://{b64_val}"
            except Exception:
                pass

    main_part = node.raw_uri.split("#")[0].strip()
    return f"{main_part}#{urllib.parse.quote(node_name)}"


# Pipeline Orchestration

def cluster_and_deduplicate(nodes: list[CanonicalNode]) -> list[CanonicalNode]:
    nodes.sort(
        key=lambda n: (
            n.sort_key.address_type,
            n.sort_key.ip_int,
            n.sort_key.domain_hierarchy,
            n.sort_key.port,
            n.protocol,
            n.userinfo,
        )
    )

    seen_strict = set()
    seen_semantic = set()
    deduped = []

    for node in nodes:
        if node.strict_key in seen_strict:
            continue
        if node.semantic_key in seen_semantic:
            continue

        seen_strict.add(node.strict_key)
        seen_semantic.add(node.semantic_key)
        deduped.append(node)

    return deduped


def run_deduplication():
    print("Fetching upstream subscriptions...")
    lines = []
    for source in UPSTREAM_SOURCES:
        try:
            print(f"Fetching from source: {source}")
            fetched = fetch_source_lines(source)
            print(f"  -> Retrieved {len(fetched)} raw lines.")
            lines.extend(fetched)
        except Exception as e:
            print(f"  -> Warning: Failed to fetch from '{source}': {e}")

    if not lines:
        print("ERROR: Fetch returned 0 lines across all sources. Aborting to prevent wiping repo!")
        sys.exit(1)

    print(f"Total raw lines fetched: {len(lines)}")

    parsed_nodes: list[CanonicalNode] = []
    unparsed_count = 0

    for line in lines:
        node = parse_canonical_node(line)
        if node:
            parsed_nodes.append(node)
        else:
            unparsed_count += 1

    print(
        f"Parsed {len(parsed_nodes)} nodes ({unparsed_count} skipped/unparseable)."
    )

    unique_nodes = cluster_and_deduplicate(parsed_nodes)
    print(f"Unique nodes after clustering & deduplication: {len(unique_nodes)}")

    unique_hosts = {node.host for node in unique_nodes}
    prefetch_dns_and_geo(unique_hosts)

    sanitized_nodes = [
        sanitize_node(node, i + 1) for i, node in enumerate(unique_nodes)
    ]

    plain_text_out = "\n".join(sanitized_nodes) + "\n"
    with open("All_Configs_Sub.txt", "w", encoding="utf-8") as f:
        f.write(plain_text_out)

    b64_content = base64.b64encode(plain_text_out.encode("utf-8")).decode(
        "utf-8"
    )
    with open("All_Configs_base64_Sub.txt", "w", encoding="utf-8") as f:
        f.write(b64_content + "\n")

    print("Submissions successfully generated:")
    print("  -> All_Configs_Sub.txt")
    print("  -> All_Configs_base64_Sub.txt")


if __name__ == "__main__":
    run_deduplication()
