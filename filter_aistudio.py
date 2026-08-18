import base64
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, quote, unquote
import requests
import urllib.request

INPUT_FILE = "All_Configs_Sub.txt"
XRAY_BIN = "xray"
MAX_WORKERS = 25
TEST_TIMEOUT = 10
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"
GEOIP_DB_URL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML,"
        " like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Upgrade-Insecure-Requests": "1",
}

# Thread-safe cache for GeoIP lookups
GEO_CACHE = {}
GEO_LOCK = threading.Lock()
GEOIP_READER = None


def ensure_geoip_db():
    if not os.path.exists(GEOIP_DB_PATH):
        print("Downloading GeoLite2 Country database...")
        try:
            req = urllib.request.Request(
                GEOIP_DB_URL, headers={"User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            with open(GEOIP_DB_PATH, "wb") as f:
                f.write(data)
            print("GeoLite2 Country database downloaded successfully.")
        except Exception as e:
            print(f"Warning: Failed to download GeoIP database: {e}")


def init_geoip_reader():
    global GEOIP_READER
    if GEOIP_READER is not None:
        return GEOIP_READER

    ensure_geoip_db()
    if os.path.exists(GEOIP_DB_PATH):
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


def resolve_to_ip(host: str) -> str | None:
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


def get_country_info_for_host(host: str) -> tuple[str, str]:
    if not host:
        return "UN", "🌐"

    with GEO_LOCK:
        if host in GEO_CACHE:
            return GEO_CACHE[host]

    ip = resolve_to_ip(host)
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

    flag = get_country_flag(country_code)
    res = (country_code, flag)

    with GEO_LOCK:
        GEO_CACHE[host] = res

    return res


def extract_node_host(uri: str) -> str | None:
    uri = uri.strip()
    try:
        if uri.startswith("vmess://"):
            raw_payload = uri[8:].split("#")[0].strip()
            json_str = (
                raw_payload
                if raw_payload.startswith("{")
                else decode_base64(raw_payload)
            )
            if json_str:
                cfg = json.loads(json_str)
                if isinstance(cfg, dict):
                    add = str(
                        cfg.get("add") or cfg.get("address") or ""
                    ).strip()
                    if add:
                        return add
            return None

        if uri.startswith("ssr://"):
            raw_payload = uri[6:].split("#")[0].strip()
            decoded = decode_base64(raw_payload)
            if decoded:
                main_part = decoded.split("/?", 1)[0]
                parts = main_part.split(":")
                if len(parts) >= 1 and parts[0]:
                    return parts[0].strip()
            return None

        if uri.startswith("ss://"):
            raw_payload = uri[5:].split("#")[0].strip()
            main_part = raw_payload.split("?", 1)[0]
            if "@" in main_part:
                _, hostport = main_part.rsplit("@", 1)
            else:
                decoded = decode_base64(main_part)
                if "@" in decoded:
                    _, hostport = decoded.rsplit("@", 1)
                else:
                    return None
            _, _, host, _, _, _ = safe_urlsplit(f"ss://{hostport}")
            return host if host else None

        if uri.startswith(
            (
                "vless://",
                "trojan://",
                "tuic://",
                "hysteria://",
                "hysteria2://",
                "hy2://",
            )
        ):
            _, _, host, _, _, _ = safe_urlsplit(uri)
            return host if host else None

    except Exception:
        pass
    return None


def decode_base64(data: str) -> str:
    data = re.sub(r"\s+", "", data).replace("-", "+").replace("_", "/")
    if not data:
        return ""
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def clean_path(path: str) -> str:
    if not path:
        return "/"
    path = unquote(path).strip()
    if not path.startswith("/"):
        path = "/" + path
    return path


def safe_urlsplit(url: str):
    scheme = ""
    if "://" in url:
        scheme, url = url.split("://", 1)

    if "#" in url:
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

    return scheme.lower(), userinfo, host.lower(), port, path, query


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def is_port_listening(port: int, timeout: float = 0.1) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except Exception:
        return False


def parse_node_to_outbound(uri: str) -> dict | None:
    try:
        if uri.startswith("vmess://"):
            data = uri[8:].split("#")[0].strip()
            js_str = decode_base64(data) if not data.startswith("{") else data
            js = json.loads(js_str)

            add = str(js.get("add") or js.get("address") or "").strip()
            if not add:
                return None
            port = int(js["port"])
            uuid = str(js.get("id") or js.get("uuid") or "").strip()
            net = str(js.get("net") or js.get("network") or "tcp").lower()
            security = str(
                js.get("tls") or js.get("security") or "none"
            ).lower()
            sni = str(js.get("sni") or js.get("host") or add).strip()
            path = clean_path(str(js.get("path") or "/"))

            stream_settings = {"network": net}
            if security in ("tls", "reality"):
                stream_settings["security"] = "tls"
                stream_settings["tlsSettings"] = {
                    "serverName": sni,
                    "allowInsecure": True,
                }

            if net == "ws":
                stream_settings["wsSettings"] = {
                    "path": path,
                    "headers": {"Host": str(js.get("host") or add)},
                }
            elif net == "grpc":
                stream_settings["grpcSettings"] = {
                    "serviceName": str(js.get("path") or "")
                }

            aid_val = js.get("aid") or js.get("alterId")
            aid = int(aid_val) if aid_val is not None else 0

            return {
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": add,
                            "port": port,
                            "users": [
                                {
                                    "id": uuid,
                                    "alterId": aid,
                                    "security": "auto",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": stream_settings,
            }

        elif uri.startswith("vless://"):
            scheme, uuid, host, port, path, query = safe_urlsplit(uri)
            if not host:
                return None
            query_dict = parse_qs(query)
            security = query_dict.get("security", ["none"])[0].lower()
            net = query_dict.get("type", [query_dict.get("net", ["tcp"])[0]])[
                0
            ].lower()
            sni = query_dict.get("sni", [query_dict.get("host", [host])[0]])[0]
            flow = query_dict.get("flow", [""])[0]
            v_path = clean_path(path or query_dict.get("path", ["/"])[0])
            service_name = query_dict.get("serviceName", [v_path])[0]

            stream_settings = {"network": net}
            if security == "tls":
                stream_settings["security"] = "tls"
                stream_settings["tlsSettings"] = {
                    "serverName": sni,
                    "allowInsecure": True,
                }
            elif security == "reality":
                stream_settings["security"] = "reality"
                stream_settings["realitySettings"] = {
                    "serverName": sni,
                    "publicKey": query_dict.get("pbk", [""])[0],
                    "shortId": query_dict.get("sid", [""])[0],
                    "fingerprint": query_dict.get("fp", ["chrome"])[0],
                }

            if net == "ws":
                stream_settings["wsSettings"] = {
                    "path": v_path,
                    "headers": {"Host": query_dict.get("host", [sni])[0]},
                }
            elif net == "grpc":
                stream_settings["grpcSettings"] = {"serviceName": service_name}

            user_entry = {"id": uuid, "encryption": "none"}
            if flow:
                user_entry["flow"] = flow

            return {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": host,
                            "port": int(port or 443),
                            "users": [user_entry],
                        }
                    ]
                },
                "streamSettings": stream_settings,
            }

        elif uri.startswith("trojan://"):
            scheme, password, host, port, path, query = safe_urlsplit(uri)
            if not host:
                return None
            query_dict = parse_qs(query)
            sni = query_dict.get("sni", [host])[0]
            net = query_dict.get("type", [query_dict.get("net", ["tcp"])[0]])[
                0
            ].lower()

            stream_settings = {
                "network": net,
                "security": "tls",
                "tlsSettings": {"serverName": sni, "allowInsecure": True},
            }

            if net == "ws":
                stream_settings["wsSettings"] = {
                    "path": clean_path(
                        path or query_dict.get("path", ["/"])[0]
                    ),
                    "headers": {"Host": query_dict.get("host", [sni])[0]},
                }
            elif net == "grpc":
                stream_settings["grpcSettings"] = {
                    "serviceName": query_dict.get("serviceName", [""])[0]
                }

            return {
                "protocol": "trojan",
                "settings": {
                    "servers": [
                        {
                            "address": host,
                            "port": int(port or 443),
                            "password": password,
                        }
                    ]
                },
                "streamSettings": stream_settings,
            }

        elif uri.startswith("ss://"):
            raw = uri[5:].split("#")[0].strip()
            main_part = raw.split("?", 1)[0] if "?" in raw else raw

            method = ""
            password = ""
            hostport = ""

            if "@" in main_part:
                userinfo, hostport = main_part.rsplit("@", 1)
                decoded_userinfo = decode_base64(userinfo)
                if ":" in decoded_userinfo:
                    method, password = decoded_userinfo.split(":", 1)
                elif ":" in userinfo:
                    method, password = userinfo.split(":", 1)
                else:
                    return None
            else:
                decoded = decode_base64(main_part)
                if "@" in decoded:
                    userinfo, hostport = decoded.rsplit("@", 1)
                    if ":" in userinfo:
                        method, password = userinfo.split(":", 1)
                    else:
                        return None
                else:
                    return None

            _, _, host, port, _, _ = safe_urlsplit(f"ss://{hostport}")
            if not host:
                return None
            if not port:
                port = "8388"

            return {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [
                        {
                            "address": host,
                            "port": int(port),
                            "method": method.lower(),
                            "password": password,
                        }
                    ]
                },
            }
    except Exception:
        return None
    return None


def verify_aistudio_proxy(proxies: dict) -> bool:
    try:
        try:
            conn_resp = requests.get(
                "https://www.google.com/generate_204",
                proxies=proxies,
                headers=HEADERS,
                timeout=TEST_TIMEOUT,
            )
            if conn_resp.status_code not in (200, 204):
                return False
        except Exception:
            return False

        api_test_url = "https://generativelanguage.googleapis.com/v1beta/models?key=AIzaSyTestKeyForRegionCheck"
        api_resp = requests.get(
            api_test_url,
            proxies=proxies,
            headers=HEADERS,
            timeout=TEST_TIMEOUT,
        )

        api_text = api_resp.text.lower()
        blocked_api_keywords = [
            "user location is not supported",
            "failed_precondition",
            "not available in your country",
            "not available in your region",
        ]
        if api_resp.status_code == 403 or any(
            kw in api_text for kw in blocked_api_keywords
        ):
            return False

        if not any(
            kw in api_text
            for kw in (
                "api_key_invalid",
                "api key not valid",
                "invalid_argument",
            )
        ):
            return False

        studio_resp = requests.get(
            "https://aistudio.google.com/",
            headers=HEADERS,
            proxies=proxies,
            allow_redirects=True,
            timeout=TEST_TIMEOUT,
        )

        if studio_resp.status_code != 200:
            return False

        final_url = studio_resp.url.lower()
        if (
            "ai.google.dev" in final_url
            or "available_regions" in final_url
            or "available-regions" in final_url
        ):
            return False

        if not any(
            d in final_url
            for d in (
                "aistudio.google.com",
                "accounts.google.com",
                "google.com",
            )
        ):
            return False

        body_text = studio_resp.text.lower()
        blocked_keywords = [
            "not available in your region",
            "not available in your country",
            "available regions for google ai studio",
            "access denied",
            "403 forbidden",
        ]
        if any(keyword in body_text for keyword in blocked_keywords):
            return False

        return True
    except Exception:
        return False


def test_single_node(node_uri: str) -> tuple[bool, str]:
    outbound = parse_node_to_outbound(node_uri)
    if not outbound:
        return False, node_uri

    port = get_free_port()
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "http"}],
        "outbounds": [outbound],
    }

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
        json.dump(config, f)
        config_path = f.name

    proc = None
    try:
        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-config", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        port_ready = False
        start_time = time.time()
        while time.time() - start_time < 3.0:
            if proc.poll() is not None:
                break
            if is_port_listening(port):
                port_ready = True
                break
            time.sleep(0.05)

        if not port_ready:
            return False, node_uri

        proxies = {
            "http": f"http://127.0.0.1:{port}",
            "https": f"http://127.0.0.1:{port}",
        }

        if verify_aistudio_proxy(proxies):
            return True, node_uri

        return False, node_uri
    except Exception:
        return False, node_uri
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            except Exception:
                pass
        if os.path.exists(config_path):
            try:
                os.remove(config_path)
            except Exception:
                pass


def sanitize_node(uri: str, idx: int) -> str:
    uri = uri.strip().replace("\r", "")
    host = extract_node_host(uri)
    code, flag = get_country_info_for_host(host)
    node_name = f"{flag} {code} - AIStudio-Node-{idx}"

    if uri.startswith("vmess://"):
        raw_payload = uri[8:].split("#")[0].strip()
        json_str = (
            raw_payload
            if raw_payload.startswith("{")
            else decode_base64(raw_payload)
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
        return f"vmess://{raw_payload}#{quote(node_name)}"

    if uri.startswith("ssr://"):
        raw_payload = uri[6:].split("#")[0].strip()
        decoded = decode_base64(raw_payload)
        if decoded:
            main_part = decoded.split("/?", 1)[0] if "/?" in decoded else decoded
            query_part = decoded.split("/?", 1)[1] if "/?" in decoded else ""
            query_dict = parse_qs(query_part) if query_part else {}
            
            b64_remarks = (
                base64.urlsafe_b64encode(node_name.encode("utf-8"))
                .decode("utf-8")
                .rstrip("=")
            )
            query_dict["remarks"] = [b64_remarks]
            
            new_query = "&".join(f"{k}={v[0]}" for k, v in query_dict.items())
            new_decoded = f"{main_part}/?{new_query}"
            new_b64 = (
                base64.urlsafe_b64encode(new_decoded.encode("utf-8"))
                .decode("utf-8")
                .rstrip("=")
            )
            return f"ssr://{new_b64}"
        return uri

    # Standard URI protocols (vless, trojan, ss, tuic, hysteria, hysteria2, hy2)
    main_part = uri.split("#")[0].strip()
    encoded_name = quote(node_name)
    return f"{main_part}#{encoded_name}"


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"File {INPUT_FILE} not found!")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        raw_nodes = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]

    total_nodes = len(raw_nodes)
    print(
        f"Testing {total_nodes} deduplicated nodes against Google AI Studio..."
    )

    working_nodes = []
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(test_single_node, node): node for node in raw_nodes
        }

        for future in as_completed(futures):
            completed += 1
            success, uri = future.result()
            if success:
                working_nodes.append(uri)

            print(
                f"\rProgress: [{completed}/{total_nodes}] | Verified AI Studio Nodes: {len(working_nodes)}",
                end="",
                flush=True,
            )

    if not working_nodes:
        print(
            "\nERROR: No working AI Studio nodes found or test failed completely. Aborting save to avoid wiping repository files!"
        )
        sys.exit(1)

    sanitized_working = [
        sanitize_node(node, i + 1) for i, node in enumerate(working_nodes)
    ]

    plain_out = "\n".join(sanitized_working) + "\n"
    with open("AIStudio_Configs_Sub.txt", "w", encoding="utf-8") as f:
        f.write(plain_out)

    b64_content = base64.b64encode(plain_out.encode("utf-8")).decode("utf-8")
    with open("AIStudio_Configs_base64_Sub.txt", "w", encoding="utf-8") as f:
        f.write(b64_content + "\n")

    print(
        f"\nDone! Saved {len(sanitized_working)} working AI Studio nodes to 'AIStudio_Configs_Sub.txt'."
    )


if __name__ == "__main__":
    main()
