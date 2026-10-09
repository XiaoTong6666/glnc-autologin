#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import fcntl
import gzip
import http.client
import json
import os
from pathlib import Path
import random
import re
import shlex
import socket
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit, urlunsplit


DEFAULT_CONFIG = "/etc/glnc-autologin.conf"
DEFAULT_PROBE = "http://firefox-portal-detection.com/generate_204"

# =============================================================================
# 协议来源与调用链说明
# =============================================================================
# 本文件不是根据“常见 Dr.COM 脚本”猜出来的，而是参考 pcapng 抓包与 Portal
# 前端资源逐步还原。下面给出关键证据，后续维护时优先以这些事实为准：
#
# 1. 抓包开始时客户端网卡已经有 IPv4 地址；抓包内没有 DHCP/BOOTP、ARP、
#    EAPOL/EAP。因此本程序只负责“获得 IPv4 后的 Portal 认证”，不实现 DHCP/802.1X。
#
# 2. 抓包帧 220/221/223/228：
#      Firefox -> http://firefox-portal-detection.com/success.txt?ipv4
#      校园侧透明设备 -> HTTP 302
#      Location: http://192.168.110.1/a79.htm?...wlanuserip=...&wlanacip=...
#    302 响应带 Server: NetEngine Server 1.0；伪造 SYN/ACK 还复用了客户端 SYN 的
#    IP ID/TCP timestamp，说明这是校园网关透明劫持 HTTP，而不是公网真实站点重定向。
#
# 3. Portal 页面随后调用：
#      /eportal/portal/page/loadConfig   （抓包帧 177 附近）
#      /drcom/chkstatus                 （抓包帧 183 附近）
#      /eportal/portal/login             （抓包帧 294）
#    成功响应位于帧 297：dr1003({"result":1,"msg":"Portal协议认证成功！"});
#
# 4. 当前 Portal 的 a41.js / a40.js 前端调用链进一步证明：
#      login.login()
#        -> login_method == 1
#        -> login.login_portal()
#        -> data.user_password = this.form.upass.value
#        -> login.portal_login(data, ...)
#        -> /eportal/portal/login
#    所以当前 login_method=1 下 user_password 就是密码框原始值，只经过 URL 编码。
#    另外 default_login() 才存在 en_md5 分支，但当前 loadConfig 明确 en_md5=0。
#
# 5. 抓包中的 loadConfig 返回：
#      login_method=1, en_md5=0, password_cut=0, enable_https=0
#    本程序每次登录前重新读取实时 Portal 配置，只有仍满足这一组合才发送凭据。
#    这是“失败关闭”安全护栏，避免学校升级 Portal 后还按旧规则发送密码。
#
# 6. 登录成功后数据面不是同一时刻立刻放行：帧 297 成功响应后约 138 ms 才观察到
#    外网 HTTPS SYN/ACK，随后 Firefox probe 才恢复真实 200/204。因此 login() 成功后
#    还必须再次做 connectivity probe，而不能仅凭 result=1 认定 Internet 已可用。
#
# 程序主调用链：
#   NetworkManager dispatcher / systemd 定时巡检 / 手动执行
#     -> run_serialized() 进程锁，避免多实例并发重复登录
#     -> resolve_interfaces()
#     -> discover_on_interface()
#     -> discover_portal()
#          -> HTTP connectivity probe
#          -> 校验 /a79.htm Dr.COM 302
#          -> 动态取得 user IP/MAC、AC IP/name 等
#     -> fetch_portal_profile()
#          -> Portal landing page
#          -> 当前页面引用的 JS
#          -> 动态取得 program_index/jsVersion/ePortal port
#          -> loadConfig
#          -> 校验 login_method/en_md5/password_cut/enable_https
#     -> login()
#          -> /eportal/portal/login
#     -> discover_portal()
#          -> 再次 probe 验证数据面已经放行
# =============================================================================


def read_config(path: str) -> dict[str, str]:
    # 配置文件只应保存“用户身份/可选安全 pin/重试策略”。
    # 网卡名、IP、MAC、Portal/AC 地址、端口等设备环境均尽量运行时发现。
    cfg: dict[str, str] = {}
    p = Path(path)
    if not p.exists():
        return cfg
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value:
            try:
                parsed = shlex.split(value, posix=True)
                value = parsed[0] if len(parsed) == 1 else value
            except ValueError:
                pass
        cfg[key] = value
    for key, value in os.environ.items():
        if key.startswith("GLNC_"):
            cfg[key] = value
    return cfg


def interface_ipv4(interface: str) -> str:
    # 抓包只能证明认证发生在已经拿到 IPv4 之后，所以这里直接读取现有地址，
    # 不把 DHCP 当成 Portal 协议的一部分。
    cp = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "dev", interface, "scope", "global"],
        check=False,
        capture_output=True,
        text=True,
    )
    for line in cp.stdout.splitlines():
        parts = line.split()
        if "inet" in parts:
            idx = parts.index("inet")
            return parts[idx + 1].split("/", 1)[0]
    raise RuntimeError(f"{interface}: no global IPv4 address yet")


def interface_mac(interface: str) -> str:
    return Path(f"/sys/class/net/{interface}/address").read_text().strip().lower()


def normalize_portal_mac(value: str) -> str:
    """按 Portal 前端的规则规范化 wlanusermac。

    当前 a41.js 的 term.init() 对 wlanusermac 只执行删除 '-' / ':' 分隔符的操作。

    因此不能把这个字段武断地解释为“永远是 6 字节真实网卡 MAC”。
    一种接入场景中它是 12 位 MAC；另一种接入场景的 302 则返回了更长的
    十六进制会话标识，Portal 仍然会把它原样放入 term.mac 并用于后续接口。
    """

    normalized = value.replace(":", "").replace("-", "").strip().lower()
    if not normalized or not re.fullmatch(r"[0-9a-f]+", normalized):
        raise RuntimeError(f"portal returned invalid wlanusermac token {value!r}")
    return normalized


def candidate_interfaces() -> list[str]:
    """返回当前有全局 IPv4 的候选物理接口。

    dispatcher 会直接传入发生 up/dhcp4-change 的接口；手动运行时不能假定
    网卡名称固定，因此自动发现 Ethernet/Wi-Fi，并过滤 Docker/LXC/TUN/WireGuard 等虚拟网卡。
    """

    cp = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "up", "scope", "global"],
        check=False,
        capture_output=True,
        text=True,
    )
    with_ipv4: list[str] = []
    for line in cp.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            interface = parts[1].split("@", 1)[0]
            if interface != "lo" and interface not in with_ipv4:
                with_ipv4.append(interface)

    # 自动触发层本来就依赖 NetworkManager，因此优先使用 NM 判定当前已连接的物理
    # Ethernet/Wi-Fi。这样不会在 wg0、docker0、veth、TUN 上逐个等 HTTP 超时。
    nm = subprocess.run(
        ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status"],
        check=False,
        capture_output=True,
        text=True,
    )
    physical: list[str] = []
    if nm.returncode == 0:
        for line in nm.stdout.splitlines():
            match = re.match(r"^(.*):([^:]+):([^:]+)$", line)
            if not match:
                continue
            interface, dev_type, state = match.groups()
            interface = interface.replace(r"\:", ":")
            if (
                dev_type in {"ethernet", "wifi"}
                and state.startswith("connected")
                and interface in with_ipv4
                and interface not in physical
            ):
                physical.append(interface)
    if physical:
        return physical

    # 如果 nmcli 输出异常，再退回 sysfs：真实硬件网卡通常存在 /sys/class/net/*/device，
    # 而 tun/veth/bridge 一般没有这个硬件 backing。
    return [
        interface
        for interface in with_ipv4
        if Path(f"/sys/class/net/{interface}/device").exists()
        and Path(f"/sys/class/net/{interface}/address").exists()
    ]


class BoundHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, interface: str, source_ip: str, **kwargs):
        super().__init__(*args, **kwargs)
        self._interface = interface
        self._source_ip = source_ip

    def connect(self) -> None:
        # 这里同时绑定“接口 + 源 IPv4”，不是为了模拟浏览器，而是为了多网卡环境下
        # 保证 probe/login 真正从被检测的那张校园网卡出去。否则 Wi-Fi/VPN 默认路由
        # 可能把请求送错接口，导致误判“已经联网”或把 Portal 请求发到错误网络。
        last_error: OSError | None = None
        infos = socket.getaddrinfo(
            self.host,
            self.port,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
        for af, socktype, proto, _canon, sockaddr in infos:
            sock = socket.socket(af, socktype, proto)
            try:
                sock.settimeout(self.timeout)
                bind_to_device = getattr(socket, "SO_BINDTODEVICE", None)
                if bind_to_device is not None:
                    try:
                        sock.setsockopt(
                            socket.SOL_SOCKET,
                            bind_to_device,
                            self._interface.encode() + b"\0",
                        )
                    except PermissionError:
                        # 非 root 手动运行时 SO_BINDTODEVICE 可能失败；仍保留源 IP bind。
                        pass
                sock.bind((self._source_ip, 0))
                sock.connect(sockaddr)
                self.sock = sock
                return
            except OSError as exc:
                last_error = exc
                sock.close()
        if last_error is not None:
            raise last_error
        raise OSError(f"cannot resolve/connect to {self.host}:{self.port}")


def http_get(
    url: str,
    *,
    interface: str,
    source_ip: str,
    headers: dict[str, str] | None = None,
    timeout: float = 4.0,
) -> tuple[int, dict[str, str], bytes]:
    # 当前抓包和 loadConfig 都明确显示 enable_https=0，Portal 登录本身使用明文 HTTP。
    # 因此这里只实现 HTTP；若未来实时配置切到 HTTPS，会在 fetch_portal_profile() 中
    # 失败关闭，而不是悄悄按旧协议继续发凭据。
    u = urlsplit(url)
    if u.scheme != "http" or not u.hostname:
        raise ValueError(f"only plain HTTP is supported for the campus portal: {url}")
    port = u.port or 80
    target = urlunsplit(("", "", u.path or "/", u.query, ""))
    conn = BoundHTTPConnection(
        u.hostname,
        port,
        timeout=timeout,
        interface=interface,
        source_ip=source_ip,
    )
    req_headers = {
        "Accept": "*/*",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) GLNC-AutoLogin/1.0",
        "Connection": "close",
    }
    if headers:
        req_headers.update(headers)
    try:
        conn.request("GET", target, headers=req_headers)
        resp = conn.getresponse()
        body = resp.read(512 * 1024)
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, body
    finally:
        conn.close()


def is_probe_success(status: int, body: bytes) -> bool:
    # generate_204 的正常结果是 204；Firefox success.txt 类探针正常结果可能是正文
    # "success"。登录前会被校园网关改成 302，登录后才恢复真实公网响应。
    if status == 204:
        return True
    if status != 200:
        return False
    text = body.decode("utf-8", errors="ignore").strip().lower()
    return text == "success"


def is_drcom_redirect(location: str) -> bool:
    if not location:
        return False
    u = urlsplit(location)
    q = parse_qs(u.query, keep_blank_values=True)
    # 抓包中的主字段名是 wlanuserip/wlanacip/wlanacname/wlanusermac。
    # 兼容项来自同类 ePortal 常见别名，但必须四类身份字段都齐全才认为是候选 Dr.COM。
    has = lambda names: any(name in q for name in names)
    return bool(
        u.scheme == "http"
        and u.hostname
        and u.path.endswith("/a79.htm")
        and has(("wlanuserip", "userip", "user-ip", "client_ip", "station_ip"))
        and has(("wlanacip", "acip", "switchip", "nasip", "nas-ip"))
        and has(("wlanacname", "sysname", "nasname", "nas-name"))
        and has(("wlanusermac", "usermac", "client_mac", "station_mac"))
    )


def parse_redirect(location: str, source_ip: str, local_mac: str) -> dict[str, str]:
    # 抓包帧 228 的 Location 是本程序最重要的运行时环境来源：
    #   wlanuserip  -> 当前客户端 IPv4
    #   wlanusermac -> Portal 使用的终端标识（可能是真实 MAC 或会话 token）
    #   wlanacip    -> AC/NAS/BAS 地址
    #   wlanacname  -> AC 名称
    # 本校园网 Portal 地址为 192.168.110.1；代码仍从 Location 动态获取地址，
    # 不必把校园网固定地址当成所有 Dr.COM/ePortal 部署的通用地址。
    u = urlsplit(location)
    q = parse_qs(u.query, keep_blank_values=True)

    def one(name: str, default: str = "") -> str:
        values = q.get(name)
        return values[0] if values else default

    def first(names: tuple[str, ...], default: str = "") -> str:
        for name in names:
            value = one(name)
            if value:
                return value
        return default

    return {
        "portal_host": u.hostname or "",
        "user_ip": first(("wlanuserip", "userip", "user-ip", "client_ip", "station_ip"), source_ip),
        "user_mac": first(("wlanusermac", "usermac", "client_mac", "station_mac"), local_mac),
        "ac_ip": first(("wlanacip", "acip", "switchip", "nasip", "nas-ip")),
        "ac_name": first(("wlanacname", "sysname", "nasname", "nas-name")),
        # 本次有线抓包这些字段为空/默认值，但保留从重定向动态采集的能力，方便其他设备
        # 或无线场景直接复用，而不是把 0/空字符串永远写死。
        "vlan_id": first(("wlan_vlan_id", "vlan", "vlanid"), "0"),
        "ssid": first(("wlan_user_ssid", "ssid", "essid")),
        "area_id": first(("wlan_user_areaid", "areaID")),
        "ap_mac": first(("wlan_ap_mac", "apmac", "ap_mac"), "000000000000"),
        "gw_id": first(("gw_id", "gw_mac"), "000000000000"),
    }


def discover_portal(
    cfg: dict[str, str], interface: str, source_ip: str, local_mac: str
) -> tuple[bool, dict[str, str]]:
    # 第一阶段只做“网络状态/Portal 发现”，此处绝不接触账号密码。
    # 抓包证明未认证时普通 HTTP 会被透明设备 302 到 /a79.htm；认证后 probe 恢复正常。
    probe_url = cfg.get("GLNC_PROBE_URL", DEFAULT_PROBE)
    status, headers, body = http_get(
        probe_url,
        interface=interface,
        source_ip=source_ip,
    )
    if is_probe_success(status, body):
        return True, {}

    location = headers.get("location", "")
    if not is_drcom_redirect(location):
        raise RuntimeError(
            f"connectivity probe is captive (HTTP {status}), but did not return the expected Dr.COM redirect"
        )

    portal = parse_redirect(location, source_ip, local_mac)
    portal["redirect_url"] = location

    # user IP 必须和实际绑定的源 IPv4 一致，这是当前会话最可靠的接口绑定证据。
    #
    # wlanusermac 则不能一概要求 == 本机 L2 MAC：
    #   - 某些接入方式：Portal 给出普通 12 位 MAC；
    #   - 另一些接入方式：Portal 给出长度不同的十六进制会话标识。
    # 实时 a41.js 的 term.init() 明确只是读取 query 的 wlanusermac 并去掉 ':'/'-'，
    # 后续 perceive/login 等接口继续使用 term.mac。因此 12 位时可以额外核对真实 MAC，
    # 非 12 位时必须把它视为 Portal 提供的 opaque session MAC/token，而不能自行替换。
    redirect_mac = normalize_portal_mac(portal["user_mac"])
    local_mac_norm = normalize_portal_mac(local_mac)
    if portal["user_ip"] != source_ip:
        raise RuntimeError(
            f"portal redirect user IP {portal['user_ip']} does not match {interface} source IP {source_ip}"
        )
    if len(redirect_mac) == 12 and redirect_mac != local_mac_norm:
        raise RuntimeError(
            f"portal redirect MAC {redirect_mac} does not match {interface} MAC {local_mac_norm}"
        )
    portal["user_mac"] = redirect_mac
    portal["user_mac_kind"] = "hardware" if len(redirect_mac) == 12 else "portal-token"
    if not portal["portal_host"] or not portal["ac_ip"] or not portal["ac_name"]:
        raise RuntimeError("Dr.COM redirect is missing portal/AC identity fields")
    return False, portal


def decode_body(headers: dict[str, str], body: bytes) -> bytes:
    # 抓到的 Portal JS/JSONP 响应存在 gzip，因此所有前端资源统一先解压再解析。
    encoding = headers.get("content-encoding", "").lower()
    if "gzip" in encoding or body.startswith(b"\x1f\x8b"):
        return gzip.decompress(body)
    return body


def parse_jsonp(body: bytes) -> dict:
    # ePortal API 不是纯 JSON，而是 dr1001({...}); / dr1003({...}); 这种 JSONP。
    # 抓包中的 loadConfig 与 login 成功响应都采用这一格式。
    text = body.decode("utf-8", errors="replace").strip()
    match = re.search(r"^[^(]+\((\{.*\})\)\s*;?\s*$", text, re.S)
    if not match:
        raise RuntimeError("portal returned malformed JSONP")
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise RuntimeError("portal returned invalid JSONP payload") from exc


def fetch_portal_profile(
    cfg: dict[str, str],
    interface: str,
    source_ip: str,
    portal: dict[str, str],
) -> dict[str, str]:
    """读取实时 ePortal 配置，并在发送凭据前确认仍兼容本次抓包证明的认证模式。

    证据链：
      302 /a79.htm -> landing page -> 页面引用的 JS -> program_index/jsVersion/端口
      -> /eportal/portal/page/loadConfig
      -> login_method=1, en_md5=0, password_cut=0, enable_https=0

    当前 a40.js 又证明 login_method=1 时：
      login.login() -> login.login_portal()
      -> user_password = form.upass.value
      -> login.portal_login()

    因此只有实时配置仍等于上述模式时，后面的 login() 才允许发送密码。
    """

    redirect_url = portal["redirect_url"]
    status, headers, body = http_get(
        redirect_url,
        interface=interface,
        source_ip=source_ip,
    )
    if status != 200:
        raise RuntimeError(f"portal landing page returned HTTP {status}")
    html = decode_body(headers, body).decode("gb18030", errors="replace")

    # 本次 Portal 的 bootstrap 是 a41.js，但文件名本身不是协议契约。
    # 为了迁移到其他设备/Portal 小版本，不写死 a41.js，而是扫描 landing page
    # 当前实际引用的脚本，从其中寻找真正需要的运行时常量。
    sources = [html]
    script_urls: list[str] = []
    for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        script_url = urljoin(redirect_url, match.group(1))
        if script_url not in script_urls:
            script_urls.append(script_url)

    patterns = {
        # 本次 a41.js 中 page.name == program_index；loadConfig 请求正是把它作为
        # program_index 发送。jsVersion 和 epHTTPPort 也来自同一份前端配置。
        "program_index": r"\bname\s*:\s*['\"]([^'\"]+)['\"]",
        "js_version": r"\bvar\s+jsVersion\s*=\s*['\"]([^'\"]+)['\"]",
        "portal_port": r"\bvar\s+epHTTPPort\s*=\s*(\d+)",
    }

    def values_from_sources() -> dict[str, str]:
        combined = "\n".join(sources)
        found: dict[str, str] = {}
        for name, pattern in patterns.items():
            match = re.search(pattern, combined)
            if match:
                found[name] = match.group(1)
        return found

    found = values_from_sources()
    # 不依赖厂商以后继续使用 a41.js 这个名字；找到全部常量后立即停止下载更多脚本。
    for script_url in script_urls[:20]:
        if len(found) == len(patterns):
            break
        try:
            status, script_headers, script_body = http_get(
                script_url,
                interface=interface,
                source_ip=source_ip,
            )
            if status != 200:
                continue
            sources.append(
                decode_body(script_headers, script_body).decode("gb18030", errors="replace")
            )
            found = values_from_sources()
        except Exception:
            continue

    missing = [name for name in patterns if name not in found]
    if missing:
        raise RuntimeError(
            "cannot determine live ePortal bootstrap values: " + ", ".join(missing)
        )

    program_index = found["program_index"]
    js_version = found["js_version"]
    portal_port = found["portal_port"]
    expected_program = cfg.get("GLNC_EXPECTED_PROGRAM_INDEX", "").strip()
    # 可选校园身份 pin。由于 Portal 是 HTTP，没有 TLS 证书可校验，program_index 可作为
    # 额外的部署指纹，避免在另一个同样使用 Dr.COM 的网络里自动发送 GLNC 凭据。
    if expected_program and program_index != expected_program:
        raise RuntimeError(
            f"unexpected ePortal program_index {program_index!r}; "
            f"expected {expected_program!r}"
        )

    def b64(value: str) -> str:
        return base64.b64encode(value.encode()).decode()

    # 抓包帧 177 的 loadConfig 请求证明：这里只对 wlan_user_ip / wlan_ac_ip 做 Base64。
    # 这和后面的 /login 不同，/login 中 IP/AC IP 是普通文本，密码也是原始表单值。
    params = [
        ("callback", "dr1001"),
        ("program_index", program_index),
        ("wlan_vlan_id", portal["vlan_id"]),
        ("wlan_user_ip", b64(portal["user_ip"])),
        ("wlan_user_ipv6", ""),
        ("wlan_user_ssid", portal["ssid"]),
        ("wlan_user_areaid", portal["area_id"]),
        ("wlan_ac_ip", b64(portal["ac_ip"])),
        ("wlan_ap_mac", re.sub(r"[^0-9a-fA-F]", "", portal["ap_mac"]).lower()),
        ("gw_id", re.sub(r"[^0-9a-fA-F]", "", portal["gw_id"]).lower()),
        ("jsVersion", js_version),
        ("v", str(random.randint(500, 10499))),
        ("lang", "zh"),
    ]
    endpoint = (
        f"http://{portal['portal_host']}:{portal_port}/eportal/portal/page/loadConfig"
    )
    status, headers, body = http_get(
        endpoint + "?" + urlencode(params),
        interface=interface,
        source_ip=source_ip,
        headers={"Referer": redirect_url},
    )
    if status != 200:
        raise RuntimeError(f"ePortal loadConfig returned HTTP {status}")
    obj = parse_jsonp(decode_body(headers, body))
    if obj.get("code") not in (1, "1") or not isinstance(obj.get("data"), dict):
        raise RuntimeError("ePortal loadConfig did not return a successful configuration")
    data = obj["data"]

    # 下面四个值不是“我们希望它是什么”，而是本次抓包 + 实时 Portal JS 共同确认的
    # 当前协议契约。任一变化都意味着认证流程可能已经改版，必须停止而不是猜。
    live_method = str(data.get("login_method", ""))
    live_md5 = str(data.get("en_md5", ""))
    live_cut = str(data.get("password_cut", ""))
    live_https = str(data.get("enable_https", ""))
    if (live_method, live_md5, live_cut, live_https) != ("1", "0", "0", "0"):
        raise RuntimeError(
            "unsupported live portal mode: "
            f"login_method={live_method!r} en_md5={live_md5!r} "
            f"password_cut={live_cut!r} enable_https={live_https!r}; "
            "refusing to send credentials using the captured plaintext-login flow"
        )

    return {
        "program_index": program_index,
        "page_index": str(data.get("page_index", "")),
        "js_version": js_version,
        "portal_port": portal_port,
        "login_method": live_method,
        "en_md5": live_md5,
        "password_cut": live_cut,
        "enable_https": live_https,
    }


def build_account(cfg: dict[str, str]) -> str:
    # 抓包中的 user_account 已经包含运营商后缀。Portal 页面 pc.js 也证明运营商下拉框
    # 只是把 @telecom/@cmcc/@unicom/@sarft 拼到用户输入后面，因此推荐直接保存完整账号。
    direct = cfg.get("GLNC_ACCOUNT", "").strip()
    if direct:
        return direct
    username = cfg.get("GLNC_USERNAME", "").strip()
    if not username:
        raise RuntimeError("GLNC_USERNAME (or GLNC_ACCOUNT) is not configured")
    suffix = cfg.get("GLNC_SUFFIX", "").strip()
    if "@" in username or not suffix:
        return username
    return username + suffix


def resolve_interfaces(args_interface: str | None, cfg: dict[str, str]) -> list[str]:
    # 优先级：命令行显式指定 > 配置安全 pin > 自动枚举。
    if args_interface:
        return [args_interface]
    pinned = cfg.get("GLNC_INTERFACE", "").strip()
    if pinned:
        return [pinned]
    interfaces = candidate_interfaces()
    if not interfaces:
        raise RuntimeError("no active interface with a global IPv4 address was found")
    return interfaces


def discover_on_interface(
    cfg: dict[str, str],
    interface: str,
    *,
    tries: int,
    retry_delay: float,
) -> tuple[str, str, bool, dict[str, str]]:
    # NetworkManager 的 up/dhcp4-change 可能早于地址/路由完全稳定，所以单接口模式允许
    # 重试；自动扫描多接口时每张接口只试一次，避免 VPN/异常链路累计大量超时。
    last_error: Exception | None = None
    for attempt in range(1, tries + 1):
        try:
            source_ip = interface_ipv4(interface)
            local_mac = interface_mac(interface)
            online, portal = discover_portal(cfg, interface, source_ip, local_mac)
            return source_ip, local_mac, online, portal
        except Exception as exc:
            last_error = exc
            if attempt < tries:
                time.sleep(retry_delay)
    assert last_error is not None
    raise last_error


def login(
    cfg: dict[str, str],
    interface: str,
    source_ip: str,
    portal: dict[str, str],
    profile: dict[str, str],
    *,
    dry_run: bool = False,
) -> tuple[bool, str]:
    # 到这里之前必须已经经过：
    #   discover_portal() 的网络/会话身份校验
    #   fetch_portal_profile() 的实时协议模式校验
    # login() 本身只负责复现抓包帧 294 的 GET /eportal/portal/login。
    account = build_account(cfg)
    password = cfg.get("GLNC_PASSWORD", "")
    if not password:
        raise RuntimeError("GLNC_PASSWORD is not configured")

    host = portal["portal_host"]
    port = int(profile["portal_port"])
    # 必须使用 Portal 会话里的 wlanusermac/term.mac，而不是强行读取本机硬件 MAC。
    # 当 Portal 返回扩展 token 时，a41.js 证明前端也是原样把它用于登录参数。
    mac = normalize_portal_mac(portal["user_mac"])
    params = [
        # callback=dr1003、terminal_type=1、双 lang、jsVersion 等均来自抓到的成功请求。
        # v 是前端 _jsonp() 生成的随机数，本次 a40.js 逻辑为 Math.random() 派生值；
        # 它不是挑战值或会话 token。
        ("callback", "dr1003"),
        ("login_method", profile["login_method"]),
        ("user_account", account),
        # 关键：a40.js 的 login.login_portal() 直接取 this.form.upass.value。
        # 这里传入原始密码，由 urlencode() 只做一次 URL percent-encoding，绝不预先 MD5。
        ("user_password", password),
        ("wlan_user_ip", portal["user_ip"]),
        ("wlan_user_ipv6", ""),
        ("wlan_user_mac", mac),
        ("wlan_ac_ip", portal["ac_ip"]),
        ("wlan_ac_name", portal["ac_name"]),
        ("jsVersion", profile["js_version"]),
        ("terminal_type", "1"),
        ("lang", "zh-cn"),
        ("v", str(random.randint(1000, 9999))),
        ("lang", "zh"),
    ]
    endpoint = f"http://{host}:{port}/eportal/portal/login"
    # 注意：当前学校 Portal 把密码放在明文 HTTP GET query 中，这是服务端协议本身的行为。
    # 本程序不会打印完整 url，也不会把它交给 curl 等子进程，避免凭据进入 argv/日志。
    url = endpoint + "?" + urlencode(params)

    if dry_run:
        masked_account = account[:2] + "***" + (account[-5:] if len(account) > 7 else "")
        return True, (
            f"dry-run endpoint={endpoint} account={masked_account} "
            f"ip={portal['user_ip']} mac={mac} ac={portal['ac_ip']} "
            f"ac_name={portal['ac_name']}"
        )

    status, _headers, body = http_get(
        url,
        interface=interface,
        source_ip=source_ip,
        headers={"Referer": f"http://{host}/"},
    )
    if status != 200:
        return False, f"unexpected portal response (HTTP {status})"
    try:
        obj = parse_jsonp(decode_body(_headers, body))
    except RuntimeError as exc:
        return False, str(exc)
    result = obj.get("result")
    msg = str(obj.get("msg", ""))
    if result in (1, "1", "ok"):
        # 抓包帧 297 的 result=1 只表示 Portal 认证接受；数据面 ACL 的实际放行稍晚，
        # 因此 main() 后面还会重新 probe 验证，不在这里直接宣布 Internet 可用。
        return True, msg or "portal returned success"
    return False, msg or f"portal result={result!r}"


def main() -> int:
    parser = argparse.ArgumentParser(description="GLNC Dr.COM ePortal auto-login")
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--interface")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    cfg = read_config(args.config)
    try:
        tries = max(1, int(cfg.get("GLNC_DISCOVERY_TRIES", "10")))
        retry_delay = max(0.0, float(cfg.get("GLNC_RETRY_DELAY", "2")))
        interfaces = resolve_interfaces(args.interface, cfg)

        selected: tuple[str, str, str, dict[str, str]] | None = None
        online_interfaces: list[tuple[str, str]] = []
        errors: list[str] = []

        # 多网卡时逐张绑定接口探测：例如 Wi-Fi 已联网而 Ethernet 仍 captive，不能因为
        # 任意一张接口能上网就提前退出，必须找到真正返回 GLNC 302 的那张接口。
        for interface in interfaces:
            try:
                source_ip, local_mac, online, portal = discover_on_interface(
                    cfg,
                    interface,
                    tries=tries if len(interfaces) == 1 else 1,
                    retry_delay=retry_delay,
                )
                if online:
                    online_interfaces.append((interface, source_ip))
                    continue
                selected = (interface, source_ip, local_mac, portal)
                break
            except Exception as exc:
                errors.append(f"{interface}: {exc}")

        if selected is None:
            if online_interfaces:
                summary = ", ".join(f"{name} ({ip})" for name, ip in online_interfaces)
                print(f"online: no GLNC captive interface found; Internet works on {summary}")
                if errors:
                    # 某张接口能联网不代表其他接口也可用。定时巡检时需要保留诊断信息，
                    # 避免只看到其中一张网卡在线，却忽略了其他网卡的探测失败。
                    print("warning: failed interface probes: " + "; ".join(errors), file=sys.stderr)
                return 0
            detail = "; ".join(errors) if errors else "no candidate interface matched"
            raise RuntimeError(f"no GLNC captive interface found: {detail}")

        interface, source_ip, local_mac, portal = selected
        print(f"selected interface: {interface} ({source_ip})")

        print(
            "portal: "
            f"host={portal['portal_host']} ip={portal['user_ip']} "
            f"mac={portal['user_mac']} mac_kind={portal['user_mac_kind']} "
            f"ac={portal['ac_ip']} ac_name={portal['ac_name']}"
        )
        profile = fetch_portal_profile(cfg, interface, source_ip, portal)
        print(
            "profile: "
            f"login_method={profile['login_method']} jsVersion={profile['js_version']} "
            f"port={profile['portal_port']} en_md5={profile['en_md5']} "
            f"password_cut={profile['password_cut']}"
        )
        ok, message = login(
            cfg,
            interface,
            source_ip,
            portal,
            profile,
            dry_run=args.dry_run,
        )
        if args.dry_run:
            print(message)
            return 0 if ok else 1
        if not ok:
            print(f"login failed: {message}", file=sys.stderr)
            return 2

        print(f"login accepted: {message}")
        # 抓包显示 Portal result=1 与外网真正恢复之间存在约百毫秒级延迟，所以这里按
        # GLNC_VERIFY_* 重试 connectivity probe，确认数据面已经放行后才返回成功。
        verify_tries = max(1, int(cfg.get("GLNC_VERIFY_TRIES", "5")))
        verify_delay = max(0.0, float(cfg.get("GLNC_VERIFY_DELAY", "1")))
        for attempt in range(1, verify_tries + 1):
            time.sleep(verify_delay)
            try:
                verified, _ = discover_portal(cfg, interface, source_ip, local_mac)
                if verified:
                    print("verified: Internet probe succeeded")
                    return 0
            except Exception:
                if attempt == verify_tries:
                    raise
        print("login was accepted, but Internet probe is still captive", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def run_serialized(state_dir: Path | None = None) -> int:
    """在多个 systemd 触发源之间串行执行一次检查/登录。

    调用方可能同时来自 NetworkManager 的 up/dhcp4-change 和每分钟的巡检 timer。
    两套 service 的 systemd 单元互不排斥，因此必须在进程层面抢同一把锁。

    unit 使用 StateDirectory=glnc-autologin，保证 ProtectSystem=strict 下仍可写锁文件。
    手动以 root 启动时也会使用这把锁。非 root 手动探测保持原有行为。
    """
    if os.geteuid() != 0:
        return main()

    if state_dir is None:
        state_dir = Path("/var/lib/glnc-autologin")
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (state_dir / "client.lock").open("a+") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("skip: another GLNC check/login is already in progress")
            return 0
        return main()


if __name__ == "__main__":
    raise SystemExit(run_serialized())
