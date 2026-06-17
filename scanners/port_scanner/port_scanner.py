#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端口扫描器 (Port Scanner)
=========================

功能特性:
  1. TCP Connect 全连接扫描（最可靠，完整三次握手）
  2. TCP SYN 半开扫描（需管理员/root权限，不可用时自动降级为 Connect 扫描）
  3. 服务版本探测（Banner Grabbing，支持 HTTP/SSH/FTP/SMTP/MySQL/Redis 等常见服务）
  4. 内置 TOP_PORTS 端口字典（150+ 常见端口含服务名映射）
     - common: 约100个高频开放端口
     - extended: Top 1000
     - full: 1-65535
  5. 多线程并发扫描（默认100线程）
  6. 灵活端口指定: "80", "1-1000", "80,443,8080", "1-1024,3306,8080"
  7. Nmap 风格计时模板 T0-T5
  8. 结果输出至文件 (txt/json/csv)
  9. 单端口超时控制
 10. 实时进度显示

使用示例:
  # 扫描常见端口
  python port_scanner.py -t 192.168.1.1

  # SYN 扫描 + 服务探测
  python port_scanner.py -t 10.0.0.1 --scan-type syn --service-detection

  # 指定端口范围
  python port_scanner.py -t example.com -p 1-65535 -T 4 --threads 200

  # 输出为 JSON
  python port_scanner.py -t 192.168.1.1 -p common --format json -o results.json
"""

import socket
import struct
import sys
import argparse
import json
import csv
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# ──────────────────────────────────────────────
# 彩色输出
# ──────────────────────────────────────────────

class C:
    RED = "\033[91m"
    GRN = "\033[92m"
    YLW = "\033[93m"
    BLU = "\033[94m"
    CYN = "\033[96m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"


def info(msg: str):
    print(f"  {C.CYN}[*]{C.END} {msg}")


def success(msg: str):
    print(f"  {C.GRN}[+]{C.END} {msg}")


def warn(msg: str):
    print(f"  {C.YLW}[!]{C.END} {msg}")


def fail(msg: str):
    print(f"  {C.RED}[-]{C.END} {msg}")


# ──────────────────────────────────────────────
# 内置端口字典（150+ 常见端口）
# ──────────────────────────────────────────────

TOP_PORTS: Dict[int, str] = {
    1: "tcpmux", 5: "rje", 7: "echo", 11: "systat", 13: "daytime",
    17: "qotd", 18: "msp", 19: "chargen", 20: "ftp-data", 21: "ftp",
    22: "ssh", 23: "telnet", 25: "smtp", 27: "nsw-fe", 29: "msg-icp",
    31: "msg-auth", 33: "dsp", 37: "time", 38: "rap", 39: "rlp",
    41: "graphics", 42: "nameserver", 43: "whois", 44: "mpm-flags",
    49: "tacacs", 53: "dns", 67: "dhcp-server", 68: "dhcp-client",
    69: "tftp", 79: "finger", 80: "http", 81: "hosts2-ns",
    88: "kerberos", 95: "supdup", 101: "hostname", 102: "iso-tsap",
    104: "acr-nema", 109: "pop2", 110: "pop3", 111: "rpcbind",
    113: "auth", 115: "sftp", 117: "uucp-path", 119: "nntp",
    123: "ntp", 129: "pwdgen", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmptrap", 177: "xdmcp", 179: "bgp", 194: "irc",
    199: "smux", 201: "apple-qt", 209: "qmtp", 210: "z3950",
    213: "ipx", 220: "imap3", 259: "esro-gen", 264: "bgmp",
    280: "http-mgmt", 318: "tsp", 383: "hp-alm", 389: "ldap",
    427: "svrloc", 443: "https", 444: "snpp", 445: "microsoft-ds",
    464: "kpasswd", 465: "smtps", 497: "retrospect", 500: "isakmp",
    512: "exec", 513: "login", 514: "shell", 515: "printer",
    520: "efs", 523: "ibm-db2", 524: "ncp", 530: "rpc",
    543: "klogin", 544: "kshell", 548: "afp", 554: "rtsp",
    587: "submission", 631: "ipp", 636: "ldaps", 646: "ldp",
    873: "rsync", 902: "vmware-auth", 993: "imaps", 995: "pop3s",
    1080: "socks", 1098: "rmi-activation", 1100: "mctp",
    1433: "mssql", 1434: "mssql-udp", 1521: "oracle", 1720: "h323q931",
    1723: "pptp", 1755: "ms-streaming", 1900: "upnp", 2000: "cisco-sccp",
    2001: "dc", 2049: "nfs", 2100: "amiganetfs", 2121: "ccproxy-ftp",
    2207: "hpss-ndapi", 2301: "compaq-dm", 2383: "ms-olap",
    2401: "cvspserver", 2601: "zebra", 2607: "spug", 2638: "sybase",
    2809: "corbaloc", 2967: "ssc-agent", 3025: "arepa-cas",
    3071: "csregistrar", 3128: "squid", 3268: "ldap-global",
    3269: "ldap-gs-ssl", 3306: "mysql", 3389: "rdp", 3493: "nut",
    3517: "ap-mesh", 3632: "distcc", 3690: "svn", 3703: "adobeserver-3",
    3900: "udt_os", 4321: "rwhois", 4443: "pharos", 4444: "krb524",
    4500: "nat-t", 4555: "rsip", 4662: "edonkey", 4899: "radmin",
    5000: "upnp-p2p", 5009: "airport-admin", 5051: "ida-agent",
    5060: "sip", 5101: "admd", 5120: "barracuda", 5222: "xmpp-client",
    5225: "hp-server", 5269: "xmpp-server", 5300: "hacl-hb",
    5351: "nat-pmp", 5353: "mdns", 5432: "postgresql", 5555: "freeciv",
    5631: "pcanywheredata", 5632: "pcanywherestat", 5666: "nrpe",
    5800: "vnc-http", 5900: "vnc", 5985: "wsman", 6000: "x11",
    6001: "x11-1", 6101: "backupexec", 6106: "isd", 6379: "redis",
    6502: "netcheque", 6543: "mythtv", 6566: "sane-port",
    6660: "irc", 6666: "irc-serv", 6667: "irc", 7001: "afs3-callback",
    7002: "afs3-prserver", 7070: "realserver", 7777: "cbt",
    7778: "interwise", 8000: "http-alt", 8008: "http-alt",
    8009: "ajp13", 8080: "http-proxy", 8081: "sunproxy-admin",
    8443: "https-alt", 8888: "sun-answerbook", 9000: "cslistener",
    9001: "tor-orport", 9002: "dynamid", 9030: "iss-console-mgr",
    9090: "zeus-admin", 9100: "jetdirect", 9200: "elasticsearch",
    9300: "vrace", 9443: "tungsten-https", 9999: "abyss",
    10000: "snet-sensor-mgmt", 10050: "zabbix-agent",
    10051: "zabbix-trapper", 11211: "memcached",
    11337: "elite", 12345: "netbus", 13782: "veritas-netbackup",
    15000: "hydap", 16080: "fbsd", 18004: "biimenu",
    20000: "dnp", 27017: "mongodb", 27018: "mongodb",
    27019: "mongodb", 28017: "mongodb-web", 50000: "isakmp",
    50070: "hdfs-namenode", 50075: "hdfs-datanode",
}

# common 模式：高频开放端口约100个
COMMON_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 8888, 9000, 9200, 27017,
    49, 88, 161, 179, 389, 465, 514, 548, 554, 587,
    631, 636, 873, 1080, 1098, 1720, 1723, 2049, 2601, 3128,
    3268, 3690, 4443, 4662, 4899, 5000, 5060, 5222, 5353, 5666,
    5800, 5985, 6000, 6101, 6502, 6666, 6667, 7001, 7070, 7777,
    8000, 8008, 8009, 8081, 9001, 9090, 9100, 9443, 9999,
    10000, 10050, 10051, 11211, 12345, 15000, 20000, 27018, 27019,
    28017, 50000, 50070, 50075, 19, 67, 69, 79, 113, 119,
    137, 138, 162, 464, 512, 513, 520, 902, 2181, 2375,
]

# ──────────────────────────────────────────────
# 计时模板（Nmap 风格 T0-T5）
# ──────────────────────────────────────────────

TIMING_TEMPLATES: Dict[int, Dict] = {
    0: {"name": "Paranoid",  "timeout": 5.0, "delay": 0.50, "desc": "极慢，IDS规避"},
    1: {"name": "Sneaky",    "timeout": 3.0, "delay": 0.20, "desc": "较慢，IDS规避"},
    2: {"name": "Polite",    "timeout": 1.5, "delay": 0.10, "desc": "礼貌模式"},
    3: {"name": "Normal",    "timeout": 1.0, "delay": 0.00, "desc": "默认"},
    4: {"name": "Aggressive","timeout": 0.5, "delay": 0.00, "desc": "激进"},
    5: {"name": "Insane",    "timeout": 0.3, "delay": 0.00, "desc": "极速"},
}

# ──────────────────────────────────────────────
# 服务探测探针
# ──────────────────────────────────────────────

SERVICE_PROBES: Dict[int, bytes] = {
    80:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    9000: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    10000: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
}

BANNER_TIMEOUT = 2.0


# ──────────────────────────────────────────────
# 端口规格解析
# ──────────────────────────────────────────────

def parse_port_spec(spec: str) -> List[int]:
    """解析端口规格字符串，返回排序去重的端口列表。"""
    spec = spec.strip().lower()
    if spec == "full":
        return list(range(1, 65536))
    if spec == "extended":
        top1000 = sorted(TOP_PORTS.keys())[:1000]
        return top1000
    if spec == "common":
        return sorted(COMMON_PORTS)

    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                s, e = int(start), int(end)
                if not (1 <= s <= 65535 and 1 <= e <= 65535):
                    warn(f"端口范围超出 1-65535，已跳过: {part}")
                    continue
                for p in range(min(s, e), max(s, e) + 1):
                    ports.add(p)
            except ValueError:
                warn(f"无效端口范围，已跳过: {part}")
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
                else:
                    warn(f"端口超出 1-65535，已跳过: {p}")
            except ValueError:
                warn(f"无效端口号，已跳过: {part}")
    return sorted(ports)


# ──────────────────────────────────────────────
# 扫描结果数据类
# ──────────────────────────────────────────────

@dataclass
class PortResult:
    port: int
    state: str = "closed"
    service: str = ""
    version: str = ""

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "version": self.version,
        }


# ──────────────────────────────────────────────
# 解析目标主机
# ──────────────────────────────────────────────

def resolve_target(target: str) -> str:
    """将主机名解析为 IP 地址。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        addr = socket.gethostbyname(target)
        sock.close()
        return addr
    except socket.gaierror:
        fail(f"无法解析主机名: {target}")
        sys.exit(1)


# ──────────────────────────────────────────────
# SYN 扫描辅助函数
# ──────────────────────────────────────────────

def _build_syn(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """构造 TCP SYN 数据包。"""
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 28, 54321, 0x4000, 64, 6, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    ip_checksum = _checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack("!H", ip_checksum) + ip_hdr[12:]

    tcp_offset = 5 << 4
    tcp_flags = 0x02  # SYN
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, 0, 0,
        tcp_offset, tcp_flags, 64240, 0, 0,
    )

    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    placeholder = struct.pack("!4s4sBBH", src_addr, dst_addr, 0, 6, 20)
    tcp_checksum = _checksum(placeholder + tcp_hdr)
    tcp_hdr = tcp_hdr[:16] + struct.pack("!H", tcp_checksum) + tcp_hdr[18:]

    return ip_hdr + tcp_hdr


def _checksum(data: bytes) -> int:
    """计算校验和。"""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


# ──────────────────────────────────────────────
# 主扫描器类
# ──────────────────────────────────────────────

class PortScanner:
    def __init__(self, target: str, ports: List[int], scan_type: str,
                 timing: int, threads: int, timeout: float,
                 service_detection: bool, verbose: bool):
        self.target = target
        self.ip = resolve_target(target)
        self.ports = ports
        self.scan_type = scan_type
        self.timing = timing
        self.threads = threads
        self.timeout = timeout
        self.service_detection = service_detection
        self.verbose = verbose

        self.results: List[PortResult] = []
        self._lock = threading.Lock()
        self._scanned = 0
        self._total = len(ports)

        self._syn_available = False
        if scan_type == "syn":
            self._check_syn_available()

    def _check_syn_available(self):
        """检查 SYN 扫描是否可用（需要 root/管理员 + 原始套接字支持）。"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.close()
            self._syn_available = True
        except (PermissionError, OSError):
            warn("SYN 扫描需要管理员/root权限且系统支持原始套接字")
            warn("自动降级为 TCP Connect 扫描")
            self._syn_available = False
            self.scan_type = "connect"

    def _print_progress(self, port: int, result: PortResult):
        """实时打印扫描进度。"""
        self._scanned += 1
        pct = self._scanned / self._total * 100
        bar_len = 30
        filled = int(bar_len * self._scanned / self._total)
        bar = "█" * filled + "░" * (bar_len - filled)

        if result.state == "open":
            svc = result.service or TOP_PORTS.get(port, "unknown")
            line = (f"  {C.GRN}OPEN{C.END}  {C.BOLD}{port:>5}/tcp{C.END}  "
                    f"{C.CYN}{svc:<20}{C.END}")
            if result.version:
                line += f" {C.DIM}{result.version}{C.END}"
            print(line)
        elif self.verbose:
            svc = TOP_PORTS.get(port, "")
            print(f"  {C.DIM}CLOSED {port:>5}/tcp  {svc}{C.END}")

        if self._scanned % max(1, self._total // 20) == 0 or self._scanned == self._total:
            print(f"  {C.DIM}[{bar}] {pct:5.1f}% ({self._scanned}/{self._total}){C.END}",
                  end="\r")

    def _scan_connect(self, port: int) -> PortResult:
        """TCP Connect 全连接扫描。"""
        result = PortResult(port=port)
        result.service = TOP_PORTS.get(port, "unknown")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            ret = sock.connect_ex((self.ip, port))
            if ret == 0:
                result.state = "open"
                if self.service_detection:
                    result.version = self._grab_banner(sock, port)
            else:
                result.state = "closed"
            sock.close()
        except socket.timeout:
            result.state = "filtered"
        except ConnectionRefusedError:
            result.state = "closed"
        except OSError:
            result.state = "closed"
        return result

    def _scan_syn(self, port: int) -> PortResult:
        """TCP SYN 半开扫描（不可用时已降级，此方法不会被调用）。"""
        if not self._syn_available:
            return self._scan_connect(port)

        result = PortResult(port=port)
        result.service = TOP_PORTS.get(port, "unknown")

        try:
            src_port = 40000 + (port % 25000)
            src_ip = socket.gethostbyname(socket.gethostname())
            pkt = _build_syn(src_ip, self.ip, src_port, port)

            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            recv_sock.settimeout(self.timeout)
            recv_sock.bind(("", src_port))

            send_sock.sendto(pkt, (self.ip, 0))
            send_sock.close()

            try:
                while True:
                    data = recv_sock.recv(65535)
                    if len(data) < 40:
                        continue
                    ip_hdr_len = (data[0] & 0x0F) * 4
                    tcp_hdr = data[ip_hdr_len:]
                    if len(tcp_hdr) < 14:
                        continue
                    resp_port = struct.unpack("!H", tcp_hdr[0:2])[0]
                    flags = tcp_hdr[13]
                    if resp_port == port:
                        if flags & 0x12:  # SYN-ACK
                            result.state = "open"
                        elif flags & 0x14:  # RST-ACK
                            result.state = "closed"
                        elif flags & 0x04:  # RST
                            result.state = "closed"
                        break
            except socket.timeout:
                result.state = "filtered"
            finally:
                recv_sock.close()

        except (PermissionError, OSError):
            result.state = "closed"

        return result

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """获取服务 Banner 信息。"""
        banner = ""
        try:
            if port in SERVICE_PROBES:
                probe = SERVICE_PROBES[port].replace(b"target", self.target.encode())
                sock.send(probe)
            elif port in (25, 587):
                pass  # SMTP 会主动发 banner
            elif port == 21:
                pass  # FTP 会主动发 banner
            elif port == 22:
                pass  # SSH 会主动发 banner
            elif port == 110:
                pass  # POP3 会主动发 banner
            elif port == 143:
                pass  # IMAP 会主动发 banner
            else:
                # 对于未知服务，尝试发送换行触发 banner
                sock.send(b"\r\n")

            sock.settimeout(BANNER_TIMEOUT)
            data = sock.recv(1024)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()
            sock.settimeout(self.timeout)
        except (socket.timeout, OSError, UnicodeDecodeError):
            pass
        return self._identify_service(banner, port)

    def _identify_service(self, banner: str, port: int) -> str:
        """从 Banner 识别服务版本信息。"""
        if not banner:
            return ""
        banner_lower = banner.lower()

        patterns = [
            ("ssh",   r"ssh",       "SSH"),
            ("ftp",   r"ftp",       "FTP"),
            ("smtp",  r"smtp|esmtp","SMTP"),
            ("http",  r"http/",     "HTTP"),
            ("mysql", r"mysql",     "MySQL"),
            ("redis", r"redis",     "Redis"),
            ("nginx", r"nginx",     "Nginx"),
            ("apache",r"apache",    "Apache"),
            ("iis",   r"microsoft-iis", "IIS"),
        ]
        import re
        for key, pat, label in patterns:
            if key in banner_lower or re.search(pat, banner_lower):
                first_line = banner.split("\n")[0].strip()
                if len(first_line) > 80:
                    first_line = first_line[:80] + "..."
                return first_line

        first_line = banner.split("\n")[0].strip()
        if len(first_line) > 80:
            first_line = first_line[:80] + "..."
        return first_line

    def _scan_port(self, port: int) -> PortResult:
        """扫描单个端口。"""
        tmpl = TIMING_TEMPLATES[self.timing]
        delay = tmpl["delay"]
        if delay > 0:
            time.sleep(delay)

        if self.scan_type == "syn" and self._syn_available:
            result = self._scan_syn(port)
        else:
            result = self._scan_connect(port)

        with self._lock:
            self._print_progress(port, result)

        return result

    def run(self) -> List[PortResult]:
        """执行端口扫描，返回开放端口结果列表。"""
        open_count = 0
        closed_count = 0
        filtered_count = 0

        print()
        info(f"目标: {C.BLD}{self.target}{C.END} ({self.ip})")
        info(f"扫描类型: {self.scan_type.upper()}  |  "
             f"计时: T{self.timing} ({TIMING_TEMPLATES[self.timing]['name']})  |  "
             f"线程: {self.threads}")
        info(f"端口范围: {len(self.ports)} 个端口  |  "
             f"超时: {self.timeout}s  |  "
             f"服务探测: {'开' if self.service_detection else '关'}")
        print(f"  {C.DIM}{'─' * 60}{C.END}")
        print()

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port, p): p for p in self.ports}
            for future in as_completed(futures):
                result = future.result()
                with self._lock:
                    self.results.append(result)
                    if result.state == "open":
                        open_count += 1
                    elif result.state == "filtered":
                        filtered_count += 1
                    else:
                        closed_count += 1

        elapsed = time.time() - start_time

        self.results.sort(key=lambda r: r.port)
        open_results = [r for r in self.results if r.state == "open"]

        print()
        print(f"  {C.DIM}{'─' * 60}{C.END}")
        print()
        success(f"扫描完成! 耗时 {elapsed:.2f}s")
        info(f"总计 {len(self.ports)} 端口: "
             f"{C.GRN}{open_count} 开放{C.END}, "
             f"{C.RED}{closed_count} 关闭{C.END}, "
             f"{C.YLW}{filtered_count} 过滤{C.END}")

        if open_results:
            print()
            info("开放端口汇总:")
            print(f"  {C.DIM}{'PORT':>8}  {'STATE':<10} {'SERVICE':<20} VERSION{C.END}")
            print(f"  {C.DIM}{'─' * 70}{C.END}")
            for r in open_results:
                svc = r.service or TOP_PORTS.get(r.port, "unknown")
                ver = r.version or ""
                print(f"  {C.GRN}{r.port:>5}/tcp{C.END}  "
                      f"{C.GRN}open{C.END}      "
                      f"{C.CYN}{svc:<20}{C.END} "
                      f"{C.DIM}{ver}{C.END}")
        print()
        return open_results

    def save_results(self, filepath: str, fmt: str):
        """将结果保存至文件。"""
        open_results = [r for r in self.results if r.state == "open"]
        try:
            if fmt == "json":
                data = {
                    "target": self.target,
                    "ip": self.ip,
                    "scan_type": self.scan_type,
                    "timing": self.timing,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "open_ports": len(open_results),
                    "results": [r.to_dict() for r in open_results],
                }
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)

            elif fmt == "csv":
                with open(filepath, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["port", "state", "service", "version"])
                    for r in open_results:
                        writer.writerow([r.port, r.state, r.service, r.version])

            else:  # txt
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(f"端口扫描结果 - {self.target} ({self.ip})\n")
                    f.write(f"扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"扫描类型: {self.scan_type.upper()}  "
                            f"计时: T{self.timing}\n")
                    f.write(f"{'=' * 70}\n")
                    f.write(f"{'PORT':>8}  {'STATE':<10} {'SERVICE':<20} VERSION\n")
                    f.write(f"{'-' * 70}\n")
                    for r in open_results:
                        svc = r.service or "unknown"
                        f.write(f"{r.port:>5}/tcp  {r.state:<10} "
                                f"{svc:<20} {r.version}\n")
                    f.write(f"{'=' * 70}\n")
                    total = len(self.ports)
                    closed = total - len(open_results)
                    f.write(f"总计: {total} 端口, {len(open_results)} 开放, "
                            f"{closed} 关闭/过滤\n")

            success(f"结果已保存: {filepath} ({fmt.upper()})")
        except OSError as e:
            fail(f"保存文件失败: {e}")


# ──────────────────────────────────────────────
# CLI 入口
# ──────────────────────────────────────────────

def main():
    banner = f"""
{C.CYN}{C.BLD}
  ╔═══════════════════════════════════════════╗
  ║        Port Scanner v1.0 by SecMind      ║
  ╚═══════════════════════════════════════════╝
{C.END}"""
    print(banner)

    parser = argparse.ArgumentParser(
        description="高性能端口扫描器 - 支持 TCP Connect / SYN 半开扫描 / 服务探测",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
端口规格示例:
  common     内置高频端口（约100个，默认）
  extended   Top 1000 端口
  full       全端口 1-65535
  80         单个端口
  1-1000     端口范围
  80,443,8080    逗号分隔
  1-1024,3306,8080  混合模式

计时模板:
  T0  Paranoid    极慢（5s超时，500ms延迟），IDS规避
  T1  Sneaky      较慢（3s超时，200ms延迟），IDS规避
  T2  Polite      礼貌（1.5s超时，100ms延迟）
  T3  Normal      默认（1s超时，无延迟）
  T4  Aggressive  激进（0.5s超时，无延迟）
  T5  Insane      极速（0.3s超时，无延迟）
        """,
    )

    parser.add_argument("-t", "--target", required=True,
                        help="目标 IP 或主机名")
    parser.add_argument("-p", "--ports", default="common",
                        help="端口规格 (common/extended/full/范围)")
    parser.add_argument("--scan-type", choices=["connect", "syn"],
                        default="connect",
                        help="扫描类型: connect(默认) / syn(需root)")
    parser.add_argument("-T", "--timing", type=int, choices=range(0, 6),
                        default=3,
                        help="计时模板 T0-T5 (默认3)")
    parser.add_argument("--threads", type=int, default=100,
                        help="并发线程数 (默认100)")
    parser.add_argument("-o", "--output",
                        help="输出文件路径")
    parser.add_argument("--format", choices=["txt", "json", "csv"],
                        default="txt",
                        help="输出格式 (默认txt)")
    parser.add_argument("--timeout", type=float, default=None,
                        help="单端口超时秒数 (默认由计时模板决定)")
    parser.add_argument("--service-detection", action="store_true",
                        help="启用服务版本探测 (Banner Grabbing)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="显示关闭的端口")

    args = parser.parse_args()

    tmpl = TIMING_TEMPLATES[args.timing]
    timeout = args.timeout if args.timeout is not None else tmpl["timeout"]

    ports = parse_port_spec(args.ports)
    if not ports:
        fail("未指定有效端口")
        sys.exit(1)

    scanner = PortScanner(
        target=args.target,
        ports=ports,
        scan_type=args.scan_type,
        timing=args.timing,
        threads=args.threads,
        timeout=timeout,
        service_detection=args.service_detection,
        verbose=args.verbose,
    )

    scanner.run()

    if args.output:
        scanner.save_results(args.output, args.format)


if __name__ == "__main__":
    main()
