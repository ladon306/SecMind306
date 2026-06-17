"""
SubdomainEnum - 子域名枚举工具
==============================

核心特性:
  1. 字典爆破: 内置 200+ 常见子域名字典, 涵盖服务/环境/内部/云/CI-CD/安全类
  2. DNS 解析: 基于 dnspython 可靠查询, 支持自定义 DNS 服务器
  3. 多线程并发: 默认 20 线程, 可配置
  4. 递归发现: 对已发现子域名继续枚举 (如 sub.test.example.com)
  5. IP 解析: 展示每个子域名对应的 IP 地址
  6. 多格式输出: 支持 txt/json/csv 格式
  7. 限速控制: 可配置请求间隔, 避免触发防护
  8. 进度显示: 实时输出发现结果, 扫描结束展示汇总

用法:
  python subdomain_enum.py -d example.com
  python subdomain_enum.py -d example.com -t 30 -r
  python subdomain_enum.py -d example.com -w custom_wordlist.txt
  python subdomain_enum.py -d example.com --dns 8.8.8.8 --format json -o results.json
  python subdomain_enum.py -d example.com -r --depth 3 --delay 0.05

仅用于授权安全测试, 未经授权使用属违法行为。
"""

import argparse
import csv
import json
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

# ──────────────────────────────────────────────
# 颜色输出
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

def info(m):   print(f"{C.BLU}[*]{C.END} {m}")
def ok(m):     print(f"{C.GRN}[+]{C.END} {m}")
def warn(m):   print(f"{C.YLW}[!]{C.END} {m}")
def fail(m):   print(f"{C.RED}[-]{C.END} {m}")
def head(m):   print(f"\n{C.BLD}{'='*60}\n  {m}\n{'='*60}{C.END}")
def dim(m):    print(f"{C.DIM}    {m}{C.END}")

# ──────────────────────────────────────────────
# 内置子域名字典 — 200+ 常见子域名
# ──────────────────────────────────────────────
DEFAULT_WORDLIST = [
    # ── 常见服务 ──
    "www", "mail", "ftp", "admin", "api", "web", "blog", "dev", "stage",
    "staging", "test", "uat", "prod", "production", "app", "portal",
    "dashboard", "panel", "control", "manage", "monitor", "status",
    "cdn", "static", "media", "img", "images", "assets", "css", "js",
    "download", "upload", "files", "docs", "wiki", "help", "support",
    "forum", "community", "shop", "store", "pay", "payment", "billing",
    "auth", "login", "sso", "oauth", "id", "identity", "account",
    "registry", "hub", "git", "code", "repo", "search", "find",
    "news", "info", "about", "contact", "feedback", "survey",
    # ── 内部系统 ──
    "oa", "erp", "crm", "hr", "finance", "stock", "inventory",
    "intranet", "internal", "vpn", "proxy", "gateway", "tunnel",
    "backoffice", "backend", "worker", "task", "queue", "job",
    "report", "analytics", "data", "etl", "bi", "olap",
    "email", "smtp", "pop", "imap", "mx", "webmail",
    "ldap", "ad", "directory", "dns", "ns1", "ns2", "ns3",
    # ── 云服务 ──
    "s3", "cloudfront", "aws", "azure", "gcp", "digitalocean",
    "cloud", "storage", "bucket", "cdn2", "origin", "edge",
    "compute", "container", "k8s", "kubernetes", "docker", "registry2",
    "ecs", "ec2", "rds", "lambda", "func", "function", "serverless",
    # ── CI/CD & 开发工具 ──
    "jenkins", "gitlab", "github", "bitbucket", "jira", "confluence",
    "bamboo", "circleci", "travis", "build", "ci", "cd", "deploy",
    "release", "artifact", "nexus", "sonar", "sonarqube", "coverage",
    "stash", "scm", "pipeline", "runner", "agent",
    # ── 安全 & 监控 ──
    "nagios", "zabbix", "grafana", "prometheus", "kibana", "elastic",
    "splunk", "siem", "waf", "firewall", "ids", "ips",
    "security", "scan", "audit", "log", "logs", "trace", "apm",
    "alert", "alertmanager", "ping", "health", "heartbeat",
    # ── 数据库 & 缓存 ──
    "db", "database", "mysql", "postgres", "pgsql", "mongo", "mongodb",
    "redis", "memcache", "memcached", "elasticsearch", "es",
    "cassandra", "couchdb", "neo4j", "influxdb", "clickhouse",
    # ── 微服务 & API ──
    "api2", "api-gw", "api-v1", "api-v2", "rest", "graphql",
    "grpc", "websocket", "ws", "socket", "mqtt", "amqp",
    "user", "order", "product", "catalog", "cart", "checkout",
    "notify", "notification", "push", "sms", "messaging",
    "config", "conf", "env", "secret", "feature", "flag",
    # ── 移动 & 前端 ──
    "m", "mobile", "wap", "h5", "android", "ios", "app-api",
    "mini", "wechat", "weixin", "alipay", "flutter",
    # ── 备用 & 临时 ──
    "backup", "bak", "old", "new", "temp", "tmp", "demo", "poc",
    "beta", "alpha", "pre", "preprod", "sandbox", "playground",
    "mirror", "replica", "slave", "master", "primary", "secondary",
    # ── 其他 ──
    "mx1", "mx2", "mail2", "smtp2", "relay", "catchall",
    "office", "remote", "rdp", "ssh", "telnet", "vnc",
    "xmlrpc", "soap", "rpc", "restful", "swagger", "openapi",
]

# ──────────────────────────────────────────────
# 默认 DNS 服务器列表
# ──────────────────────────────────────────────
DEFAULT_DNS_SERVERS = [
    "8.8.8.8", "8.8.4.4",
    "1.1.1.1", "1.0.0.1",
    "114.114.114.114", "114.114.115.115",
    "223.5.5.5", "223.6.6.6",
    "119.29.29.29",
    "9.9.9.9",
]

# ──────────────────────────────────────────────
# 子域名枚举引擎
# ──────────────────────────────────────────────
class SubdomainEnumerator:
    def __init__(self, domain, wordlist=None, threads=20,
                 recursive=False, max_depth=2,
                 dns_servers=None, timeout=3, delay=0,
                 output_file=None, output_format="txt"):
        self.domain = domain.strip().lower()
        self.threads = threads
        self.recursive = recursive
        self.max_depth = max_depth
        self.timeout = timeout
        self.delay = delay
        self.output_file = output_file
        self.output_format = output_format

        self.dns_servers = dns_servers if dns_servers else DEFAULT_DNS_SERVERS[:4]
        self.wordlist = wordlist if wordlist else DEFAULT_WORDLIST

        self.found = {}
        self.found_lock = threading.Lock()
        self.scanned_count = 0
        self.scanned_lock = threading.Lock()
        self.start_time = None

        self._setup_resolver()

    def _setup_resolver(self):
        """配置 dnspython 解析器"""
        if not HAS_DNSPYTHON:
            return
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = self.dns_servers
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout * 2
        self.resolver.lifetime = min(self.resolver.lifetime, 10)

    def _resolve_domain(self, subdomain):
        """
        解析子域名, 返回 IP 列表
        优先使用 dnspython, 回退到 socket
        """
        ips = []

        if HAS_DNSPYTHON:
            try:
                answers = self.resolver.resolve(subdomain, "A", raise_on_no_answer=False)
                for rdata in answers:
                    ip = str(rdata.address)
                    if ip and ip not in ips:
                        ips.append(ip)
                if ips:
                    return ips
            except dns.resolver.NXDOMAIN:
                return []
            except dns.resolver.NoAnswer:
                pass
            except dns.exception.Timeout:
                pass
            except Exception:
                pass

        try:
            results = socket.getaddrinfo(subdomain, None, socket.AF_INET)
            for _, _, _, _, addr in results:
                ip = addr[0]
                if ip and ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            return []
        except socket.timeout:
            return []
        except Exception:
            pass

        return ips

    def _check_subdomain(self, sub_prefix, base_domain):
        """
        检查单个子域名是否存在
        返回 (full_subdomain, ips) 或 None
        """
        if sub_prefix and base_domain:
            full = f"{sub_prefix}.{base_domain}"
        else:
            return None

        if self.delay > 0:
            time.sleep(self.delay)

        ips = self._resolve_domain(full)
        with self.scanned_lock:
            self.scanned_count += 1

        if ips:
            with self.found_lock:
                if full not in self.found:
                    self.found[full] = ips
                    ip_str = ", ".join(ips[:4])
                    if len(ips) > 4:
                        ip_str += f" (+{len(ips)-4})"
                    ok(f"{C.CYN}{full}{C.END} → {ip_str}")
            return (full, ips)
        return None

    def _scan_level(self, base_domain, wordlist, depth):
        """扫描一层子域名"""
        new_found = []

        total = len(wordlist)
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for word in wordlist:
                fut = executor.submit(self._check_subdomain, word, base_domain)
                futures[fut] = word

            done_count = 0
            for future in as_completed(futures):
                done_count += 1
                try:
                    result = future.result()
                    if result:
                        new_found.append(result[0])
                except Exception:
                    pass

                if done_count % 50 == 0 or done_count == total:
                    dim(f"进度: {done_count}/{total} (已发现: {len(self.found)})")

        return new_found

    def scan(self):
        """执行完整子域名枚举"""
        head("SubdomainEnum - 子域名枚举工具")
        info(f"目标域名: {C.BLD}{self.domain}{C.END}")
        info(f"字典大小: {len(self.wordlist)} 条")
        info(f"线程数: {self.threads}")
        info(f"DNS 服务器: {', '.join(self.dns_servers)}")
        info(f"DNS 超时: {self.timeout}s")
        info(f"递归发现: {'开启 (深度 ' + str(self.max_depth) + ')' if self.recursive else '关闭'}")
        info(f"请求间隔: {self.delay}s" if self.delay > 0 else "请求间隔: 无")
        if self.output_file:
            info(f"输出文件: {self.output_file} ({self.output_format})")

        if not HAS_DNSPYTHON:
            warn("未安装 dnspython, 将使用 socket 回退模式 (精度降低)")
            warn("建议安装: pip install dnspython")

        print()
        self.start_time = time.time()

        first_level = self._scan_level(self.domain, self.wordlist, depth=1)

        if self.recursive and self.max_depth >= 2 and first_level:
            for depth in range(2, self.max_depth + 1):
                head(f"递归扫描 - 深度 {depth}/{self.max_depth}")
                next_bases = list(first_level)
                first_level = []
                for base in next_bases:
                    info(f"递归枚举: {base}")
                    sub_prefixes = self._get_recursive_wordlist()
                    found = self._scan_level(base, sub_prefixes, depth=depth)
                    first_level.extend(found)
                if not first_level:
                    info(f"深度 {depth} 未发现新子域名, 停止递归")
                    break

        self._print_summary()
        return self.found

    def _get_recursive_wordlist(self):
        """递归扫描用的精简字典"""
        return [
            "www", "mail", "api", "admin", "dev", "test", "staging",
            "app", "web", "portal", "internal", "vpn", "git", "ci",
            "db", "redis", "elastic", "monitor", "log", "cdn",
            "s3", "cloud", "docker", "k8s", "jenkins", "gitlab",
            "backup", "beta", "demo", "new", "old", "pre", "uat",
        ]

    def _print_summary(self):
        """输出扫描汇总"""
        elapsed = time.time() - self.start_time
        head("扫描结果汇总")
        info(f"目标域名: {self.domain}")
        info(f"扫描耗时: {elapsed:.1f}s")
        info(f"查询总数: {self.scanned_count}")
        info(f"请求速率: {self.scanned_count / max(elapsed, 0.1):.1f} req/s")
        info(f"DNS 服务器: {', '.join(self.dns_servers)}")

        if not self.found:
            warn("未发现子域名")
            return

        ok(f"共发现 {C.BLD}{len(self.found)}{C.END} 个子域名")
        print()

        sorted_subs = sorted(self.found.items(), key=lambda x: x[0])
        for sub, ips in sorted_subs:
            ip_str = ", ".join(ips[:4])
            if len(ips) > 4:
                ip_str += f" (+{len(ips)-4})"
            print(f"  {C.CYN}{sub:<40}{C.END} → {ip_str}")

        if self.output_file:
            self._save_results()
        print()

    def _save_results(self):
        """保存结果到文件"""
        sorted_subs = sorted(self.found.items(), key=lambda x: x[0])

        try:
            if self.output_format == "json":
                data = {
                    "domain": self.domain,
                    "total": len(self.found),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "subdomains": [
                        {"subdomain": sub, "ips": ips}
                        for sub, ips in sorted_subs
                    ],
                }
                with open(self.output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)

            elif self.output_format == "csv":
                with open(self.output_file, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["subdomain", "ips"])
                    for sub, ips in sorted_subs:
                        writer.writerow([sub, ";".join(ips)])

            else:
                with open(self.output_file, "w", encoding="utf-8") as f:
                    f.write(f"# SubdomainEnum Results\n")
                    f.write(f"# Target: {self.domain}\n")
                    f.write(f"# Found: {len(self.found)}\n")
                    f.write(f"# Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    for sub, ips in sorted_subs:
                        f.write(f"{sub} {' '.join(ips)}\n")

            ok(f"结果已保存: {self.output_file}")
        except IOError as e:
            fail(f"保存文件失败: {e}")


# ──────────────────────────────────────────────
# 字典加载
# ──────────────────────────────────────────────
def load_wordlist(filepath):
    """从文件加载自定义字典"""
    words = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    words.append(line.lower())
    except FileNotFoundError:
        fail(f"字典文件不存在: {filepath}")
        sys.exit(1)
    except IOError as e:
        fail(f"读取字典失败: {e}")
        sys.exit(1)

    seen = set()
    unique = []
    for w in words:
        if w not in seen:
            seen.add(w)
            unique.append(w)
    return unique


# ──────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SubdomainEnum - 子域名枚举工具",
        epilog="仅用于授权安全测试, 未经授权使用属违法行为。",
    )
    parser.add_argument("-d", "--domain", required=True,
                        help="目标域名 (如 example.com)")
    parser.add_argument("-w", "--wordlist",
                        help="自定义字典文件路径")
    parser.add_argument("-t", "--threads", type=int, default=20,
                        help="线程数 (默认20)")
    parser.add_argument("-o", "--output",
                        help="输出文件路径")
    parser.add_argument("--format", dest="output_format",
                        choices=["txt", "json", "csv"], default="txt",
                        help="输出格式 txt/json/csv (默认txt)")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="启用递归子域名发现")
    parser.add_argument("--depth", type=int, default=2,
                        help="最大递归深度 (默认2)")
    parser.add_argument("--dns",
                        help="自定义 DNS 服务器 (逗号分隔, 如 8.8.8.8,1.1.1.1)")
    parser.add_argument("--timeout", type=int, default=3,
                        help="DNS 超时秒数 (默认3)")
    parser.add_argument("--delay", type=float, default=0,
                        help="请求间隔秒数, 用于限速 (默认0)")

    args = parser.parse_args()

    domain = args.domain.rstrip(".")
    parts = domain.split(".")
    if len(parts) < 2:
        fail(f"无效域名: {domain}")
        sys.exit(1)

    wordlist = None
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        info(f"自定义字典: {len(wordlist)} 条")
    else:
        wordlist = DEFAULT_WORDLIST

    dns_servers = None
    if args.dns:
        dns_servers = [s.strip() for s in args.dns.split(",") if s.strip()]
        info(f"自定义 DNS: {', '.join(dns_servers)}")

    enumerator = SubdomainEnumerator(
        domain=domain,
        wordlist=wordlist,
        threads=args.threads,
        recursive=args.recursive,
        max_depth=args.depth,
        dns_servers=dns_servers,
        timeout=args.timeout,
        delay=args.delay,
        output_file=args.output,
        output_format=args.output_format,
    )
    enumerator.scan()


if __name__ == "__main__":
    main()
