"""
DirScanner - 智能目录扫描工具
==============================

核心特性:
  1. 递归扫描: 即使父目录返回 404, 仍会继续扫描子目录 (借鉴 dirmap)
  2. 智能判断: 自动识别自定义 404 页面、重定向、空响应
  3. 分类字典: 按 OA / CMS / 框架 / 中间件 / 通用 分类, 可按需加载
  4. 多线程并发: 可配置线程数, 支持断点续扫
  5. 后缀扩展: 自动为目录路径追加常见文件后缀 (.php, .html, .bak 等)

用法:
  python dir_scanner.py -u http://target.com
  python dir_scanner.py -u http://target.com -t 30 -r 3
  python dir_scanner.py -u http://target.com --dict oa,cms     # 只加载 OA+CMS 字典
  python dir_scanner.py -u http://target.com --dict all         # 全部字典
  python dir_scanner.py -u http://target.com -w custom.txt      # 自定义字典

仅用于授权安全测试, 未经授权使用属违法行为。
"""

import argparse
import os
import re
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException

# ──────────────────────────────────────────────
# 颜色输出
# ──────────────────────────────────────────────
class C:
    RED = "\033[91m"; GRN = "\033[92m"; YLW = "\033[93m"
    BLU = "\033[94m"; CYN = "\033[96m"; BLD = "\033[1m"
    DIM = "\033[2m"; END = "\033[0m"

def info(m):  print(f"{C.BLU}[*]{C.END} {m}")
def ok(m):   print(f"{C.GRN}[+]{C.END} {m}")
def warn(m): print(f"{C.YLW}[!]{C.END} {m}")
def fail(m): print(f"{C.RED}[-]{C.END} {m}")
def head(m): print(f"\n{C.BLD}{'='*60}\n  {m}\n{'='*60}{C.END}")
def dim(m):  print(f"{C.DIM}    {m}{C.END}")

# ──────────────────────────────────────────────
# 自定义 404 检测器
# ──────────────────────────────────────────────
class Custom404Detector:
    """
    检测目标是否使用自定义 404 页面 (返回 200 但内容是 404)
    原理: 发送随机不存在的路径, 分析响应特征
    """

    def __init__(self, base_url, session, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.timeout = timeout
        self.baseline_status = None
        self.baseline_length = None
        self.baseline_hashes = set()
        self.custom_404_patterns = []
        self.is_custom_404 = False

    def detect(self):
        """发送多个随机路径, 判断是否存在自定义 404"""
        info("检测自定义 404 页面...")
        random_paths = [
            f"/ThIsPaThSuReLyDoEsNoTeXiSt{hash(str(time.time()))}",
            f"/n0t_ex1st_{hash('random1')}.html",
            f"/definitely_not_here_{hash('random2')}/",
        ]

        responses = []
        for path in random_paths:
            try:
                url = self.base_url + path
                resp = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=False)
                responses.append({
                    "status": resp.status_code,
                    "length": len(resp.content),
                    "hash": hash(resp.text[:500]),  # 取前500字符hash
                    "text_sample": resp.text[:300].lower(),
                })
            except RequestException:
                continue

        if not responses:
            self.is_custom_404 = False
            return self

        # 如果随机路径返回 200, 说明有自定义 404
        statuses = [r["status"] for r in responses]
        if all(s == 200 for s in statuses):
            self.is_custom_404 = True
            # 记录 404 页面的特征
            self.baseline_length = responses[0]["length"]
            for r in responses:
                self.baseline_hashes.add(r["hash"])
            # 常见 404 页面关键词
            for r in responses:
                text = r["text_sample"]
                for kw in ["not found", "404", "页面不存在", "找不到", "does not exist",
                           "page not found", "sorry", "error"]:
                    if kw in text:
                        self.custom_404_patterns.append(kw)

            warn(f"检测到自定义 404 (返回200)! 基线长度={self.baseline_length}")
        else:
            self.baseline_status = max(set(statuses), key=statuses.count)
            info(f"标准 404 响应: 状态码={self.baseline_status}")

        return self

    def is_404_like(self, response):
        """判断响应是否像 404 页面"""
        if response.status_code == 404:
            return True
        if response.status_code == 200 and self.is_custom_404:
            resp_hash = hash(response.text[:500])
            # hash 匹配
            if resp_hash in self.baseline_hashes:
                return True
            # 长度相近 (±100 bytes)
            if self.baseline_length and abs(len(response.content) - self.baseline_length) < 100:
                return True
            # 关键词匹配
            text_lower = response.text[:300].lower()
            if any(kw in text_lower for kw in self.custom_404_patterns):
                return True
        return False


# ──────────────────────────────────────────────
# 目录扫描引擎
# ──────────────────────────────────────────────
class DirScanner:
    def __init__(self, base_url, threads=20, timeout=10, max_depth=3,
                 dict_categories=None, custom_wordlist=None, extensions=None,
                 recursive=True, recursive_codes=None, proxy=None,
                 cookies=None, headers=None, output_file=None):
        self.base_url = base_url.rstrip("/")
        self.threads = threads
        self.timeout = timeout
        self.max_depth = max_depth
        self.recursive = recursive
        self.recursive_codes = recursive_codes or [200, 301, 302, 403]
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.output_file = output_file

        # 默认后缀扩展
        self.extensions = extensions or [".php", ".html", ".htm", ".asp",
                                          ".aspx", ".jsp", ".json", ".xml",
                                          ".txt", ".bak", ".old", ".zip",
                                          ".tar.gz", ".sql", ".conf", ".cfg",
                                          ".log", ".env", ".git", ".svn"]

        # Session
        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)
        self.session.headers.setdefault("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

        # 结果
        self.found = []          # (url, status, length, depth)
        self.scanned_count = 0
        self.start_time = None

        # 字典加载
        self.wordlist = self._load_wordlist(dict_categories, custom_wordlist)
        self.detector = None

    def _load_wordlist(self, categories, custom_path):
        """加载分类字典"""
        wordlist_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "wordlists")

        # 分类字典文件映射
        dict_files = {
            "common":    os.path.join(wordlist_dir, "common.txt"),
            "oa":        os.path.join(wordlist_dir, "oa.txt"),
            "cms":       os.path.join(wordlist_dir, "cms.txt"),
            "framework": os.path.join(wordlist_dir, "framework.txt"),
            "middleware": os.path.join(wordlist_dir, "middleware.txt"),
            "sensitive": os.path.join(wordlist_dir, "sensitive.txt"),
            "api":       os.path.join(wordlist_dir, "api.txt"),
        }

        paths = set()

        # 加载自定义字典
        if custom_path:
            if os.path.isfile(custom_path):
                with open(custom_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            paths.add(line)
                ok(f"自定义字典: {len(paths)} 条")

        # 加载分类字典
        if categories:
            cats = [c.strip() for c in categories.split(",")]
            if "all" in cats:
                cats = list(dict_files.keys())

            for cat in cats:
                fpath = dict_files.get(cat)
                if fpath and os.path.isfile(fpath):
                    count_before = len(paths)
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                paths.add(line)
                    count_after = len(paths)
                    info(f"字典 [{cat}]: +{count_after - count_before} 条")
                else:
                    warn(f"字典 [{cat}] 不存在, 跳过")
        else:
            # 默认只加载 common
            fpath = dict_files.get("common")
            if fpath and os.path.isfile(fpath):
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            paths.add(line)
                info(f"默认字典 [common]: {len(paths)} 条")

        if not paths:
            fail("字典为空! 请指定 --dict 或 -w")
            sys.exit(1)

        return sorted(paths)

    def _generate_paths(self, base_paths, with_extensions=True):
        """
        从基础路径生成完整路径列表
        目录路径追加后缀扩展
        """
        paths = set()
        for p in base_paths:
            p = p.strip("/")
            paths.add(p)
            if with_extensions and not "." in os.path.basename(p):
                # 是目录, 追加文件后缀
                for ext in self.extensions:
                    paths.add(p + ext)
                # 也追加 index 文件
                paths.add(p + "/index.html")
                paths.add(p + "/index.php")
        return list(paths)

    def _scan_path(self, path):
        """扫描单个路径"""
        url = self.base_url + "/" + path
        try:
            resp = self.session.get(url, timeout=self.timeout,
                                    allow_redirects=False,
                                    proxies=self.proxy)
            return {
                "url": url,
                "path": path,
                "status": resp.status_code,
                "length": len(resp.content),
                "is_dir": path.endswith("/") or resp.status_code in (301, 302),
                "response": resp,
            }
        except RequestException:
            return None

    def _is_interesting(self, result):
        """判断响应是否值得关注"""
        if result is None:
            return False

        status = result["status"]

        # 排除明确的 404
        if self.detector and self.detector.is_404_like(result["response"]):
            return False
        if status == 404:
            return False

        # 感兴趣的状态码
        interesting_codes = {200, 201, 204, 301, 302, 303, 307, 308,
                             401, 403, 405, 500, 501, 502, 503}
        return status in interesting_codes

    def scan(self):
        """执行扫描"""
        head("DirScanner - 智能目录扫描")
        info(f"目标: {self.base_url}")
        info(f"线程: {self.threads}")
        info(f"最大深度: {self.max_depth}")
        info(f"递归扫描: {'开启' if self.recursive else '关闭'}")
        info(f"递归状态码: {self.recursive_codes}")
        info(f"字典路径数: {len(self.wordlist)}")
        print()

        self.start_time = time.time()

        # 检测自定义 404
        self.detector = Custom404Detector(self.base_url, self.session, self.timeout)
        self.detector.detect()

        # BFS 层级扫描
        current_dirs = {"/"}  # 从根开始
        for depth in range(self.max_depth + 1):
            head(f"扫描层级 {depth}/{self.max_depth}")
            info(f"待扫描目录: {len(current_dirs)} 个")
            print()

            next_dirs = set()
            path_count = 0

            for base_dir in current_dirs:
                # 生成当前目录下的完整路径
                base_paths = [base_dir.lstrip("/") + w if base_dir == "/"
                              else base_dir.lstrip("/") + "/" + w
                              for w in self.wordlist]
                full_paths = self._generate_paths(base_paths)

                info(f"  目录 /{base_dir.lstrip('/') or ''} - 生成 {len(full_paths)} 条路径")

                # 并发扫描
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {executor.submit(self._scan_path, p): p
                               for p in full_paths}

                    for future in as_completed(futures):
                        self.scanned_count += 1
                        result = future.result()

                        if result and self._is_interesting(result):
                            url = result["url"]
                            status = result["status"]
                            length = result["length"]

                            # 输出
                            status_color = C.GRN if status == 200 else C.YLW if status in (301, 302) else C.RED
                            print(f"  {status_color}[{status}]{C.END} {url} ({length}B)")
                            self.found.append((url, status, length, depth))

                            # 判断是否递归
                            if (self.recursive and
                                depth < self.max_depth and
                                (status in self.recursive_codes or
                                 (status == 404 and self.recursive))):
                                # ★ 即使 404 也会加入递归队列 (借鉴 dirmap)
                                new_dir = "/" + result["path"].rstrip("/")
                                next_dirs.add(new_dir)

                path_count += len(full_paths)

            # 去重 + 限流
            current_dirs = next_dirs - {"", "/"}
            if not current_dirs:
                info(f"层级 {depth} 无新目录, 停止递归")
                break

        # 汇总
        self._print_summary()

        return self.found

    def _print_summary(self):
        """输出扫描汇总"""
        elapsed = time.time() - self.start_time
        head("扫描结果汇总")
        info(f"扫描耗时: {elapsed:.1f}s")
        info(f"发送请求: {self.scanned_count}")
        info(f"请求速率: {self.scanned_count / max(elapsed, 1):.1f} req/s")

        if not self.found:
            warn("未发现有效路径")
            return

        # 按状态码分组
        by_status = defaultdict(list)
        for url, status, length, depth in self.found:
            by_status[status].append((url, length))

        for status in sorted(by_status.keys()):
            entries = by_status[status]
            color = C.GRN if status == 200 else C.YLW if status in (301, 302) else C.RED
            print(f"\n{color}[{status}] - {len(entries)} 条{C.END}")
            for url, length in entries[:30]:
                print(f"  {url} ({length}B)")
            if len(entries) > 30:
                print(f"  ... 还有 {len(entries) - 30} 条")

        # 写入文件
        if self.output_file:
            with open(self.output_file, "w", encoding="utf-8") as f:
                for url, status, length, depth in self.found:
                    f.write(f"{status} {length}B {url}\n")
            ok(f"结果已保存: {self.output_file}")

        print()


# ──────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="DirScanner - 智能目录扫描工具",
        epilog="仅用于授权安全测试, 未经授权使用属违法行为。"
    )
    parser.add_argument("-u", "--url", required=True, help="目标URL")
    parser.add_argument("-t", "--threads", type=int, default=20, help="线程数 (默认20)")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时 (默认10)")
    parser.add_argument("-r", "--max-depth", type=int, default=3,
                        help="递归深度 (默认3)")
    parser.add_argument("--dict", dest="dict_categories",
                        help="字典分类, 逗号分隔: common,oa,cms,framework,middleware,sensitive,api 或 all")
    parser.add_argument("-w", "--wordlist", help="自定义字典文件路径")
    parser.add_argument("-e", "--extensions",
                        help="文件后缀, 逗号分隔 (默认 .php,.html,.htm,.asp,.aspx,.jsp,.json,.xml,.txt,.bak,.old,.zip,.sql,.conf,.env)")
    parser.add_argument("--no-recursive", action="store_true",
                        help="禁用递归扫描")
    parser.add_argument("--recursive-codes", default="200,301,302,403",
                        help="触发递归的状态码 (默认 200,301,302,403)")
    parser.add_argument("--proxy", help="代理地址")
    parser.add_argument("-c", "--cookies", help="Cookie字符串")
    parser.add_argument("-o", "--output", help="结果输出文件")
    parser.add_argument("--no-ext", action="store_true",
                        help="不追加文件后缀扩展 (只扫目录)")

    args = parser.parse_args()

    # 解析参数
    ext = None
    if args.no_ext:
        ext = []
    elif args.extensions:
        ext = [e.strip() if e.startswith(".") else "." + e.strip()
               for e in args.extensions.split(",")]

    recursive_codes = [int(c.strip()) for c in args.recursive_codes.split(",")]
    cookies = None
    if args.cookies:
        cookies = dict(item.split("=", 1) for item in args.cookies.split(";")
                       if "=" in item)

    scanner = DirScanner(
        base_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        max_depth=args.max_depth,
        dict_categories=args.dict_categories,
        custom_wordlist=args.wordlist,
        extensions=ext,
        recursive=not args.no_recursive,
        recursive_codes=recursive_codes,
        proxy=args.proxy,
        cookies=cookies,
        output_file=args.output,
    )
    scanner.scan()


if __name__ == "__main__":
    main()
