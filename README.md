---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '29ed61e0-c2c4-41da-b0bc-7bea0a23684b'
  PropagateID: '29ed61e0-c2c4-41da-b0bc-7bea0a23684b'
  ReservedCode1: 'd9dba8c6-fb5f-45dd-8680-c0fe3fecbc10'
  ReservedCode2: 'd9dba8c6-fb5f-45dd-8680-c0fe3fecbc10'
---

<p align="center">
  <img src="assets/banner.jpg" alt="MY-PROJECT Banner" width="100%">
</p>

<h1 align="center">⚡ MY-PROJECT ⚡</h1>

<p align="center">
  <em>Security Tools & AI Algorithms — 一站式安全攻防 & 智能算法工具箱</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.13-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/专注-安全攻防|AI算法-E94D35?style=for-the-badge&logo=hackthebox&logoColor=white" alt="Focus">
  <img src="https://img.shields.io/github/stars/ladon306/my-project?style=for-the-badge&logo=github&logoColor=white" alt="Stars">
  <img src="https://img.shields.io/github/license/ladon306/my-project?style=for-the-badge" alt="License">
</p>

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0D1117,100:1F6FEB&height=80&section=footer" alt="wave" width="100%">
</p>

---

## 📂 工具一览

> 每个工具独立可用，按类别持续扩展中

### 🔫 安全扫描工具

| 文件 | 功能简介 | 状态 |
|:-----|:---------|:----:|
| [`sql_injection_detector.py`](scanners/sql_injection/sql_injection_detector.py) | SQL 注入自动探测，支持 5 种注入类型（布尔盲注 / 时间盲注 / 报错注入 / 联合查询 / 堆叠注入），自动参数识别、数据库指纹检测 | ✅ 可用 |
| [`xss_scanner.py`](scanners/xss/xss_scanner.py) | XSS 智能扫描，上下文感知 + 过滤器指纹 + Payload 分级（100+在野payload），并发可控，非无脑遍历 | ✅ 可用 |
| [`dir_scanner.py`](scanners/dir_scanner/dir_scanner.py) | 智能目录扫描，404 递归 + 自定义 404 检测 + 7 类分类字典（OA/CMS/框架/中间件/敏感/API） + 后缀扩展 | ✅ 可用 |

### 🤖 大模型 & AI 算法

| 文件 | 功能简介 | 状态 |
|:-----|:---------|:----:|
| [`cross_attention.py`](llm-tools/attention/cross_attention.py) | 交叉注意力机制实现（缩放点积注意力 / 单头 / 多头），支持 mask，含残差连接 + LayerNorm | ✅ 可用 |

---

## 🚀 快速开始

### 环境要求

- Python 3.10+
- 推荐使用 Conda 隔离环境

### 安装依赖

```bash
pip install requests torch
```

### 使用示例

**SQL 注入探测：**

```bash
# 自动检测 URL 中所有 GET 参数
python scanners/sql_injection/sql_injection_detector.py -u "http://target/page?id=1"

# 指定参数 + POST 请求
python scanners/sql_injection/sql_injection_detector.py -u "http://target/login" -p username -m POST -d "username=admin&pass=123"

# 带 Cookie 和代理（Burp 抓包场景）
python scanners/sql_injection/sql_injection_detector.py -u "http://target/page?id=1" -c "session=abc" --proxy http://127.0.0.1:8080

# 跳过耗时的检查项
python scanners/sql_injection/sql_injection_detector.py -u "http://target/page?id=1" --skip time stacked
```

**XSS 智能扫描：**

```bash
# 基础扫描（智能筛选 + L0/L1 payload）
python scanners/xss/xss_scanner.py -u "http://target/search?q=test"

# POST 参数扫描
python scanners/xss/xss_scanner.py -u "http://target/search" -p q -m POST -d "q=test"

# 带 Cookie 和代理
python scanners/xss/xss_scanner.py -u "http://target/search?q=test" -c "session=abc" --proxy http://127.0.0.1:8080

# 全量遍历（跳过智能筛选，所有payload都测）
python scanners/xss/xss_scanner.py -u "http://target/search?q=test" --fuzz-all

# 仅测核心payload（最快）
python scanners/xss/xss_scanner.py -u "http://target/search?q=test" --max-level 0
```

**交叉注意力：**

```bash
# 运行示例（单头/多头/mask 三种场景）
python llm-tools/attention/cross_attention.py

# 性能基准测试
python llm-tools/attention/cross_attention.py --benchmark
```

**目录扫描：**

```bash
# 基础扫描（默认 common 字典）
python scanners/dir_scanner/dir_scanner.py -u http://target.com

# 加载 OA + CMS 字典，20线程，递归3层
python scanners/dir_scanner/dir_scanner.py -u http://target.com --dict oa,cms -t 20 -r 3

# 全部字典
python scanners/dir_scanner/dir_scanner.py -u http://target.com --dict all

# 自定义字典 + 结果导出
python scanners/dir_scanner/dir_scanner.py -u http://target.com -w my_dict.txt -o results.txt

# 禁用递归 + 不追加后缀
python scanners/dir_scanner/dir_scanner.py -u http://target.com --no-recursive --no-ext
```

---

## 📖 原理文档

| 文档 | 内容 |
|:-----|:-----|
| [`SQL_Injection_Principles.md`](scanners/sql_injection/SQL_Injection_Principles.md) | 5 种 SQL 注入类型原理详解 + 攻击示例 + 防御建议 |
| [`Cross_Attention_Principles.md`](llm-tools/attention/Cross_Attention_Principles.md) | 交叉注意力公式推导 + 计算流程 + 典型应用场景 |
| [`XSS_Scanner_Principles.md`](scanners/xss/XSS_Scanner_Principles.md) | XSS 三种类型 + 上下文感知原理 + 在野 Payload + WAF 绕过技巧 |
| [`DirScanner_Principles.md`](scanners/dir_scanner/DirScanner_Principles.md) | 递归扫描策略 + 自定义 404 检测 + 分类字典设计 + 工具对比 |

---

## 🗂️ 项目结构

```
SecMind306/
├── assets/
│   └── banner.jpg                            # 仓库头图
├── scanners/                                 # 安全扫描类工具
│   ├── sql_injection/
│   │   ├── sql_injection_detector.py         # SQL 注入探测工具
│   │   └── SQL_Injection_Principles.md       # SQL 注入原理说明
│   ├── xss/
│   │   ├── xss_scanner.py                   # XSS 智能扫描工具
│   │   └── XSS_Scanner_Principles.md         # XSS 扫描原理说明
│   └── dir_scanner/
│       ├── dir_scanner.py                   # 目录扫描工具
│       ├── DirScanner_Principles.md         # 目录扫描原理说明
│       └── wordlists/                       # 分类字典
│           ├── common.txt                   # 通用目录
│           ├── oa.txt                       # OA 系统
│           ├── cms.txt                      # CMS 系统
│           ├── framework.txt                # 开发框架
│           ├── middleware.txt               # 中间件
│           ├── sensitive.txt                # 敏感文件
│           └── api.txt                      # API 接口
├── llm-tools/                                # 大模型 & AI 算法
│   └── attention/
│       ├── cross_attention.py                # 交叉注意力实现
│       └── Cross_Attention_Principles.md     # 交叉注意力原理说明
├── .gitignore
└── README.md
```

---

## ⚠️ 免责声明

本项目所有工具**仅供安全研究与授权渗透测试**使用。未经目标所有者明确授权，使用本工具对任何系统进行扫描或攻击均属违法行为。使用者需自行承担一切法律责任。

---

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=18&duration=3000&pause=1000&color=1F6FEB&center=true&vCenter=true&multiline=true&repeat=true&width=500&height=50&lines=Hack+The+Planet+%F0%9F%92%BB;Stay+Curious+%F0%9F%94%8D" alt="Typing SVG" />
</p>

> AI生成