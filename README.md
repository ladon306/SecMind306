---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'b349d464-827b-4214-8e05-0630768575dd'
  PropagateID: 'b349d464-827b-4214-8e05-0630768575dd'
  ReservedCode1: '2415bbce-c532-4deb-97f1-0499dedcc7a0'
  ReservedCode2: '2415bbce-c532-4deb-97f1-0499dedcc7a0'
---

<p align="center">
  <img src="assets/banner.jpg" alt="MY-PROJECT Banner" width="100%">
</p>

<h1 align="center">⚡ SecMind306 ⚡</h1>

<p align="center">
  <em>Security Tools & AI Algorithms — 一站式安全攻防 & 智能算法工具箱</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.13-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/专注-安全攻防|AI算法-E94D35?style=for-the-badge&logo=hackthebox&logoColor=white" alt="Focus">
  <img src="https://img.shields.io/github/stars/ladon306/SecMind306?style=for-the-badge&logo=github&logoColor=white" alt="Stars">
  <img src="https://img.shields.io/github/license/ladon306/SecMind306?style=for-the-badge" alt="License">
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
| [`subdomain_enum.py`](scanners/subdomain_enum/subdomain_enum.py) | 子域名枚举，200+ 内置字典 + 多 DNS 服务器 + 递归发现 + 多线程，支持 txt/json/csv 导出 | ✅ 可用 |
| [`port_scanner.py`](scanners/port_scanner/port_scanner.py) | 端口扫描，TCP Connect/SYN + 150+ 端口字典 + 服务探测 + T0-T5 时机模板，支持 common/extended/full | ✅ 可用 |

### 🤖 大模型 & AI 算法

| 文件 | 功能简介 | 状态 |
|:-----|:---------|:----:|
| [`cross_attention.py`](llm-tools/attention/cross_attention.py) | 交叉注意力机制实现（缩放点积注意力 / 单头 / 多头），支持 mask，含残差连接 + LayerNorm | ✅ 可用 |
| [`self_attention.py`](llm-tools/attention/self_attention.py) | 自注意力机制实现（缩放点积 / 因果掩码），含注意力权重可视化 + 性能基准 | ✅ 可用 |
| [`multi_head_attention.py`](llm-tools/attention/multi_head_attention.py) | 多头注意力实现，支持自注意力/交叉注意力双模式 + 因果掩码 + 填充掩码 + 残差+LayerNorm | ✅ 可用 |
| [`transformer.py`](llm-tools/transformer/transformer.py) | Transformer 完整实现（位置编码 / Encoder / Decoder / Pre-LN & Post-LN / Xavier 初始化） | ✅ 可用 |
| [`rnn.py`](llm-tools/rnn/rnn.py) | Vanilla RNN 实现（多层 / 双向 / tanh & ReLU 变体），含梯度消失实验 | ✅ 可用 |
| [`lstm.py`](llm-tools/rnn/lstm.py) | LSTM 实现（四门控 / 多层 / 双向 / Stateful），含遗忘门分析 + 序列预测 demo | ✅ 可用 |

---

## 🚀 快速开始

### 环境要求

- Python 3.10+
- 推荐使用 Conda 隔离环境

### 安装依赖

```bash
pip install requests torch dnspython
```

### 使用示例

#### 🔫 安全扫描工具

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
```

**目录扫描：**

```bash
# 基础扫描（默认 common 字典）
python scanners/dir_scanner/dir_scanner.py -u http://target.com

# 加载 OA + CMS 字典，20线程，递归3层
python scanners/dir_scanner/dir_scanner.py -u http://target.com --dict oa,cms -t 20 -r 3

# 自定义字典 + 结果导出
python scanners/dir_scanner/dir_scanner.py -u http://target.com -w my_dict.txt -o results.txt

# 禁用递归 + 不追加后缀
python scanners/dir_scanner/dir_scanner.py -u http://target.com --no-recursive --no-ext
```

**子域名枚举：**

```bash
# 基础枚举（200+ 内置字典）
python scanners/subdomain_enum/subdomain_enum.py -d example.com

# 自定义字典 + 30线程 + 递归2层
python scanners/subdomain_enum/subdomain_enum.py -d example.com -w custom.txt -t 30 -r --depth 2

# 指定 DNS 服务器 + JSON 导出
python scanners/subdomain_enum/subdomain_enum.py -d example.com --dns 8.8.8.8 -o results.json --format json
```

**端口扫描：**

```bash
# 常用端口扫描
python scanners/port_scanner/port_scanner.py -t 192.168.1.1

# 指定端口范围 + 服务探测
python scanners/port_scanner/port_scanner.py -t 192.168.1.1 -p 1-1000,3306,8080 --service-detection

# SYN 半开扫描 + T5 极速模式
python scanners/port_scanner/port_scanner.py -t 192.168.1.1 --scan-type syn -T 5

# 全端口扫描 + CSV 导出
python scanners/port_scanner/port_scanner.py -t 192.168.1.1 -p full -o results.csv --format csv
```

#### 🤖 大模型 & AI 算法

**交叉注意力：**

```bash
# 运行示例（单头/多头/mask 三种场景）
python llm-tools/attention/cross_attention.py

# 性能基准测试
python llm-tools/attention/cross_attention.py --benchmark
```

**自注意力 / 多头注意力：**

```bash
# 自注意力示例 + 权重可视化
python llm-tools/attention/self_attention.py

# 多头注意力（自注意力 + 交叉注意力双模式 demo）
python llm-tools/attention/multi_head_attention.py

# 性能基准测试
python llm-tools/attention/self_attention.py --benchmark
python llm-tools/attention/multi_head_attention.py --benchmark
```

**Transformer：**

```bash
# 完整 Transformer demo（forward / causal mask / 自回归 / Pre-LN vs Post-LN）
python llm-tools/transformer/transformer.py

# 性能基准测试
python llm-tools/transformer/transformer.py --benchmark
```

**RNN / LSTM：**

```bash
# Vanilla RNN demo + 梯度消失实验
python llm-tools/rnn/rnn.py

# LSTM demo + 遗忘门分析 + 序列预测
python llm-tools/rnn/lstm.py

# 性能基准测试
python llm-tools/rnn/rnn.py --benchmark
python llm-tools/rnn/lstm.py --benchmark
```

---

## 📖 原理文档

### 🔫 安全扫描原理

| 文档 | 内容 |
|:-----|:-----|
| [`SQL_Injection_Principles.md`](scanners/sql_injection/SQL_Injection_Principles.md) | 5 种 SQL 注入类型原理详解 + 攻击示例 + 防御建议 |
| [`XSS_Scanner_Principles.md`](scanners/xss/XSS_Scanner_Principles.md) | XSS 三种类型 + 上下文感知原理 + 在野 Payload + WAF 绕过技巧 |
| [`DirScanner_Principles.md`](scanners/dir_scanner/DirScanner_Principles.md) | 递归扫描策略 + 自定义 404 检测 + 分类字典设计 + 工具对比 |
| [`SubdomainEnum_Principles.md`](scanners/subdomain_enum/SubdomainEnum_Principles.md) | DNS 解析 + 字典爆破 + 递归发现 + 多 DNS 服务器 + 防御建议 |
| [`PortScanner_Principles.md`](scanners/port_scanner/PortScanner_Principles.md) | TCP 扫描原理 + SYN/FIN/Xmas/Null Scan + 服务探测 + 时机模板 |

### 🤖 AI 算法原理

| 文档 | 内容 |
|:-----|:-----|
| [`Cross_Attention_Principles.md`](llm-tools/attention/Cross_Attention_Principles.md) | 交叉注意力公式推导 + 计算流程 + 典型应用场景 |
| [`Self_Attention_Principles.md`](llm-tools/attention/Self_Attention_Principles.md) | 自注意力公式推导 + 因果掩码 + 缩放因子 + 复杂度分析 |
| [`MultiHead_Attention_Principles.md`](llm-tools/attention/MultiHead_Attention_Principles.md) | 多头注意力公式 + 头数与维度关系 + 掩码类型 + 残差+LayerNorm |
| [`Transformer_Principles.md`](llm-tools/transformer/Transformer_Principles.md) | Transformer 完整架构 + 位置编码 + Pre-LN/Post-LN + 变体对比 |
| [`RNN_LSTM_Principles.md`](llm-tools/rnn/RNN_LSTM_Principles.md) | RNN 梯度消失推导 + LSTM 四门控 + 加性更新 + GRU 对比 |

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
│   ├── dir_scanner/
│   │   ├── dir_scanner.py                   # 目录扫描工具
│   │   ├── DirScanner_Principles.md         # 目录扫描原理说明
│   │   └── wordlists/                       # 分类字典
│   │       ├── common.txt                   # 通用目录
│   │       ├── oa.txt                       # OA 系统
│   │       ├── cms.txt                      # CMS 系统
│   │       ├── framework.txt                # 开发框架
│   │       ├── middleware.txt               # 中间件
│   │       ├── sensitive.txt                # 敏感文件
│   │       └── api.txt                      # API 接口
│   ├── subdomain_enum/
│   │   ├── subdomain_enum.py                  # 子域名枚举工具
│   │   └── SubdomainEnum_Principles.md      # 子域名枚举原理说明
│   └── port_scanner/
│       ├── port_scanner.py                   # 端口扫描工具
│       └── PortScanner_Principles.md        # 端口扫描原理说明
├── llm-tools/                                # 大模型 & AI 算法
│   ├── attention/
│   │   ├── cross_attention.py                # 交叉注意力实现
│   │   ├── self_attention.py                 # 自注意力实现
│   │   ├── multi_head_attention.py           # 多头注意力实现
│   │   ├── Cross_Attention_Principles.md     # 交叉注意力原理说明
│   │   ├── Self_Attention_Principles.md      # 自注意力原理说明
│   │   └── MultiHead_Attention_Principles.md # 多头注意力原理说明
│   ├── transformer/
│   │   ├── transformer.py                    # Transformer 完整实现
│   │   └── Transformer_Principles.md         # Transformer 完整架构原理说明
│   └── rnn/
│       ├── rnn.py                            # Vanilla RNN 实现
│       ├── lstm.py                           # LSTM 实现
│       └── RNN_LSTM_Principles.md            # RNN & LSTM 原理说明
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