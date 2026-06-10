---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '0ab58b9b-bb8f-4d10-b9cb-de3c6ab8bbc6'
  PropagateID: '0ab58b9b-bb8f-4d10-b9cb-de3c6ab8bbc6'
  ReservedCode1: 'a5d3ad66-7906-4c90-bfca-712d7c19ab1c'
  ReservedCode2: 'a5d3ad66-7906-4c90-bfca-712d7c19ab1c'
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
| [`sql_injection_detector.py`](sql_injection_detector.py) | SQL 注入自动探测，支持 5 种注入类型（布尔盲注 / 时间盲注 / 报错注入 / 联合查询 / 堆叠注入），自动参数识别、数据库指纹检测 | ✅ 可用 |

### 🤖 大模型 & AI 算法

| 文件 | 功能简介 | 状态 |
|:-----|:---------|:----:|
| *持续添加中...* | | |

---

## 🚀 快速开始

### 环境要求

- Python 3.10+
- 推荐使用 Conda 隔离环境

### 安装依赖

```bash
pip install requests
```

### 使用示例

**SQL 注入探测：**

```bash
# 自动检测 URL 中所有 GET 参数
python sql_injection_detector.py -u "http://target/page?id=1"

# 指定参数 + POST 请求
python sql_injection_detector.py -u "http://target/login" -p username -m POST -d "username=admin&pass=123"

# 带 Cookie 和代理（Burp 抓包场景）
python sql_injection_detector.py -u "http://target/page?id=1" -c "session=abc" --proxy http://127.0.0.1:8080

# 跳过耗时的检查项
python sql_injection_detector.py -u "http://target/page?id=1" --skip time stacked
```

---

## 📖 原理文档

| 文档 | 内容 |
|:-----|:-----|
| [`SQL_Injection_Principles.md`](SQL_Injection_Principles.md) | 5 种 SQL 注入类型原理详解 + 攻击示例 + 防御建议 |

---

## 🗂️ 项目结构

```
my-project/
├── assets/
│   └── banner.jpg                    # 仓库头图
├── sql_injection_detector.py         # SQL 注入探测工具
├── SQL_Injection_Principles.md       # SQL 注入原理说明
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