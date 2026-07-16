---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: ''
  PropagateID: ''
  ReservedCode1: ''
  ReservedCode2: ''
---

# Java 反序列化组件检测工具 - 原理说明

## 概述

Java 反序列化漏洞是 OWASP Top 10 中排名靠前的严重漏洞。当应用程序对不可信数据进行反序列化时，攻击者可通过构造恶意序列化对象实现远程代码执行（RCE）。

本工具通过 **DNS 外带（DNS Exfiltration）** 方式探测目标系统 Classpath 中存在的第三方库组件，进而推荐可用的 Gadget Chain 进行漏洞利用。

---

## 核心原理

### 为什么能通过 DNS 检测组件？

每种 ysoserial Gadget Chain 依赖特定的第三方库（如 Commons Collections、Spring、Groovy 等）中的特定类：

| Gadget Chain | 依赖库 | 关键类 |
|---|---|---|
| CommonsCollections1 | commons-collections 3.x | `InvokerTransformer`, `LazyMap` |
| CommonsCollections6 | commons-collections 3.x | `InvokerTransformer`, `TiedMapEntry` |
| CommonsBeanutils1 | commons-beanutils | `BeanComparator`, `ComparableComparator` |
| Groovy1 | groovy 2.x | `ConvertedClosure`, `MethodClosure` |
| Spring1 | spring-beans 4.x | `MethodInvokeTypeProvider` |
| URLDNS | JDK 内置 | `HashMap`, `URL` |

**检测逻辑：**

1. 为每条链生成一个携带 **唯一 DNS 子域名** 的序列化 payload
2. 将 payload 发送到目标反序列化端点
3. 如果目标 Classpath 中 **存在该链所需的所有类**，反序列化会成功执行并触发 DNS 查询
4. 通过 DNSLog 平台监控回连，**收到回连即表明该组件可用**

```
Payload(n) ──发送──▶ 目标反序列化端点
                         │
                         ├─ 类存在 → 反序列化成功 → DNS查询 → DNSLog ✅
                         │
                         └─ 类不存在 → ClassNotFoundException → 无DNS ❌
```

---

## URLDNS 探针

### 原理

URLDNS 是 ysoserial 中最特殊的链——它 **不依赖任何第三方库**，仅使用 JDK 内置类：

```
HashMap.readObject()
  → HashMap.putVal()
    → URL.hashCode()           # hashCode == -1 时触发 DNS
      → URLStreamHandler.getHostAddress()
        → InetAddress.getByName()
          → DNS 查询 ← 携带子域名信息外带
```

### 用途

- **验证反序列化端点是否存在**：收到 URLDNS 回连即确认目标接受反序列化输入
- **确认 DNS 外带通道可达**：目标能出网进行 DNS 查询
- **本工具支持纯 Python 生成 URLDNS payload**，无需安装 Java

---

## 检测流程

```
1. 配置 DNSLog 平台 (ceye.io / dnslog.cn / interactsh)
                     │
2. 生成所有链的检测 payload (每条链唯一子域名)
                     │
3. 逐个/批量发送 payload 到目标端点
                     │
4. 轮询 DNSLog 平台，监控回连记录
                     │
5. 根据回连子域名，映射出可用链
                     │
6. 进入交互式菜单，选择并生成利用 payload
```

---

## 交互式菜单功能介绍

检测完成后进入交互式菜单，提供完整的利用工作流：

1. **查看检测结果** — 按类别（RCE/JNDI/FileWrite）分组展示，清晰标注 JDK 版本限制
2. **链详情** — 查看特定链的依赖类、适用版本、替代方案
3. **生成利用 payload** — 为检测到的链生成实际 RCE payload（需要 ysoserial.jar）
4. **手动指定链** — 即使 DNS 未检测到，也可以强制为任意链生成 payload
5. **导出报告** — JSON 格式导出检测结果，方便后续分析和记录

### 智能分组

工具会自动识别链之间的替代关系：

```
CommonsCollections 3.x → CC1, CC3, CC5, CC6, CC7
CommonsCollections 4.x → CC2, CC4
Spring Framework        → Spring1, Spring2
Hibernate               → Hibernate1, Hibernate2
```

当检测到 Commons Collections 3.x 可用时，推荐 **CC6**（兼容性最好、无 JDK 版本限制）作为首选。

---

## DNSLog 平台对比

| 平台 | 优点 | 缺点 | 适用场景 |
|------|------|------|----------|
| **ceye.io** | 稳定、有 API、可过滤 | 需注册 | 持续使用、自动化 |
| **dnslog.cn** | 无需注册、即开即用 | 无 API 过滤、域名有时效 | 快速测试、临时使用 |
| **interactsh** | 自托管、隐私安全 | 需额外部署 | 高安全要求环境 |

---

## 注意事项

1. **网络可达性**：目标必须能够发起 DNS 出网查询，否则无法检测
2. **防火墙/代理**：企业内网可能存在 DNS 劫持或上游 DNS 服务器限制
3. **Payload 大小**：部分 WAF 会限制 HTTP body 大小，序列化 payload 可能被截断
4. **ysoserial.jar**：非 URLDNS 链的 payload 生成需要 Java 运行环境 + ysoserial.jar
5. **法律合规**：仅用于授权测试，未经授权的反序列化利用属于违法行为

---

## 参考资源

- [ysoserial - GitHub](https://github.com/frohoff/ysoserial)
- [Java Deserialization Cheat Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [MarshalSec - Java 反序列化系列](https://www.cnblogs.com/nice0e3/p/13957990.html)
