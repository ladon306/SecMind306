---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '93adb3f6-39b4-43f9-92f0-5965c1312073'
  PropagateID: '93adb3f6-39b4-43f9-92f0-5965c1312073'
  ReservedCode1: 'd0c93cfc-b75e-4c24-b946-445b904599c6'
  ReservedCode2: 'd0c93cfc-b75e-4c24-b946-445b904599c6'
---

# Self-Attention 自注意力机制 — 原理说明

## 核心概念

自注意力（Self-Attention）是 Transformer 的核心组件。**查询 Q、键 K、值 V 均来自同一个输入序列**，使序列中每个位置能直接关注序列内所有其他位置，捕获长距离依赖关系。

---

## 数学公式推导

### 缩放点积注意力

$$\text{Attention}(Q, K, V) = \text{softmax}\left(\frac{QK^T}{\sqrt{d_k}}\right) V$$

逐步拆解：

1. **线性投影**：输入 $X \in \mathbb{R}^{n \times d}$ 经三个投影矩阵生成 Q/K/V

$$Q = XW^Q, \quad K = XW^K, \quad V = XW^V$$

2. **注意力得分**：Q 与 K 的转置做点积，计算每对位置的相似度

$$S = QK^T \in \mathbb{R}^{n \times n}$$

3. **缩放**：除以 $\sqrt{d_k}$

$$S_{\text{scaled}} = \frac{S}{\sqrt{d_k}}$$

4. **Softmax 归一化**：每行转为概率分布

$$A = \text{softmax}(S_{\text{scaled}}), \quad A_{ij} = \frac{e^{S_{\text{scaled},ij}}}{\sum_k e^{S_{\text{scaled},ik}}}$$

5. **加权求和**：用注意力权重对 V 加权

$$\text{Output} = AV \in \mathbb{R}^{n \times d_v}$$

---

## Q=K=V 来源同一输入的含义

自注意力中 Q、K、V 均由同一输入 $X$ 投影而来：

- **Q（Query）**：当前位置发出"我在找什么"的查询
- **K（Key）**：每个位置提供"我有什么信息"的键
- **V（Value）**：每个位置提供"我的实际内容"的值

**直觉**：每个 token 同时既是提问者（Q），也是被查询者（K）和信息提供者（V），实现序列内部的**全局信息交互**。

---

## 缩放因子 √d_k 的必要性

当 $d_k$ 较大时，点积 $q \cdot k = \sum_{i=1}^{d_k} q_i k_i$ 的方差也随之增大：

$$\text{Var}(q \cdot k) = d_k \cdot \sigma^2$$

假设 $q_i, k_i \sim \mathcal{N}(0, \sigma^2)$ 独立同分布，则点积的方差为 $d_k \sigma^2$。当 $d_k = 64$ 时，点积值的量级可达 $\pm 8\sigma$，导致 softmax 输入值差异巨大：

- 最大值对应的 $e^x$ 占据绝大部分概率（接近 1）
- 其余位置概率趋近于 0
- **梯度近乎为零**，反向传播无法有效更新参数

**除以 $\sqrt{d_k}$** 将方差归一化为 $\sigma^2$，使 softmax 输入保持在合理范围，梯度稳定流动。

---

## 因果掩码（Causal Mask）原理

自回归生成（如 GPT）要求**当前位置不能看到未来信息**，否则模型直接"偷看"答案，无需学习预测。

### 掩码实现

构造掩码矩阵 $M \in \mathbb{R}^{n \times n}$，上三角为 $-\infty$，下三角（含对角线）为 0：

$$M = \begin{pmatrix} 0 & -\infty & -\infty & \cdots \\ 0 & 0 & -\infty & \cdots \\ 0 & 0 & 0 & \cdots \\ \vdots & \vdots & \vdots & \ddots \end{pmatrix}$$

$$\text{Attention} = \text{softmax}\left(\frac{QK^T}{\sqrt{d_k}} + M\right) V$$

$-\infty$ 经 softmax 后变为 0，未来位置的注意力权重被完全屏蔽。

```
注意力矩阵（掩码前）        因果掩码后
  t1  t2  t3  t4           t1  t2  t3  t4
t1 [.3  .2  .3  .2]      t1 [.3   0   0   0]
t2 [.1  .4  .2  .3]  →   t2 [.1  .4   0   0]
t3 [.2  .1  .3  .4]      t3 [.2  .1  .3   0]
t4 [.1  .2  .3  .4]      t4 [.1  .2  .3  .4]
```

---

## 与交叉注意力的对比

| | Self-Attention | Cross-Attention |
|:--|:--|:--|
| Q 来源 | 自身序列 $X$ | 目标序列 $Y$ |
| K 来源 | 自身序列 $X$ | 源序列 $X$ |
| V 来源 | 自身序列 $X$ | 源序列 $X$ |
| 核心作用 | 序列内部全局交互 | 跨序列信息融合 |
| 典型位置 | Encoder / Decoder 前 | Decoder 中（融合 Encoder 输出） |

---

## 计算复杂度分析

- **时间复杂度**：$O(n^2 \cdot d)$，其中 $n$ 为序列长度，$d$ 为维度
  - $QK^T$：$O(n^2 \cdot d_k)$
  - softmax：$O(n^2)$
  - $AV$：$O(n^2 \cdot d_v)$
- **空间复杂度**：$O(n^2)$，需存储 $n \times n$ 注意力矩阵

这是 Transformer 的核心瓶颈——长序列时 $n^2$ 增长极快，催生了 FlashAttention、稀疏注意力等优化。

---

## 典型应用

| 模型 | 注意力类型 | 掩码 | 特点 |
|:-----|:-----------|:-----|:-----|
| **GPT** | Self-Attention | 因果掩码 | 自回归生成，逐 token 预测 |
| **BERT** | Self-Attention | 无掩码 | 双向编码，MLM 预训练 |
| **ViT** | Self-Attention | 无掩码 | 图像切成 patch 作为序列 |

---

## 优化方向

| 方法 | 思路 | 复杂度 |
|:-----|:-----|:-------|
| FlashAttention | 分块计算避免 materialize 注意力矩阵 | $O(n^2 \cdot d)$（常数优化） |
| 稀疏注意力 | 每个位置只关注局部窗口 + 少量全局位置 | $O(n \cdot w \cdot d)$ |
| 线性注意力 | 用核函数近似 softmax，避免 n² | $O(n \cdot d^2)$ |
| MQA / GQA | 多个头共享 K/V，减少 KV Cache | 推理 $O(n \cdot d / g)$ |

> AI生成