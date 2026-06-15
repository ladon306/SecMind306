---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '9fa85133-0bdd-4211-8562-ab7dfa453d8c'
  PropagateID: '9fa85133-0bdd-4211-8562-ab7dfa453d8c'
  ReservedCode1: '79d32d63-58e1-4612-be5e-ec2c42bef566'
  ReservedCode2: '79d32d63-58e1-4612-be5e-ec2c42bef566'
---

# Cross Attention 交叉注意力 — 原理说明

## 核心概念

交叉注意力（Cross Attention）是注意力机制的一种变体，**查询（Q）和键值（K/V）分别来自两个不同的序列**，用于让一个序列"关注"另一个序列的信息。

与自注意力的对比：

| | Self-Attention | Cross-Attention |
|:--|:--|:--|
| Q 来源 | 自身序列 | 目标序列 |
| K 来源 | 自身序列 | 源序列 |
| V 来源 | 自身序列 | 源序列 |
| 核心作用 | 序列内部关联 | 跨序列信息交互 |

---

## 数学公式

### 缩放点积注意力

$$\text{Attention}(Q, K, V) = \text{softmax}\left(\frac{QK^T}{\sqrt{d_k}}\right) V$$

- $Q \in \mathbb{R}^{n \times d_k}$：查询矩阵（来自目标序列）
- $K \in \mathbb{R}^{m \times d_k}$：键矩阵（来自源序列）
- $V \in \mathbb{R}^{m \times d_v}$：值矩阵（来自源序列）
- $d_k$：键/查询维度，除以 $\sqrt{d_k}$ 防止点积过大导致 softmax 梯度消失

### 多头交叉注意力

$$\text{MultiHead}(Q, K, V) = \text{Concat}(\text{head}_1, ..., \text{head}_h)W^O$$

$$\text{head}_i = \text{Attention}(QW_i^Q, KW_i^K, VW_i^V)$$

将 Q/K/V 投影到 $h$ 个子空间独立计算注意力，拼接后通过线性层融合。每个头可以关注不同类型的关联模式。

---

## 计算流程

```
目标序列 target ──→ W_Q ──→ Q ──┐
                                 ├─→ QK^T/√d_k ──→ softmax ──→ × V ──→ 拼接多头 ──→ FC ──→ 残差+LN ──→ 输出
源序列  source ──→ W_K ──→ K ──┘         ↑
                └─→ W_V ──→ V           mask
```

**关键步骤：**

1. **线性投影**：target 经 $W_Q$ 生成 Q，source 经 $W_K, W_V$ 生成 K/V
2. **注意力计算**：Q 与 K 做点积，缩放后 softmax 得到注意力权重
3. **加权求和**：权重与 V 相乘，得到源序列的加权表示
4. **残差连接**：输出与原始 target 相加，缓解梯度消失
5. **LayerNorm**：归一化稳定训练

---

## 典型应用场景

### 1. Transformer Decoder

解码器中每个 block 先做一次自注意力（关注已生成的 token），再做一次交叉注意力（Q 来自解码器，K/V 来自编码器输出），从而获取源句信息。

```
解码器输入 ──→ Self-Attention ──→ Cross-Attention ──→ FFN ──→ 输出
                                    ↑ K/V
                               编码器输出
```

### 2. 图像描述生成（Image Captioning）

- Q 来自已生成的文本序列
- K/V 来自图像特征（CNN/ViT 提取）
- 文本通过交叉注意力"看"图像的不同区域来生成描述

### 3. Stable Diffusion（文本条件生成）

- Q 来自 U-Net 中间特征
- K/V 来自 CLIP 文本编码器输出
- 图像特征通过交叉注意力对齐文本语义

### 4. 机器翻译

- 编码器处理源语言 → 输出 K/V
- 解码器生成目标语言 → 输出 Q
- 目标语言每个位置通过交叉注意力"参考"源语言对应部分

---

## 代码实现说明

本实现包含三个核心类：

| 类名 | 说明 |
|:-----|:-----|
| `ScaledDotProductAttention` | 底层缩放点积注意力，支持 mask |
| `CrossAttention` | 单头交叉注意力，含残差连接 + LayerNorm |
| `MultiHeadCrossAttention` | 多头交叉注意力，实际使用的主力 |

**使用示例：**

```python
import torch
from cross_attention import MultiHeadCrossAttention

# 模拟: 编码器输出 (源) + 解码器输入 (目标)
source = torch.randn(2, 20, 64)  # batch=2, len=20, d=64
target = torch.randn(2, 10, 64)  # batch=2, len=10, d=64

model = MultiHeadCrossAttention(n_heads=8, d_model=64, dropout=0.1)
output, attn_weights = model(target, source)

# output: (2, 10, 64) — 目标序列融合了源序列信息
# attn_weights: (2, 8, 10, 20) — 每个头中目标对源的注意力分布
```

---

## 与其他注意力机制的关系

```
注意力机制
├── 自注意力 (Self-Attention)    — Q=K=V，序列内部交互
├── 交叉注意力 (Cross-Attention) — Q≠K/V，跨序列交互
├── 全局注意力 (Global Attention) — 所有位置互相可见
├── 局部注意力 (Local Attention)  — 只看滑动窗口内的位置
├── 稀疏注意力 (Sparse Attention) — 只看部分关键位置
└── 线性注意力 (Linear Attention) — O(n) 复杂度近似
```

交叉注意力是"从 A 序列查询 B 序列"的通用范式，核心思想可以推广到任何需要跨模态或跨序列信息交互的场景。

> AI生成