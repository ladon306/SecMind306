---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '31471659-5e23-4274-ac63-bc4481e26f29'
  PropagateID: '31471659-5e23-4274-ac63-bc4481e26f29'
  ReservedCode1: 'a6ee19ec-5add-43ef-b846-6631e5ed8d0a'
  ReservedCode2: 'a6ee19ec-5add-43ef-b846-6631e5ed8d0a'
---

# Transformer 完整架构 — 原理说明

## 整体架构

Transformer 由 Encoder 和 Decoder 两部分组成，原始论文用于机器翻译（Seq2Seq）。

```
                    ┌─────────────────────────────────────────┐
                    │              Decoder                     │
  目标序列 ──→      │  Masked Self-Attn → Cross-Attn → FFN    │ × N
  (shifted right)  │  + 残差连接 + LayerNorm                  │
                    └──────────────┬──────────────────────────┘
                                   │
                    ┌──────────────┴──────────────────────────┐
                    │              Encoder                     │
  源序列 ──→        │  Self-Attention → FFN                    │ × N
                    │  + 残差连接 + LayerNorm                  │
                    └─────────────────────────────────────────┘
                                   │
                               Linear → Softmax → 输出概率
```

---

## 位置编码（Positional Encoding）

Transformer 不含任何递归/卷积结构，**本身对位置无感知**，必须显式注入位置信息。

### 正弦/余弦编码

$$PE_{(pos, 2i)} = \sin\left(\frac{pos}{10000^{2i/d_{\text{model}}}}\right)$$

$$PE_{(pos, 2i+1)} = \cos\left(\frac{pos}{10000^{2i/d_{\text{model}}}}\right)$$

- $pos$：位置索引，$i$：维度索引
- 不同维度对应不同频率的正弦波，从 $2\pi$ 到 $2\pi \times 10000$
- **外推性**：对于固定偏移 $k$，$PE(pos+k)$ 可表示为 $PE(pos)$ 的线性变换（利用三角函数加法公式），使模型能泛化到训练时未见过的序列长度

### 为什么需要位置编码

```
无位置编码:  "猫 吃 鱼" → attention 认为 "吃 鱼 猫" 与之不可区分
有位置编码:  每个位置叠加不同正弦波 → 模型可区分 "猫在位置1" vs "猫在位置3"
```

---

## Encoder Layer

每个 Encoder 层包含两个子层：

```
输入 x
  │
  ▼
Multi-Head Self-Attention ──→ 残差 + LayerNorm ──→ x₁
  │
  ▼
Feed-Forward Network (FFN) ──→ 残差 + LayerNorm ──→ 输出
```

$$x_1 = \text{LayerNorm}(x + \text{MultiHead}(x, x, x))$$

$$x_2 = \text{LayerNorm}(x_1 + \text{FFN}(x_1))$$

---

## Decoder Layer

每个 Decoder 层包含三个子层：

```
输入 y
  │
  ▼
Masked Multi-Head Self-Attention ──→ 残差 + LayerNorm ──→ y₁
  │
  ▼
Multi-Head Cross-Attention(Q=y₁, K/V=encoder_out) ──→ 残差 + LayerNorm ──→ y₂
  │
  ▼
FFN ──→ 残差 + LayerNorm ──→ 输出
```

- **Masked Self-Attention**：因果掩码，生成位置 $t$ 只能看到 $\leq t$ 的位置
- **Cross-Attention**：Q 来自 Decoder，K/V 来自 Encoder 输出

---

## Pre-LN vs Post-LN

原始 Transformer 使用 **Post-LN**（先子层后归一化），但训练不稳定，需要 warmup。

| 方式 | 公式 | 特点 |
|:-----|:-----|:-----|
| **Post-LN**（原论文） | $\text{LN}(x + \text{SubLayer}(x))$ | 需 warmup，深层梯度爆炸风险 |
| **Pre-LN**（主流） | $x + \text{SubLayer}(\text{LN}(x))$ | 训练更稳定，无需 warmup |

**实践**：GPT-2/3、BERT、LLaMA 等现代模型均采用 Pre-LN。

---

## FFN 的瓶颈结构

$$\text{FFN}(x) = \max(0, xW_1 + b_1) W_2 + b_2$$

- 第一层：$d_{\text{model}} \to 4 \times d_{\text{model}}$（扩展 4 倍）
- 激活函数：ReLU（原论文）/ GELU（GPT/BERT）/ SwiGLU（LLaMA）
- 第二层：$4 \times d_{\text{model}} \to d_{\text{model}}$（压缩回原维度）

**4 倍扩展的直觉**：高维中间表示提供更强的非线性变换能力，类似 SVM 的核技巧——在高维空间线性可分，投影回低维后即为非线性决策边界。

---

## Xavier 初始化

$$W \sim \mathcal{U}\left[-\frac{\sqrt{6}}{\sqrt{n_{\text{in}} + n_{\text{out}}}}, \; \frac{\sqrt{6}}{\sqrt{n_{\text{in}} + n_{\text{out}}}}\right]$$

保证每一层输出的方差与输入方差一致，避免深层网络中信号逐层放大或衰减。

---

## 计算复杂度对比

| 模型 | 序列操作复杂度 | 最大路径长度 | 并行度 |
|:-----|:--------------|:------------|:-------|
| **Self-Attention** | $O(n^2 \cdot d)$ | $O(1)$ | ★ 完全并行 |
| **RNN** | $O(n \cdot d^2)$ | $O(n)$ | ✗ 顺序 |
| **CNN (k-size)** | $O(k \cdot n \cdot d^2)$ | $O(n/k)$ | ★ 并行 |

- Attention 的 $O(1)$ 最大路径长度意味着**任意两个位置直接交互**，无信息衰减
- RNN 的 $O(n)$ 路径长度导致长距离信息传递困难
- Attention 的代价是 $O(n^2)$ 内存，序列越长瓶颈越大

---

## Transformer 变体

| 变体 | 结构 | 预训练目标 | 代表模型 |
|:-----|:-----|:-----------|:---------|
| **Encoder-only** | 仅 Encoder | MLM（掩码语言模型） | BERT、RoBERTa、ALBERT |
| **Decoder-only** | 仅 Decoder | CLM（因果语言模型） | GPT 系列、LLaMA、Mistral |
| **Encoder-Decoder** | Encoder + Decoder | 去噪/span掩码 | T5、BART、mBART |

**趋势**：大语言模型（LLM）几乎统一采用 Decoder-only 架构，因为：
- 自回归生成天然适配因果掩码
- 单向注意力简化实现，KV Cache 推理高效
- 丰富的无标注文本可直接用于 CLM 预训练

---

## 优化实践

| 技术 | 作用 | 适用阶段 |
|:-----|:-----|:---------|
| FlashAttention | 分块计算，减少 HBM 读写 | 训练+推理 |
| KV Cache | 缓存已计算的 K/V，避免重复计算 | 推理 |
| 混合精度（FP16/BF16） | 减少显存占用和计算时间 | 训练+推理 |
| Gradient Checkpointing | 用计算换显存，减少激活值存储 | 训练 |
| ALiBi / RoPE | 替代正弦位置编码，更好的长度外推 | 训练+推理 |

> AI生成