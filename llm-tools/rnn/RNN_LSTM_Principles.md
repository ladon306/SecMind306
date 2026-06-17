---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '9c8545d8-0947-49fe-9a86-08434a067a37'
  PropagateID: '9c8545d8-0947-49fe-9a86-08434a067a37'
  ReservedCode1: 'a07e1bcb-ab5d-4f6e-9472-a6953ebd127a'
  ReservedCode2: 'a07e1bcb-ab5d-4f6e-9472-a6953ebd127a'
---

# RNN & LSTM 原理详解

## 概述

循环神经网络（RNN）是处理序列数据的经典架构，通过隐藏状态在时间步之间传递信息。然而 Vanilla RNN 存在严重的梯度消失/爆炸问题，LSTM 通过门控机制有效缓解了这一缺陷。

---

## 1. Vanilla RNN

### 前向传播

$$h_t = \tanh(W_{xh} \cdot x_t + W_{hh} \cdot h_{t-1} + b_h)$$

$$y_t = W_{hy} \cdot h_t + b_y$$

- $h_t \in \mathbb{R}^{d_h}$：时刻 $t$ 的隐藏状态
- $W_{xh} \in \mathbb{R}^{d_h \times d_x}$：输入权重
- $W_{hh} \in \mathbb{R}^{d_h \times d_h}$：循环权重
- $\tanh$：激活函数，将隐藏状态限制在 $[-1, 1]$

### 计算流程

```
x₁    x₂    x₃    ...   xₜ
↓     ↓     ↓           ↓
[×Wxh] [×Wxh] [×Wxh]     [×Wxh]
↓     ↓     ↓           ↓
h₀→[+]→h₁→[+]→h₂→[+]→...→hₜ
      ↓     ↓           ↓
     tanh  tanh        tanh
      ↓     ↓           ↓
     y₁    y₂          yₜ
```

---

## 2. BPTT（Backpropagation Through Time）

BPTT 将 RNN 按时间步展开为等价的前馈网络，再应用标准反向传播。

$$\frac{\partial \mathcal{L}}{\partial W_{hh}} = \sum_{t=1}^{T} \frac{\partial \mathcal{L}}{\partial h_t} \cdot \frac{\partial h_t}{\partial W_{hh}}$$

其中：

$$\frac{\partial \mathcal{L}}{\partial h_t} = \frac{\partial \mathcal{L}}{\partial y_t} \cdot \frac{\partial y_t}{\partial h_t} + \frac{\partial \mathcal{L}}{\partial h_{t+1}} \cdot \frac{\partial h_{t+1}}{\partial h_t}$$

关键项：$\frac{\partial h_{t+1}}{\partial h_t} = W_{hh}^T \cdot \text{diag}(1 - h_{t+1}^2)$

---

## 3. 梯度消失/爆炸问题

沿时间步 $k$ 回传时，梯度包含 $k$ 个雅可比矩阵连乘：

$$\frac{\partial h_t}{\partial h_{t-k}} = \prod_{i=t-k+1}^{t} \frac{\partial h_i}{\partial h_{i-1}} = \prod_{i=t-k+1}^{t} W_{hh}^T \cdot \text{diag}(1 - h_i^2)$$

取范数的上界：

$$\left\|\frac{\partial h_t}{\partial h_{t-k}}\right\| \leq \left(\|W_{hh}\| \cdot \gamma\right)^k, \quad \gamma = \max_i \|\text{diag}(1-h_i^2)\|$$

- **$\|W_{hh}\| \cdot \gamma < 1$**：梯度指数衰减 → **梯度消失**，远距离信息无法传递
- **$\|W_{hh}\| \cdot \gamma > 1$**：梯度指数增长 → **梯度爆炸**，训练不稳定
- $\tanh$ 的导数 $\leq 1$，更易消失；$\sigma$ 的导数 $\leq 0.25$，消失更严重

**结论**：Vanilla RNN 的有效记忆跨度约 10-20 步，无法学习长距离依赖。

---

## 4. LSTM 四大门控

LSTM 引入**细胞状态 $c_t$** 和三个门控，通过加性更新替代乘性更新，从根本上缓解梯度消失。

### 遗忘门（Forget Gate）

$$f_t = \sigma(W_f \cdot [h_{t-1}, x_t] + b_f)$$

决定上一时刻细胞状态 $c_{t-1}$ 中哪些信息需要丢弃。$f_t \in (0,1)^{d_h}$，0 = 完全遗忘，1 = 完全保留。

### 输入门（Input Gate）

$$i_t = \sigma(W_i \cdot [h_{t-1}, x_t] + b_i)$$

决定当前候选信息 $\tilde{g}_t$ 中哪些需要写入细胞状态。

### 候选记忆（Candidate）

$$\tilde{g}_t = \tanh(W_g \cdot [h_{t-1}, x_t] + b_g)$$

当前输入产生的新候选信息，范围 $[-1, 1]$。

### 输出门（Output Gate）

$$o_t = \sigma(W_o \cdot [h_{t-1}, x_t] + b_o)$$

决定细胞状态中哪些信息输出为隐藏状态。

---

## 5. 细胞状态的加性更新

$$c_t = f_t \odot c_{t-1} + i_t \odot \tilde{g}_t$$

**这是 LSTM 的核心设计**：

| | Vanilla RNN | LSTM |
|:--|:--|:--|
| 状态更新 | $h_t = \tanh(W \cdot h_{t-1} + \cdots)$ | $c_t = f_t \odot c_{t-1} + i_t \odot \tilde{g}_t$ |
| 更新方式 | **乘性**（反复乘 $W_{hh}$） | **加性**（加新信息，不反复乘权重） |
| 梯度回传 | $\prod W_{hh}$（指数衰减/爆炸） | $f_t$ 逐点乘（可学习接近 1） |

隐藏状态输出：

$$h_t = o_t \odot \tanh(c_t)$$

---

## 6. 遗忘门的作用：学习选择性遗忘

遗忘门 $f_t$ 是 LSTM 相比早期 LSTM（无遗忘门，固定 $f_t=1$）的关键改进：

- **$f_t \approx 1$**：细胞状态完全保留 → 长距离信息传递
- **$f_t \approx 0$**：细胞状态清空 → 丢弃无关旧信息
- **$f_t$ 介于之间**：选择性保留 → 灵活控制记忆

实验表明：**偏置 $b_f$ 初始化为正值**（如 +1）使 $f_t$ 初始接近 1（偏向保留），有利于长序列学习。

---

## 7. 完整门控公式汇总

| 门控 | 公式 | 范围 | 作用 |
|:-----|:-----|:-----|:-----|
| 遗忘门 | $f_t = \sigma(W_f [h_{t-1}, x_t] + b_f)$ | $(0,1)^{d_h}$ | 控制旧记忆保留 |
| 输入门 | $i_t = \sigma(W_i [h_{t-1}, x_t] + b_i)$ | $(0,1)^{d_h}$ | 控制新信息写入 |
| 候选 | $\tilde{g}_t = \tanh(W_g [h_{t-1}, x_t] + b_g)$ | $(-1,1)^{d_h}$ | 生成新候选值 |
| 细胞更新 | $c_t = f_t \odot c_{t-1} + i_t \odot \tilde{g}_t$ | $\mathbb{R}^{d_h}$ | 加性更新记忆 |
| 输出门 | $o_t = \sigma(W_o [h_{t-1}, x_t] + b_o)$ | $(0,1)^{d_h}$ | 控制记忆输出 |
| 隐藏状态 | $h_t = o_t \odot \tanh(c_t)$ | $(-1,1)^{d_h}$ | 当前时刻输出 |

---

## 8. 双向 RNN/LSTM

同时从左到右和右到右处理序列，拼接双向隐藏状态：

$$\overrightarrow{h_t} = \text{LSTM}_{\text{forward}}(x_t, \overrightarrow{h_{t-1}})$$

$$\overleftarrow{h_t} = \text{LSTM}_{\text{backward}}(x_t, \overleftarrow{h_{t+1}})$$

$$h_t = [\overrightarrow{h_t}; \; \overleftarrow{h_t}]$$

- 适用于**编码**任务（NER、情感分类），每个位置能看到完整上下文
- **不适用于自回归生成**（解码时未来信息不可见）

---

## 9. 多层堆叠

将多层 LSTM 串联，上层以下层输出为输入：

```
x₁  x₂  x₃  ...  xₜ
↓   ↓   ↓        ↓
LSTM Layer 1 → h¹₁  h¹₂  h¹₃  ...  h¹ₜ
               ↓    ↓    ↓         ↓
LSTM Layer 2 → h²₁  h²₂  h²₃  ...  h²ₜ
               ↓    ↓    ↓         ↓
LSTM Layer 3 → h³₁  h³₂  h³₃  ...  h³ₜ
```

通常 2-3 层即可，层数过多收益递减且训练困难。

---

## 10. GRU 简化版对比

GRU（Gated Recurrent Unit）将遗忘门和输入门合并为更新门，减少参数量：

| | LSTM | GRU |
|:--|:--|:--|
| 门控数量 | 3（遗忘+输入+输出） | 2（重置+更新） |
| 细胞状态 | 有 $c_t$ 和 $h_t$ 分离 | 无，仅 $h_t$ |
| 参数量 | $4d(d_x+d_h)+4d$ | $3d(d_x+d_h)+3d$ |
| 性能 | 略优（长序列） | 相近（短序列更快） |

GRU 公式：

$$z_t = \sigma(W_z [h_{t-1}, x_t]), \quad r_t = \sigma(W_r [h_{t-1}, x_t])$$

$$\tilde{h}_t = \tanh(W [r_t \odot h_{t-1}, x_t])$$

$$h_t = (1 - z_t) \odot h_{t-1} + z_t \odot \tilde{h}_t$$

---

## 实践建议

| 建议 | 说明 |
|:-----|:-----|
| **梯度裁剪** | `torch.nn.utils.clip_grad_norm_(parameters, max_norm=5.0)`，防止梯度爆炸 |
| **序列长度限制** | 截断过长的 BPTT 展开步数（通常 100-300），避免梯度链过长 |
| **PyTorch 内置实现** | `nn.LSTM` / `nn.GRU`，已优化 CUDA kernel，远快于手写循环 |
| **packed sequence** | 变长序列用 `pack_padded_sequence` 避免无效计算 |
| **偏置初始化** | 遗忘门偏置 $b_f$ 初始化为 +1（PyTorch 默认 0，需手动设置） |

> AI生成