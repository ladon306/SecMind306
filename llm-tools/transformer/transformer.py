"""
Transformer 完整架构实现 — "Attention Is All You Need" (Vaswani et al., 2017)
=============================================================================

架构总览:
  ┌─────────────┐     ┌─────────────┐
  │  Encoder     │     │  Decoder     │
  │  ┌─────────┐ │     │ ┌─────────┐ │
  │  │Embed+PE │ │     │ │Embed+PE │ │
  │  └────┬────┘ │     │ └────┬────┘ │
  │  ┌────▼────┐ │     │ ┌────▼────┐ │
  │  │EncLayer │ │     │ │MaskedSA │◄───── tgt_mask (causal)
  │  │  SelfAttn│ │     │ └────┬────┘ │
  │  │  + FFN  │ │     │ ┌────▼────┐ │
  │  │  × N    │ │────►│ │CrossAttn│◄───── encoder输出
  │  └─────────┘ │     │ └────┬────┘ │
  └─────────────┘     │ ┌────▼────┐ │
                       │ │  FFN    │ │
                       │ └────┬────┘ │
                       │  × N  │     │
                       │ ┌────▼────┐ │
                       │ │ Linear  │ │
                       │ │+ Softmax│ │
                       │ └─────────┘ │
                       └─────────────┘

关键设计:
  - 残差连接: 缓解梯度消失, ∂(x+Sublayer(x))/∂x ≥ 1 保证梯度流
  - Pre-LN vs Post-LN: 原论文 Post-LN, Pre-LN 训练更稳定 (梯度直通)
  - 正弦位置编码: 无需学习, 可外推到更长序列, 具有相对位置线性性质
  - 缩放因数 1/√d_k: 防止点积过大导致 softmax 饱和

用法:
  python transformer.py              # 运行示例
  python transformer.py --benchmark  # 性能基准测试
"""

import argparse
import math
import time

import torch
import torch.nn as nn
import torch.nn.functional as F


# ──────────────────────────────────────────────
# 1. 位置编码 (Positional Encoding)
# ──────────────────────────────────────────────
class PositionalEncoding(nn.Module):
    """
    正弦位置编码

    PE(pos, 2i)   = sin(pos / 10000^(2i/d_model))
    PE(pos, 2i+1) = cos(pos / 10000^(2i/d_model))

    PE(pos+k) 可表示为 PE(pos) 的线性变换 (旋转矩阵), 天然具有相对位置关系

    Args:
        d_model: 模型维度 (偶数)
        max_len: 预计算最大序列长度
        dropout: dropout 概率
    """

    def __init__(self, d_model, max_len=5000, dropout=0.1):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)

        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2, dtype=torch.float)
            * -(math.log(10000.0) / d_model)
        )
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)  # (1, max_len, d_model)
        self.register_buffer("pe", pe)

    def forward(self, x):
        """x: (batch, seq_len, d_model) → 加入位置编码"""
        x = x + self.pe[:, : x.size(1)]
        return self.dropout(x)


# ──────────────────────────────────────────────
# 2. 多头注意力 (Multi-Head Attention)
# ──────────────────────────────────────────────
class MultiHeadAttention(nn.Module):
    """
    多头缩放点积注意力

    MultiHead(Q,K,V) = Concat(head_1,...,head_h)·W_O
    head_i = softmax(Q_i·K_i^T / √d_k)·V_i

    Args:
        n_heads: 注意力头数
        d_model: 模型维度 (需被 n_heads 整除)
        dropout: dropout 概率
    """

    def __init__(self, n_heads, d_model, dropout=0.1):
        super().__init__()
        assert d_model % n_heads == 0, f"d_model({d_model}) 必须能被 n_heads({n_heads}) 整除"

        self.n_heads = n_heads
        self.d_k = d_model // n_heads

        self.w_q = nn.Linear(d_model, d_model, bias=False)
        self.w_k = nn.Linear(d_model, d_model, bias=False)
        self.w_v = nn.Linear(d_model, d_model, bias=False)
        self.w_o = nn.Linear(d_model, d_model, bias=False)

        self.dropout = nn.Dropout(dropout)

    def forward(self, query, key, value, mask=None):
        """
        Args:
            query: (batch, len_q, d_model)
            key:   (batch, len_k, d_model)
            value: (batch, len_v, d_model)
            mask:  (batch,1,len_q,len_k) 或可广播, 1=保留 0=遮蔽
        Returns:
            output: (batch, len_q, d_model), attn: (batch, n_heads, len_q, len_k)
        """
        batch_size = query.size(0)

        q = self.w_q(query).view(batch_size, -1, self.n_heads, self.d_k).transpose(1, 2)
        k = self.w_k(key).view(batch_size, -1, self.n_heads, self.d_k).transpose(1, 2)
        v = self.w_v(value).view(batch_size, -1, self.n_heads, self.d_k).transpose(1, 2)

        attn = torch.matmul(q, k.transpose(-2, -1)) / math.sqrt(self.d_k)

        if mask is not None:
            attn = attn.masked_fill(mask == 0, float("-inf"))

        attn = self.dropout(F.softmax(attn, dim=-1))
        out = torch.matmul(attn, v)

        out = out.transpose(1, 2).contiguous().view(batch_size, -1, self.n_heads * self.d_k)
        out = self.w_o(out)

        return out, attn


# ──────────────────────────────────────────────
# 3. 前馈网络 (Position-wise Feed-Forward)
# ──────────────────────────────────────────────
class PositionwiseFeedForward(nn.Module):
    """
    位置独立前馈网络

    FFN(x) = max(0, x·W_1+b_1)·W_2+b_2   (原论文 ReLU)
    FFN(x) = GELU(x·W_1+b_1)·W_2+b_2      (GPT/BERT 风格)

    d_ff 通常为 d_model 的 4 倍, 形成 "瓶颈" 结构

    Args:
        d_model:    模型维度
        d_ff:       内部维度 (默认 4×d_model)
        dropout:    dropout 概率
        activation: "relu" 或 "gelu"
    """

    def __init__(self, d_model, d_ff=None, dropout=0.1, activation="relu"):
        super().__init__()
        d_ff = d_ff or 4 * d_model

        self.w_1 = nn.Linear(d_model, d_ff)
        self.w_2 = nn.Linear(d_ff, d_model)
        self.dropout = nn.Dropout(dropout)
        self.activation = F.gelu if activation == "gelu" else F.relu

    def forward(self, x):
        """x: (batch, seq_len, d_model)"""
        return self.dropout(self.w_2(self.activation(self.w_1(x))))


# ──────────────────────────────────────────────
# 4. 层归一化 (Layer Normalization)
# ──────────────────────────────────────────────
class LayerNorm(nn.Module):
    """
    层归一化: LN(x) = γ·(x-μ)/√(σ²+ε) + β, 沿最后一维计算

    与 BatchNorm 的区别: LN 沿特征维归一化, 每样本独立, 适合变长序列

    Args:
        features: 归一化维度 (d_model)
        eps:      防止除零的小常数
    """

    def __init__(self, features, eps=1e-6):
        super().__init__()
        self.gamma = nn.Parameter(torch.ones(features))
        self.beta = nn.Parameter(torch.zeros(features))
        self.eps = eps

    def forward(self, x):
        mean = x.mean(-1, keepdim=True)
        std = x.std(-1, keepdim=True, unbiased=False)
        return self.gamma * (x - mean) / (std + self.eps) + self.beta


# ──────────────────────────────────────────────
# 5. 编码器层 (Encoder Layer)
# ──────────────────────────────────────────────
class EncoderLayer(nn.Module):
    """
    单个编码器层

    Post-LN (原论文): output = LN(x + Sublayer(x))
    Pre-LN (更稳定):  output = x + Sublayer(LN(x))

    残差连接: 梯度沿 x 直通回传, ∂(x+Sublayer(x))/∂x ≥ 1, 缓解梯度消失

    Args:
        d_model:    模型维度
        n_heads:    注意力头数
        d_ff:       FFN 内部维度
        dropout:    dropout 概率
        norm_type:  "post" 或 "pre"
        activation: FFN 激活函数
    """

    def __init__(self, d_model, n_heads, d_ff=None, dropout=0.1,
                 norm_type="post", activation="relu"):
        super().__init__()
        d_ff = d_ff or 4 * d_model

        self.self_attn = MultiHeadAttention(n_heads, d_model, dropout)
        self.ffn = PositionwiseFeedForward(d_model, d_ff, dropout, activation)

        self.norm1 = LayerNorm(d_model)
        self.norm2 = LayerNorm(d_model)
        self.dropout1 = nn.Dropout(dropout)
        self.dropout2 = nn.Dropout(dropout)

        self.norm_type = norm_type

    def forward(self, x, src_mask=None):
        """Args: x=(batch,seq_len,d_model), src_mask=(batch,1,seq_len,seq_len)"""
        if self.norm_type == "pre":
            # Pre-LN: LN 先, Attention 后
            x2 = self.norm1(x)
            attn_out, attn = self.self_attn(x2, x2, x2, mask=src_mask)
            x = x + self.dropout1(attn_out)
            x2 = self.norm2(x)
            x = x + self.dropout2(self.ffn(x2))
        else:
            # Post-LN: Attention 先, LN 后 (原论文)
            attn_out, attn = self.self_attn(x, x, x, mask=src_mask)
            x = self.norm1(x + self.dropout1(attn_out))
            x = self.norm2(x + self.dropout2(self.ffn(x)))

        return x, attn


# ──────────────────────────────────────────────
# 6. 解码器层 (Decoder Layer)
# ──────────────────────────────────────────────
class DecoderLayer(nn.Module):
    """
    单个解码器层: Masked Self-Attn → Cross-Attn → FFN

    Causal mask: mask[i][j]=0 if j>i, 确保位置 i 只依赖 ≤i 的信息

    Args:
        d_model, n_heads, d_ff, dropout, norm_type, activation: 同 EncoderLayer
    """

    def __init__(self, d_model, n_heads, d_ff=None, dropout=0.1,
                 norm_type="post", activation="relu"):
        super().__init__()
        d_ff = d_ff or 4 * d_model

        self.masked_self_attn = MultiHeadAttention(n_heads, d_model, dropout)
        self.cross_attn = MultiHeadAttention(n_heads, d_model, dropout)
        self.ffn = PositionwiseFeedForward(d_model, d_ff, dropout, activation)

        self.norm1 = LayerNorm(d_model)
        self.norm2 = LayerNorm(d_model)
        self.norm3 = LayerNorm(d_model)
        self.dropout1 = nn.Dropout(dropout)
        self.dropout2 = nn.Dropout(dropout)
        self.dropout3 = nn.Dropout(dropout)

        self.norm_type = norm_type

    def forward(self, x, memory, tgt_mask=None, memory_mask=None):
        """
        Args: x=(batch,tgt_len,d_model), memory=(batch,src_len,d_model)
        Returns: output, self_attn, cross_attn
        """
        if self.norm_type == "pre":
            # Pre-LN
            x2 = self.norm1(x)
            self_attn_out, self_attn = self.masked_self_attn(x2, x2, x2, mask=tgt_mask)
            x = x + self.dropout1(self_attn_out)
            x2 = self.norm2(x)
            cross_out, cross_attn = self.cross_attn(x2, memory, memory, mask=memory_mask)
            x = x + self.dropout2(cross_out)
            x2 = self.norm3(x)
            x = x + self.dropout3(self.ffn(x2))
        else:
            # Post-LN (原论文)
            self_attn_out, self_attn = self.masked_self_attn(x, x, x, mask=tgt_mask)
            x = self.norm1(x + self.dropout1(self_attn_out))
            cross_out, cross_attn = self.cross_attn(x, memory, memory, mask=memory_mask)
            x = self.norm2(x + self.dropout2(cross_out))
            x = self.norm3(x + self.dropout3(self.ffn(x)))

        return x, self_attn, cross_attn


# ──────────────────────────────────────────────
# 7. 编码器 (Encoder)
# ──────────────────────────────────────────────
class Encoder(nn.Module):
    """N 层 EncoderLayer 堆叠, Pre-LN 时末尾额外加 LN"""

    def __init__(self, n_layers, d_model, n_heads, d_ff=None, dropout=0.1,
                 norm_type="post", activation="relu"):
        super().__init__()
        self.layers = nn.ModuleList([
            EncoderLayer(d_model, n_heads, d_ff, dropout, norm_type, activation)
            for _ in range(n_layers)
        ])
        self.norm = LayerNorm(d_model) if norm_type == "pre" else None

    def forward(self, x, src_mask=None):
        """Args: x=(batch,src_len,d_model)"""
        for layer in self.layers:
            x, _ = layer(x, src_mask)
        if self.norm is not None:
            x = self.norm(x)
        return x


# ──────────────────────────────────────────────
# 8. 解码器 (Decoder)
# ──────────────────────────────────────────────
class Decoder(nn.Module):
    """N 层 DecoderLayer 堆叠, Pre-LN 时末尾额外加 LN"""

    def __init__(self, n_layers, d_model, n_heads, d_ff=None, dropout=0.1,
                 norm_type="post", activation="relu"):
        super().__init__()
        self.layers = nn.ModuleList([
            DecoderLayer(d_model, n_heads, d_ff, dropout, norm_type, activation)
            for _ in range(n_layers)
        ])
        self.norm = LayerNorm(d_model) if norm_type == "pre" else None

    def forward(self, x, memory, tgt_mask=None, memory_mask=None):
        """Args: x=(batch,tgt_len,d_model), memory=(batch,src_len,d_model)"""
        for layer in self.layers:
            x, _, _ = layer(x, memory, tgt_mask, memory_mask)
        if self.norm is not None:
            x = self.norm(x)
        return x


# ──────────────────────────────────────────────
# 9. 完整 Transformer 模型
# ──────────────────────────────────────────────
class Transformer(nn.Module):
    """
    完整 Encoder-Decoder Transformer (Vaswani et al., 2017)

    核心超参: d_model=512, n_heads=8, d_ff=2048, N=6 (原论文)

    Args:
        src_vocab_size:  源语言词表大小
        tgt_vocab_size:  目标语言词表大小
        d_model:         模型维度
        n_heads:         注意力头数
        d_ff:            FFN 内部维度
        n_layers:        编/解码器层数
        max_len:         最大序列长度
        dropout:         dropout 概率
        norm_type:       "post" (原论文) 或 "pre" (更稳定)
        activation:      "relu" 或 "gelu"
        share_embedding: 共享编解码器嵌入
    """

    def __init__(self, src_vocab_size, tgt_vocab_size, d_model=512, n_heads=8,
                 d_ff=None, n_layers=6, max_len=5000, dropout=0.1,
                 norm_type="post", activation="relu", share_embedding=False):
        super().__init__()

        self.d_model = d_model
        self.src_embed = nn.Embedding(src_vocab_size, d_model)
        self.tgt_embed = nn.Embedding(tgt_vocab_size, d_model) if not share_embedding else self.src_embed

        self.src_pe = PositionalEncoding(d_model, max_len, dropout)
        self.tgt_pe = PositionalEncoding(d_model, max_len, dropout)

        self.encoder = Encoder(n_layers, d_model, n_heads, d_ff, dropout, norm_type, activation)
        self.decoder = Decoder(n_layers, d_model, n_heads, d_ff, dropout, norm_type, activation)

        self.generator = nn.Linear(d_model, tgt_vocab_size)

        self._init_parameters()

    def _init_parameters(self):
        """Xavier 初始化 — 原论文使用, 适合注意力中的点积运算"""
        for p in self.parameters():
            if p.dim() > 1:
                nn.init.xavier_uniform_(p)

    @staticmethod
    def make_causal_mask(seq_len):
        """生成因果 mask (1,1,seq_len,seq_len), 1=保留 0=遮蔽"""
        return torch.tril(torch.ones(seq_len, seq_len)).unsqueeze(0).unsqueeze(0)

    @staticmethod
    def make_padding_mask(seq, pad_idx=0):
        """生成 padding mask (batch,1,1,seq_len), 1=保留 0=遮蔽"""
        return (seq != pad_idx).unsqueeze(1).unsqueeze(2).float()

    def forward(self, src, tgt, src_mask=None, tgt_mask=None, memory_mask=None):
        """
        Args:
            src:         (batch, src_len) token id
            tgt:         (batch, tgt_len) token id
            src_mask:    (batch,1,1,src_len) 或 (batch,1,src_len,src_len)
            tgt_mask:    (batch,1,tgt_len,tgt_len), None 则自动生成 causal mask
            memory_mask: (batch,1,tgt_len,src_len)
        Returns:
            logits: (batch, tgt_len, tgt_vocab_size)
        """
        tgt_len = tgt.size(1)
        if tgt_mask is None:
            tgt_mask = self.make_causal_mask(tgt_len).to(tgt.device)

        src_emb = self.src_pe(self.src_embed(src) * math.sqrt(self.d_model))
        tgt_emb = self.tgt_pe(self.tgt_embed(tgt) * math.sqrt(self.d_model))

        memory = self.encoder(src_emb, src_mask)
        dec_out = self.decoder(tgt_emb, memory, tgt_mask, memory_mask)
        logits = self.generator(dec_out)

        return logits

    def encode(self, src, src_mask=None):
        """仅编码, 可缓存用于自回归推理"""
        src_emb = self.src_pe(self.src_embed(src) * math.sqrt(self.d_model))
        return self.encoder(src_emb, src_mask)

    def decode(self, tgt, memory, tgt_mask=None, memory_mask=None):
        """仅解码, 配合 encode 使用"""
        tgt_len = tgt.size(1)
        if tgt_mask is None:
            tgt_mask = self.make_causal_mask(tgt_len).to(tgt.device)
        tgt_emb = self.tgt_pe(self.tgt_embed(tgt) * math.sqrt(self.d_model))
        return self.decoder(tgt_emb, memory, tgt_mask, memory_mask)


# ──────────────────────────────────────────────
# 工具函数
# ──────────────────────────────────────────────
def count_parameters(model):
    """统计可训练参数量"""
    return sum(p.numel() for p in model.parameters() if p.requires_grad)


# ──────────────────────────────────────────────
# 示例 & 测试
# ──────────────────────────────────────────────
def run_demo():
    """运行 Transformer 示例"""
    print("=" * 60)
    print("  Transformer 完整架构 示例")
    print("=" * 60)
    torch.manual_seed(42)

    # ── 1. 构建小型 Transformer ──
    print("\n[1] 构建 Transformer (d_model=128, n_heads=4, N=2)")
    model = Transformer(src_vocab_size=1000, tgt_vocab_size=1000,
                        d_model=128, n_heads=4, d_ff=512, n_layers=2)
    print(f"    参数量: {count_parameters(model):,}")

    # ── 2. Forward Pass ──
    print("\n[2] Forward Pass")
    src = torch.randint(1, 1000, (2, 10))
    tgt = torch.randint(1, 1000, (2, 8))
    model.eval()
    with torch.no_grad():
        logits = model(src, tgt)
    print(f"    src: {src.shape}, tgt: {tgt.shape}")
    print(f"    输出 logits: {logits.shape}")
    print(f"    预测 token:  {logits.argmax(dim=-1).shape}")

    # ── 3. Causal Mask 演示 ──
    print("\n[3] Causal Mask 演示")
    cm = Transformer.make_causal_mask(6)
    for row in cm[0, 0].int().tolist():
        print(f"      {row}")
    print("    位置 i 只能看到 ≤ i, 未来位置被遮蔽为 0")

    # 自回归生成
    print("\n    逐步解码 (自回归):")
    with torch.no_grad():
        memory = model.encode(src)
        generated = [torch.ones(2, 1, dtype=torch.long)]
        for _ in range(7):
            dec_in = torch.cat(generated, dim=1)
            dec_out = model.decode(dec_in, memory)
            next_tok = model.generator(dec_out[:, -1:, :]).argmax(dim=-1)
            generated.append(next_tok)
        print(f"    生成长度: {torch.cat(generated, dim=1).shape[1]} tokens")

    # ── 4. Pre-LN vs Post-LN ──
    print("\n[4] Pre-LN vs Post-LN")
    m_pre = Transformer(1000, 1000, d_model=128, n_heads=4, n_layers=2, norm_type="pre")
    m_post = Transformer(1000, 1000, d_model=128, n_heads=4, n_layers=2, norm_type="post")
    print(f"    Pre-LN:  {count_parameters(m_pre):,} params — LN在子层前, 梯度直通, 更稳定")
    print(f"    Post-LN: {count_parameters(m_post):,} params — LN在残差后, 原论文, 需warmup")

    # ── 5. 参数分布 ──
    print("\n[5] 模块参数分布")
    breakdown = {}
    for name, param in model.named_parameters():
        top = name.split(".")[0]
        breakdown[top] = breakdown.get(top, 0) + param.numel()
    total = sum(breakdown.values())
    for name, cnt in sorted(breakdown.items(), key=lambda x: -x[1]):
        print(f"    {name:15s}: {cnt:>10,} ({cnt/total*100:5.1f}%)")

    print("\n" + "=" * 60)
    print("  所有示例运行完成!")
    print("=" * 60)


def run_benchmark():
    """性能基准: 对比不同 d_model 的推理速度"""
    print("=" * 60)
    print("  Transformer 性能基准测试")
    print("=" * 60)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n设备: {device}")

    configs = [
        (128,  4, 2,  512,  32),
        (256,  8, 2, 1024,  32),
        (512,  8, 4, 2048,  32),
        (512,  8, 6, 2048,  64),
    ]
    for d_model, n_heads, n_layers, d_ff, seq_len in configs:
        model = Transformer(5000, 5000, d_model=d_model, n_heads=n_heads,
                            d_ff=d_ff, n_layers=n_layers, dropout=0.0).to(device).eval()
        src = torch.randint(1, 5000, (2, seq_len), device=device)
        tgt = torch.randint(1, 5000, (2, seq_len), device=device)
        for _ in range(5):
            with torch.no_grad(): _ = model(src, tgt)
        n_iters = 30
        if device.type == "cuda": torch.cuda.synchronize()
        start = time.time()
        with torch.no_grad():
            for _ in range(n_iters): _ = model(src, tgt)
        if device.type == "cuda": torch.cuda.synchronize()
        elapsed = (time.time() - start) / n_iters * 1000
        params = count_parameters(model)
        print(f"  d={d_model:4d} heads={n_heads} layers={n_layers} "
              f"seq={seq_len:3d} | {params:>10,} params | {elapsed:.2f} ms/iter")
    print("\n基准测试完成!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Transformer 完整架构实现")
    parser.add_argument("--benchmark", action="store_true", help="运行性能基准测试")
    args = parser.parse_args()

    if args.benchmark:
        run_benchmark()
    else:
        run_demo()
