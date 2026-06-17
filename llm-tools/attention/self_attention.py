"""
Self Attention 自注意力机制实现
================================

包含:
  1. ScaledDotProductAttention — 缩放点积注意力
  2. SelfAttention             — 单头自注意力

与交叉注意力 (Cross-Attention) 的区别:
  - 自注意力: Q = K = V 由同一输入序列经独立线性投影生成
  - 交叉注意力: Q 来自目标序列, K/V 来自源序列

核心公式:
  Attention(Q, K, V) = softmax(Q · K^T / √d_k) · V
  其中 Q = X·W_Q,  K = X·W_K,  V = X·W_V  (X 为同一输入)

典型应用:
  - Transformer Encoder: 捕获序列内部的词间依赖
  - BERT: 双向自注意力, 同时关注上下文
  - GPT (masked): 因果自注意力, 只能看到左侧上下文

用法:
  python self_attention.py              # 运行示例
  python self_attention.py --benchmark  # 性能基准测试
"""

import argparse
import math
import time

import torch
import torch.nn as nn
import torch.nn.functional as F


# ──────────────────────────────────────────────
# 1. 缩放点积注意力
# ──────────────────────────────────────────────
class ScaledDotProductAttention(nn.Module):
    """
    Attention(Q, K, V) = softmax(Q · K^T / √d_k) · V

    Args:
        temperature: 缩放因子, 通常为 √d_k
        attn_dropout: dropout 概率
    """

    def __init__(self, temperature, attn_dropout=0.1):
        super().__init__()
        self.temperature = temperature
        self.dropout = nn.Dropout(attn_dropout)

    def forward(self, q, k, v, mask=None):
        """
        Args:
            q: (batch, n_heads, len_q, d_k)  — 查询
            k: (batch, n_heads, len_k, d_k)  — 键
            v: (batch, n_heads, len_v, d_v)  — 值  (len_k == len_v)
            mask: (batch, 1, len_q, len_k) 或可广播形状

        Returns:
            output: (batch, n_heads, len_q, d_v)
            attn:   (batch, n_heads, len_q, len_k) 注意力权重
        """
        attn = torch.matmul(q, k.transpose(-2, -1)) / self.temperature

        if mask is not None:
            attn = attn.masked_fill(mask == 0, float("-inf"))

        attn = self.dropout(F.softmax(attn, dim=-1))
        output = torch.matmul(attn, v)

        return output, attn


# ──────────────────────────────────────────────
# 2. 单头自注意力
# ──────────────────────────────────────────────
class SelfAttention(nn.Module):
    """
    单头自注意力

    Q / K / V 均由同一输入 X 经独立线性投影生成:
        Q = X · W_Q    K = X · W_K    V = X · W_V

    与 Cross-Attention 的本质区别:
        Cross-Attention 中 Q 来自 target, K/V 来自 source (两个不同序列)
        Self-Attention  中 Q/K/V 来自同一个序列, 建模序列内部依赖关系

    Args:
        d_model: 模型维度
        d_k:     键/查询维度 (默认等于 d_model)
        d_v:     值维度 (默认等于 d_model)
        dropout: dropout 概率
    """

    def __init__(self, d_model, d_k=None, d_v=None, dropout=0.1):
        super().__init__()
        d_k = d_k or d_model
        d_v = d_v or d_model

        self.w_q = nn.Linear(d_model, d_k, bias=False)
        self.w_k = nn.Linear(d_model, d_k, bias=False)
        self.w_v = nn.Linear(d_model, d_v, bias=False)

        self.attention = ScaledDotProductAttention(
            temperature=math.sqrt(d_k),
            attn_dropout=dropout,
        )

        self.fc = nn.Linear(d_v, d_model)
        self.dropout = nn.Dropout(dropout)
        self.layer_norm = nn.LayerNorm(d_model)

    def forward(self, x, mask=None):
        """
        Args:
            x:    (batch, seq_len, d_model) — 输入序列, 同时生成 Q/K/V
            mask: (batch, seq_len, seq_len) — 可选掩码 (如因果掩码)

        Returns:
            output: (batch, seq_len, d_model)
            attn:   (batch, seq_len, seq_len)
        """
        residual = x

        q = self.w_q(x)
        k = self.w_k(x)
        v = self.w_v(x)

        # 增加 head 维度以适配 ScaledDotProductAttention
        q = q.unsqueeze(1)
        k = k.unsqueeze(1)
        v = v.unsqueeze(1)

        if mask is not None:
            mask = mask.unsqueeze(1)

        out, attn = self.attention(q, k, v, mask=mask)

        out = out.squeeze(1)

        out = self.dropout(self.fc(out))
        out = self.layer_norm(out + residual)

        return out, attn


# ──────────────────────────────────────────────
# 示例 & 测试
# ──────────────────────────────────────────────
def run_demo():
    """运行自注意力示例"""
    print("=" * 60)
    print("  Self Attention 自注意力 示例")
    print("=" * 60)

    batch_size = 2
    seq_len = 10
    d_model = 64

    torch.manual_seed(42)

    x = torch.randn(batch_size, seq_len, d_model)

    # ── 1. 基本自注意力 ──
    print("\n[1] 基本自注意力 SelfAttention")
    self_attn = SelfAttention(d_model=d_model, dropout=0.0)
    output, attn = self_attn(x)
    print(f"    输入 x:     {x.shape}")
    print(f"    输出 output: {output.shape}")
    print(f"    注意力权重:  {attn.shape}")
    print(f"    权重和验证:  {attn[0, 0].sum(dim=-1)[:3]}  (应接近1.0)")

    # ── 2. 因果掩码自注意力 (Causal Mask) ──
    print("\n[2] 因果掩码自注意力 (Causal / Autoregressive Mask)")
    causal_mask = torch.tril(torch.ones(seq_len, seq_len)).unsqueeze(0).expand(batch_size, -1, -1)
    output_causal, attn_causal = self_attn(x, mask=causal_mask)
    print(f"    causal mask 形状: {causal_mask.shape}")
    print(f"    输出 output:      {output_causal.shape}")
    print(f"    位置4对位置7的权重: {attn_causal[0, 0, 4, 7].item():.6f}  (应为0, 未来位置被遮蔽)")
    print(f"    位置7对位置4的权重: {attn_causal[0, 0, 7, 4].item():.6f}  (应>0, 可看到过去)")

    # ── 3. 注意力权重可视化 ──
    print("\n[3] 注意力权重可视化 — 每个查询位置最关注的 top-5 位置")
    print(f"    {'查询位置':>8}  →  关注位置 (权重从高到低)")
    print(f"    {'─' * 45}")
    for i in range(min(5, seq_len)):
        weights = attn_causal[0, 0, i]
        top5_vals, top5_idx = weights.topk(5)
        positions = ", ".join(f"pos{j}(w={v:.3f})" for j, v in zip(top5_idx.tolist(), top5_vals.tolist()))
        print(f"    pos{i:>5}  →  {positions}")

    # ── 4. 参数量统计 ──
    print("\n[4] 参数量统计")
    total = sum(p.numel() for p in self_attn.parameters())
    print(f"    SelfAttention: {total:,} 参数")
    for name, param in self_attn.named_parameters():
        print(f"      {name}: {param.shape}")

    print("\n" + "=" * 60)
    print("  所有示例运行完成!")
    print("=" * 60)


def run_benchmark():
    """性能基准测试"""
    print("=" * 60)
    print("  Self Attention 性能基准测试")
    print("=" * 60)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n设备: {device}")

    configs = [
        # (batch, seq_len, d_model)
        (4, 64, 64),
        (4, 128, 128),
        (2, 256, 256),
        (2, 512, 512),
    ]

    for batch, seq_len, d_model in configs:
        x = torch.randn(batch, seq_len, d_model, device=device)
        model = SelfAttention(d_model=d_model, dropout=0.0).to(device)
        model.eval()

        for _ in range(5):
            with torch.no_grad():
                _ = model(x)

        n_iters = 50
        if device.type == "cuda":
            torch.cuda.synchronize()
        start = time.time()
        with torch.no_grad():
            for _ in range(n_iters):
                _ = model(x)
        if device.type == "cuda":
            torch.cuda.synchronize()
        elapsed = (time.time() - start) / n_iters * 1000

        print(f"  batch={batch}, seq={seq_len}, d={d_model} → {elapsed:.2f} ms/iter")

    print("\n基准测试完成!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Self Attention 自注意力实现")
    parser.add_argument("--benchmark", action="store_true", help="运行性能基准测试")
    args = parser.parse_args()

    if args.benchmark:
        run_benchmark()
    else:
        run_demo()
