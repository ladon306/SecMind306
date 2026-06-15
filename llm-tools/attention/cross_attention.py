"""
Cross Attention 交叉注意力机制实现
================================

包含:
  1. ScaledDotProductAttention  — 缩放点积注意力
  2. CrossAttention             — 单头交叉注意力
  3. MultiHeadCrossAttention    — 多头交叉注意力

与自注意力 (Self-Attention) 的区别:
  - 自注意力: Q = K = V 来自同一序列
  - 交叉注意力: Q 来自目标序列, K/V 来自源序列

典型应用:
  - Transformer Decoder: Q 来自解码器, K/V 来自编码器输出
  - 图像描述生成: Q 来自文本, K/V 来自图像特征
  - Stable Diffusion: Q 来自 U-Net 特征, K/V 来自 CLIP 文本嵌入

用法:
  python cross_attention.py          # 运行示例
  python cross_attention.py --benchmark  # 性能基准测试
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
            mask: (batch, 1, len_q, len_k) 或 (batch, n_heads, len_q, len_k)

        Returns:
            output: (batch, n_heads, len_q, d_v)
            attn:   (batch, n_heads, len_q, len_k) 注意力权重
        """
        # Q · K^T → (batch, n_heads, len_q, len_k)
        attn = torch.matmul(q, k.transpose(-2, -1)) / self.temperature

        # mask: 被遮蔽的位置填 -inf, softmax 后变为 0
        if mask is not None:
            attn = attn.masked_fill(mask == 0, float("-inf"))

        attn = self.dropout(F.softmax(attn, dim=-1))
        output = torch.matmul(attn, v)

        return output, attn


# ──────────────────────────────────────────────
# 2. 单头交叉注意力
# ──────────────────────────────────────────────
class CrossAttention(nn.Module):
    """
    单头交叉注意力

    Q 来自目标序列 (target), K/V 来自源序列 (source)

    Args:
        d_model:    模型维度
        d_k:        键/查询维度 (默认 d_model)
        d_v:        值维度 (默认 d_model)
        dropout:    dropout 概率
    """

    def __init__(self, d_model, d_k=None, d_v=None, dropout=0.1):
        super().__init__()
        d_k = d_k or d_model
        d_v = d_v or d_model

        # Q 投影来自 target, K/V 投影来自 source
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

    def forward(self, target, source, mask=None):
        """
        Args:
            target: (batch, len_q, d_model)  — 目标序列, 生成 Q
            source: (batch, len_kv, d_model) — 源序列, 生成 K/V
            mask:   (batch, len_q, len_kv)   — 可选掩码

        Returns:
            output: (batch, len_q, d_model)
            attn:   (batch, len_q, len_kv)
        """
        residual = target

        # 线性投影
        q = self.w_q(target)  # (batch, len_q, d_k)
        k = self.w_k(source)  # (batch, len_kv, d_k)
        v = self.w_v(source)  # (batch, len_kv, d_v)

        # 缩放点积注意力 (增加 head 维度)
        q = q.unsqueeze(1)  # (batch, 1, len_q, d_k)
        k = k.unsqueeze(1)  # (batch, 1, len_kv, d_k)
        v = v.unsqueeze(1)  # (batch, 1, len_kv, d_v)

        if mask is not None:
            mask = mask.unsqueeze(1)  # (batch, 1, len_q, len_kv)

        out, attn = self.attention(q, k, v, mask=mask)

        # 去掉 head 维度
        out = out.squeeze(1)  # (batch, len_q, d_v)

        # 残差连接 + LayerNorm
        out = self.dropout(self.fc(out))
        out = self.layer_norm(out + residual)

        return out, attn


# ──────────────────────────────────────────────
# 3. 多头交叉注意力
# ──────────────────────────────────────────────
class MultiHeadCrossAttention(nn.Module):
    """
    多头交叉注意力

    将 Q/K/V 拆分到 n_heads 个头, 各自独立计算注意力再拼接融合

    Args:
        n_heads:    注意力头数
        d_model:    模型维度 (需能被 n_heads 整除)
        dropout:    dropout 概率
    """

    def __init__(self, n_heads, d_model, dropout=0.1):
        super().__init__()
        assert d_model % n_heads == 0, f"d_model({d_model}) 必须能被 n_heads({n_heads}) 整除"

        self.n_heads = n_heads
        self.d_k = d_model // n_heads
        self.d_v = d_model // n_heads

        # Q 投影来自 target, K/V 投影来自 source
        self.w_q = nn.Linear(d_model, n_heads * self.d_k, bias=False)
        self.w_k = nn.Linear(d_model, n_heads * self.d_k, bias=False)
        self.w_v = nn.Linear(d_model, n_heads * self.d_v, bias=False)

        self.attention = ScaledDotProductAttention(
            temperature=math.sqrt(self.d_k),
            attn_dropout=dropout,
        )

        self.fc = nn.Linear(n_heads * self.d_v, d_model)
        self.dropout = nn.Dropout(dropout)
        self.layer_norm = nn.LayerNorm(d_model)

    def forward(self, target, source, mask=None):
        """
        Args:
            target: (batch, len_q, d_model)  — 目标序列
            source: (batch, len_kv, d_model) — 源序列
            mask:   (batch, len_q, len_kv)   — 可选掩码

        Returns:
            output: (batch, len_q, d_model)
            attn:   (batch, n_heads, len_q, len_kv)
        """
        batch_size = target.size(0)
        residual = target

        # 线性投影并拆分多头
        q = self.w_q(target).view(batch_size, -1, self.n_heads, self.d_k).transpose(1, 2)
        k = self.w_k(source).view(batch_size, -1, self.n_heads, self.d_k).transpose(1, 2)
        v = self.w_v(source).view(batch_size, -1, self.n_heads, self.d_v).transpose(1, 2)
        # q: (batch, n_heads, len_q, d_k)
        # k: (batch, n_heads, len_kv, d_k)
        # v: (batch, n_heads, len_kv, d_v)

        if mask is not None:
            mask = mask.unsqueeze(1)  # (batch, 1, len_q, len_kv) → 广播到所有头

        out, attn = self.attention(q, k, v, mask=mask)

        # 拼接多头
        out = out.transpose(1, 2).contiguous().view(batch_size, -1, self.n_heads * self.d_v)

        # 残差连接 + LayerNorm
        out = self.dropout(self.fc(out))
        out = self.layer_norm(out + residual)

        return out, attn


# ──────────────────────────────────────────────
# 示例 & 测试
# ──────────────────────────────────────────────
def run_demo():
    """运行交叉注意力示例"""
    print("=" * 60)
    print("  Cross Attention 交叉注意力 示例")
    print("=" * 60)

    batch_size = 2
    d_model = 64
    len_target = 10   # 目标序列长度 (如解码器)
    len_source = 20   # 源序列长度 (如编码器输出)
    n_heads = 8

    torch.manual_seed(42)

    # 模拟输入
    target = torch.randn(batch_size, len_target, d_model)  # Q 的来源
    source = torch.randn(batch_size, len_source, d_model)  # K/V 的来源

    # ── 1. 单头交叉注意力 ──
    print("\n[1] 单头交叉注意力 CrossAttention")
    cross_attn = CrossAttention(d_model=d_model, dropout=0.0)
    output, attn = cross_attn(target, source)
    print(f"    输入 target: {target.shape}")
    print(f"    输入 source: {source.shape}")
    print(f"    输出 output: {output.shape}")
    print(f"    注意力权重:  {attn.shape}")
    print(f"    权重和验证:  {attn[0, 0].sum(dim=-1)[:3]}  (应接近1.0)")

    # ── 2. 多头交叉注意力 ──
    print("\n[2] 多头交叉注意力 MultiHeadCrossAttention")
    mh_cross_attn = MultiHeadCrossAttention(n_heads=n_heads, d_model=d_model, dropout=0.0)
    output_mh, attn_mh = mh_cross_attn(target, source)
    print(f"    输入 target: {target.shape}")
    print(f"    输入 source: {source.shape}")
    print(f"    输出 output: {output_mh.shape}")
    print(f"    注意力权重:  {attn_mh.shape}")
    print(f"    权重和验证:  {attn_mh[0, 0].sum(dim=-1)[:3]}  (应接近1.0)")

    # ── 3. 带 mask 的交叉注意力 ──
    print("\n[3] 带 mask 的交叉注意力 (模拟解码器 causal mask)")
    # mask: target 的每个位置只能看到 source 的部分位置
    mask = torch.ones(batch_size, len_target, len_source)
    mask[:, len_target // 2:, len_source // 2:] = 0  # 后半部分遮蔽
    output_masked, attn_masked = mh_cross_attn(target, source, mask=mask)
    print(f"    mask 形状:    {mask.shape}")
    print(f"    输出 output:  {output_masked.shape}")
    # 验证被 mask 位置的注意力权重为 0
    print(f"    被遮蔽位置权重: {attn_masked[0, 0, len_target - 1, len_source - 1].item():.6f}  (应为0)")

    # ── 4. 参数量统计 ──
    print("\n[4] 参数量统计")
    for name, model in [("CrossAttention", cross_attn), ("MultiHeadCrossAttention", mh_cross_attn)]:
        total = sum(p.numel() for p in model.parameters())
        print(f"    {name}: {total:,} 参数")

    print("\n" + "=" * 60)
    print("  所有示例运行完成!")
    print("=" * 60)


def run_benchmark():
    """性能基准测试"""
    print("=" * 60)
    print("  Cross Attention 性能基准测试")
    print("=" * 60)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n设备: {device}")

    configs = [
        # (batch, len_target, len_source, d_model, n_heads)
        (4, 32, 128, 64, 4),
        (4, 64, 256, 128, 8),
        (2, 128, 512, 256, 8),
        (2, 256, 1024, 512, 8),
    ]

    for batch, len_q, len_kv, d_model, n_heads in configs:
        target = torch.randn(batch, len_q, d_model, device=device)
        source = torch.randn(batch, len_kv, d_model, device=device)

        model = MultiHeadCrossAttention(n_heads=n_heads, d_model=d_model, dropout=0.0).to(device)
        model.eval()

        # warmup
        for _ in range(5):
            with torch.no_grad():
                _ = model(target, source)

        # benchmark
        n_iters = 50
        if device.type == "cuda":
            torch.cuda.synchronize()
        start = time.time()
        with torch.no_grad():
            for _ in range(n_iters):
                _ = model(target, source)
        if device.type == "cuda":
            torch.cuda.synchronize()
        elapsed = (time.time() - start) / n_iters * 1000

        print(f"  batch={batch}, len_q={len_q}, len_kv={len_kv}, d={d_model}, heads={n_heads} → {elapsed:.2f} ms/iter")

    print("\n基准测试完成!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cross Attention 交叉注意力实现")
    parser.add_argument("--benchmark", action="store_true", help="运行性能基准测试")
    args = parser.parse_args()

    if args.benchmark:
        run_benchmark()
    else:
        run_demo()
