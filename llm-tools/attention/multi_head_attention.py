"""
Multi-Head Attention 多头注意力机制实现
========================================

包含:
  1. MultiHeadAttention — 多头注意力 (同时支持自注意力与交叉注意力)

核心思想 (Attention Is All You Need, Vaswani et al., 2017):
  MultiHead(Q, K, V) = Concat(head_1, ..., head_h) · W_O
  head_i = Attention(Q · W_Q_i, K · W_K_i, V · W_V_i)

为什么需要多头:
  单头注意力只能捕捉一种关联模式, 多头允许模型同时关注不同表示子空间的信息,
  例如: 某些头关注语法关系, 某些头关注语义相似性, 某些头关注位置邻近关系.

约束: d_model = n_heads × d_k (模型维度必须能被头数整除)

与 cross_attention.py 的关系:
  cross_attention.py 将自注意力和交叉注意力分成两个类,
  本实现统一为一个类, 通过 forward() 的参数来切换模式.

用法:
  python multi_head_attention.py          # 运行示例
  python multi_head_attention.py --benchmark  # 性能基准测试
"""

import argparse
import math
import time

import torch
import torch.nn as nn
import torch.nn.functional as F


# ──────────────────────────────────────────────
# 1. 多头注意力
# ──────────────────────────────────────────────
class MultiHeadAttention(nn.Module):
    """
    多头注意力 — 统一支持自注意力与交叉注意力

    自注意力模式:   forward(x)           → Q = K = V = x
    交叉注意力模式: forward(x, context)  → Q = x, K = V = context

    支持:
      - Causal mask (因果掩码, 用于自回归生成)
      - Key padding mask (键填充掩码, 用于变长序列批处理)
      - 残差连接 + LayerNorm (可通过 use_resnorm 关闭)
      - Dropout

    公式:
      Q' = Q · W_Q,  K' = K · W_K,  V' = V · W_V
      Q' = Q'.view(B, L, H, d_k).transpose(1,2)   → (B, H, L, d_k)
      head_i = softmax(Q'_i · K'_i^T / √d_k) · V'_i
      output = Concat(head_1,...,head_h) · W_O

    Args:
        d_model:    模型维度 (需能被 n_heads 整除)
        n_heads:    注意力头数
        dropout:    dropout 概率
        use_resnorm: 是否使用残差连接 + LayerNorm
    """

    def __init__(self, d_model, n_heads, dropout=0.1, use_resnorm=True):
        super().__init__()
        assert d_model % n_heads == 0, f"d_model({d_model}) 必须能被 n_heads({n_heads}) 整除"

        self.d_model = d_model
        self.n_heads = n_heads
        self.d_k = d_model // n_heads

        self.w_q = nn.Linear(d_model, d_model, bias=False)
        self.w_k = nn.Linear(d_model, d_model, bias=False)
        self.w_v = nn.Linear(d_model, d_model, bias=False)
        self.w_o = nn.Linear(d_model, d_model, bias=False)

        self.dropout = nn.Dropout(dropout)
        self.attn_dropout = nn.Dropout(dropout)
        self.use_resnorm = use_resnorm
        if use_resnorm:
            self.layer_norm = nn.LayerNorm(d_model)

    def forward(self, x, context=None, causal_mask=False, key_padding_mask=None):
        """
        Args:
            x:      (batch, len_q, d_model) — 查询输入 (自注意力时也提供 K/V)
            context:(batch, len_kv, d_model) — 上下文输入 (交叉注意力时提供 K/V)
                    若为 None 则退化为自注意力: K = V = x
            causal_mask:     是否应用因果掩码 (下三角), 用于自回归解码
            key_padding_mask:(batch, len_kv) — True 表示该位置为 padding, 应被遮蔽

        Returns:
            output: (batch, len_q, d_model)
            attn:   (batch, n_heads, len_q, len_kv) 注意力权重
        """
        batch_size = x.size(0)
        residual = x

        # ── 确定 K/V 来源 ──
        source = x if context is None else context
        is_cross = context is not None

        # ── 线性投影 + 拆分多头 ──
        q = self.w_q(x).view(batch_size, -1, self.n_heads, self.d_k).transpose(1, 2)
        k = self.w_k(source).view(batch_size, -1, self.n_heads, self.d_k).transpose(1, 2)
        v = self.w_v(source).view(batch_size, -1, self.n_heads, self.d_k).transpose(1, 2)
        # q: (B, H, len_q, d_k)  k/v: (B, H, len_kv, d_k)

        # ── 构建注意力掩码 (统一约定: True = 允许关注, False = 遮蔽) ──
        len_q, len_kv = q.size(2), k.size(2)
        attn_mask = None  # bool mask: True=allow, False=block

        if causal_mask:
            causal = torch.tril(torch.ones(len_q, len_kv, device=x.device)).bool()
            attn_mask = causal.unsqueeze(0).unsqueeze(0)  # (1, 1, len_q, len_kv)

        if key_padding_mask is not None:
            # key_padding_mask: (B, len_kv), True = padding → 取反得到允许位
            pad_allowed = ~key_padding_mask.unsqueeze(1).unsqueeze(2)  # (B, 1, 1, len_kv)
            pad_allowed = pad_allowed.expand(batch_size, self.n_heads, len_q, len_kv)
            if attn_mask is None:
                attn_mask = pad_allowed
            else:
                attn_mask = attn_mask.expand(batch_size, self.n_heads, len_q, len_kv) & pad_allowed

        # ── 缩放点积注意力 ──
        scale = math.sqrt(self.d_k)
        attn_scores = torch.matmul(q, k.transpose(-2, -1)) / scale

        if attn_mask is not None:
            attn_scores = attn_scores.masked_fill(~attn_mask, float("-inf"))

        attn = F.softmax(attn_scores, dim=-1)
        attn = self.attn_dropout(attn)
        out = torch.matmul(attn, v)  # (B, H, len_q, d_k)

        # ── 拼接多头 + 输出投影 ──
        out = out.transpose(1, 2).contiguous().view(batch_size, -1, self.d_model)
        out = self.dropout(self.w_o(out))

        # ── 残差连接 + LayerNorm ──
        if self.use_resnorm:
            out = self.layer_norm(out + residual)

        return out, attn


# ──────────────────────────────────────────────
# 2. 工具函数
# ──────────────────────────────────────────────
def visualize_head_attention(attn, head_idx, tokens_q=None, tokens_kv=None, top_k=3):
    """打印单个头的注意力分布摘要"""
    weights = attn[0, head_idx]
    len_q, len_kv = weights.shape
    print(f"    Head {head_idx}: 每个 query 位的 top-{top_k} 关注位置")
    for i in range(min(len_q, 5)):
        topv, topi = weights[i].topk(top_k)
        positions = ", ".join(f"pos{ti.item()}({tv:.3f})" for tv, ti in zip(topv, topi))
        print(f"      query[{i}] → {positions}")


# ──────────────────────────────────────────────
# 3. 示例 & 测试
# ──────────────────────────────────────────────
def run_demo():
    """运行多头注意力示例"""
    print("=" * 60)
    print("  Multi-Head Attention 多头注意力 示例")
    print("=" * 60)

    batch_size = 2
    d_model = 64
    n_heads = 8
    seq_len = 10
    ctx_len = 20

    torch.manual_seed(42)

    # ── 1. 自注意力模式 ──
    print("\n[1] 自注意力模式 (Self-Attention)")
    mha = MultiHeadAttention(d_model=d_model, n_heads=n_heads, dropout=0.0)
    x = torch.randn(batch_size, seq_len, d_model)
    out_self, attn_self = mha(x)
    print(f"    输入:        {x.shape}")
    print(f"    输出:        {out_self.shape}")
    print(f"    注意力权重:  {attn_self.shape}")
    print(f"    权重和验证:  {attn_self[0, 0].sum(dim=-1)[:3]}  (应接近1.0)")

    # ── 2. 交叉注意力模式 ──
    print("\n[2] 交叉注意力模式 (Cross-Attention)")
    context = torch.randn(batch_size, ctx_len, d_model)
    out_cross, attn_cross = mha(x, context=context)
    print(f"    Query输入:   {x.shape}")
    print(f"    Context输入: {context.shape}")
    print(f"    输出:        {out_cross.shape}")
    print(f"    注意力权重:  {attn_cross.shape}")
    print(f"    权重和验证:  {attn_cross[0, 0].sum(dim=-1)[:3]}  (应接近1.0)")

    # ── 3. 因果掩码 (Causal Mask) ──
    print("\n[3] 因果掩码 — 自回归生成场景")
    out_causal, attn_causal = mha(x, causal_mask=True)
    print(f"    输出: {out_causal.shape}")
    # 验证: 位置 i 不应关注 >i 的位置
    causal_check = attn_causal[0, 0]
    for i in range(min(4, seq_len)):
        future_w = causal_check[i, i + 1:].sum().item()
        print(f"    query[{i}] 对未来位置的关注度: {future_w:.6f}  (应为0)")

    # ── 4. Key Padding Mask ──
    print("\n[4] Key Padding Mask — 变长序列批处理")
    key_pad = torch.zeros(batch_size, ctx_len, dtype=torch.bool)
    key_pad[0, -5:] = True   # batch 0 的最后5个位置是 padding
    key_pad[1, -8:] = True   # batch 1 的最后8个位置是 padding
    out_pad, attn_pad = mha(x, context=context, key_padding_mask=key_pad)
    # 验证 padding 位置的注意力权重为 0
    pad_weight = attn_pad[0, 0, 0, -5:].sum().item()
    print(f"    batch 0 对 padding 位置的关注度: {pad_weight:.6f}  (应为0)")

    # ── 5. 多头权重分析 — 不同头关注不同模式 ──
    print("\n[5] 多头注意力多样性分析")
    mha_demo = MultiHeadAttention(d_model=d_model, n_heads=n_heads, dropout=0.0, use_resnorm=False)
    torch.manual_seed(7)
    x_demo = torch.randn(1, seq_len, d_model)
    _, attn_demo = mha_demo(x_demo)

    print(f"    总头数: {n_heads}, d_k: {d_model // n_heads}")
    for h in range(min(4, n_heads)):
        visualize_head_attention(attn_demo, head_idx=h, top_k=3)

    # 计算头间差异: 不同头对同一位置的注意力分布相关系数
    print("    ── 头间相似度 (余弦相似度, 越低越多样) ──")
    for h1, h2 in [(0, 1), (0, 2), (1, 3)]:
        v1 = attn_demo[0, h1].flatten()
        v2 = attn_demo[0, h2].flatten()
        cos = F.cosine_similarity(v1.unsqueeze(0), v2.unsqueeze(0)).item()
        print(f"    head{h1} vs head{h2}: {cos:.4f}")

    # ── 6. 参数量统计 ──
    print("\n[6] 参数量统计")
    total = sum(p.numel() for p in mha.parameters())
    print(f"    MultiHeadAttention(d={d_model}, h={n_heads}): {total:,} 参数")
    print(f"    拆解: W_Q={d_model*d_model}, W_K={d_model*d_model}, "
          f"W_V={d_model*d_model}, W_O={d_model*d_model}, LN={d_model*2}")

    print("\n" + "=" * 60)
    print("  所有示例运行完成!")
    print("=" * 60)


def run_benchmark():
    """性能基准测试"""
    print("=" * 60)
    print("  Multi-Head Attention 性能基准测试")
    print("=" * 60)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n设备: {device}")

    configs = [
        # (batch, seq_len, d_model, n_heads, mode)
        (4, 128,  64,  4, "self"),
        (4, 256,  128, 8, "self"),
        (2, 512,  256, 8, "self"),
        (2, 1024, 512, 8, "self"),
        (4, 128,  128, 8, "cross"),
    ]

    for batch, seq_len, d_model, n_heads, mode in configs:
        x = torch.randn(batch, seq_len, d_model, device=device)
        ctx = torch.randn(batch, seq_len * 2, d_model, device=device) if mode == "cross" else None

        model = MultiHeadAttention(d_model=d_model, n_heads=n_heads, dropout=0.0).to(device)
        model.eval()

        for _ in range(5):
            with torch.no_grad():
                _ = model(x, context=ctx)

        n_iters = 50
        if device.type == "cuda":
            torch.cuda.synchronize()
        start = time.time()
        with torch.no_grad():
            for _ in range(n_iters):
                _ = model(x, context=ctx)
        if device.type == "cuda":
            torch.cuda.synchronize()
        elapsed = (time.time() - start) / n_iters * 1000

        tag = f"cross(ctx={seq_len * 2})" if mode == "cross" else "self"
        print(f"  batch={batch}, len={seq_len}, d={d_model}, heads={n_heads}, {tag} → {elapsed:.2f} ms/iter")

    print("\n基准测试完成!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Head Attention 多头注意力实现")
    parser.add_argument("--benchmark", action="store_true", help="运行性能基准测试")
    args = parser.parse_args()

    if args.benchmark:
        run_benchmark()
    else:
        run_demo()
