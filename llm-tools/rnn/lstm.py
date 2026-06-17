"""
Long Short-Term Memory (LSTM) 长短期记忆网络实现
================================================

包含:
  1. LSTMCell — 单步 LSTM 单元 (4个门控)
  2. LSTM     — 多层双向 LSTM (dropout / stateful)

核心公式:
  遗忘门:  f_t = σ(W_f · [h_{t-1}, x_t] + b_f)
  输入门:  i_t = σ(W_i · [h_{t-1}, x_t] + b_i)
  候选值:  g̃_t = tanh(W_g · [h_{t-1}, x_t] + b_g)
  细胞态:  c_t = f_t ⊙ c_{t-1} + i_t ⊙ g̃_t   ← 加性更新, 梯度不消失!
  输出门:  o_t = σ(W_o · [h_{t-1}, x_t] + b_o)
  隐藏态:  h_t = o_t ⊙ tanh(c_t)

关键概念:
  - 细胞状态 c_t 是"信息高速公路", 加性更新保留梯度
  - 遗忘门是"橡皮擦", 让LSTM学会主动遗忘无关信息
  - Peephole LSTM: 门控也观察c_{t-1}, 更精细的时序控制
  - GRU: LSTM的简化版, 合并遗忘门和输入门为更新门

用法:
  python lstm.py              # 运行示例
  python lstm.py --benchmark  # 性能基准测试
"""

import argparse
import math
import time

import torch
import torch.nn as nn
import torch.nn.functional as F


# ──────────────────────────────────────────────
# 1. LSTM 单元
# ──────────────────────────────────────────────
class LSTMCell(nn.Module):
    """
    单步 LSTM 单元 — 4 个门控协同工作

    将 4 组权重合并为一个大矩阵乘法以提高效率:
      [i, f, g, o] = W · [x, h] + b

    Args:
        input_size:  输入特征维度
        hidden_size: 隐藏状态维度
        bias:        是否使用偏置
    """

    def __init__(self, input_size, hidden_size, bias=True):
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size

        # 合并4门权重: 4*hidden_size 行, (input_size + hidden_size) 列
        self.weight_ih = nn.Parameter(torch.Tensor(4 * hidden_size, input_size))
        self.weight_hh = nn.Parameter(torch.Tensor(4 * hidden_size, hidden_size))
        if bias:
            self.bias = nn.Parameter(torch.Tensor(4 * hidden_size))
        else:
            self.register_parameter("bias", None)

        self.reset_parameters()

    def reset_parameters(self):
        nn.init.xavier_uniform_(self.weight_ih)
        nn.init.orthogonal_(self.weight_hh)
        if self.bias is not None:
            nn.init.zeros_(self.bias)
            # 遗忘门偏置初始化为1, 鼓励初期保留信息 (Jozefowicz et al. 2015)
            nn.init.ones_(self.bias[self.hidden_size:2 * self.hidden_size])

    def forward(self, x_t, h_prev, c_prev):
        """
        Args:
            x_t:    (batch, input_size)  当前输入
            h_prev: (batch, hidden_size) 上一隐藏态
            c_prev: (batch, hidden_size) 上一细胞态

        Returns:
            h_t: (batch, hidden_size) 当前隐藏态
            c_t: (batch, hidden_size) 当前细胞态
        """
        # 一次矩阵乘法计算4个门
        gates = x_t @ self.weight_ih.t() + h_prev @ self.weight_hh.t() + self.bias
        i, f, g, o = gates.chunk(4, dim=-1)

        i_t = torch.sigmoid(i)       # 输入门: 决定写入多少新信息
        f_t = torch.sigmoid(f)       # 遗忘门: 决定保留多少旧记忆
        g_t = torch.tanh(g)          # 候选值: 新信息的候选内容
        o_t = torch.sigmoid(o)       # 输出门: 决定输出多少记忆

        c_t = f_t * c_prev + i_t * g_t   # 加性更新: 梯度可以无损流过
        h_t = o_t * torch.tanh(c_t)

        return h_t, c_t


# ──────────────────────────────────────────────
# 2. 多层 LSTM
# ──────────────────────────────────────────────
class LSTM(nn.Module):
    """
    多层 (双向) LSTM

    - 堆叠: 第 i 层输出作为第 i+1 层输入
    - 双向: 正向 + 反向隐藏状态拼接
    - Dropout: 层间随机失活 (最后一层不加)
    - Stateful: 跨batch保留隐藏状态, 适用于超长序列分批训练

    Args:
        input_size:    输入特征维度
        hidden_size:   隐藏状态维度
        num_layers:    层数
        batch_first:   输入是否 (batch, seq, feature) 格式
        bidirectional: 是否双向
        dropout:       层间 dropout 概率 (仅 num_layers > 1 时生效)
        stateful:      是否跨 batch 保持隐藏状态
    """

    def __init__(self, input_size, hidden_size, num_layers=1,
                 batch_first=False, bidirectional=False, dropout=0.0, stateful=False):
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.batch_first = batch_first
        self.bidirectional = bidirectional
        self.num_directions = 2 if bidirectional else 1
        self.dropout = dropout
        self.stateful = stateful
        self._state = None

        self.cells = nn.ModuleList()
        self.drop = nn.Dropout(dropout) if dropout > 0 else None

        for layer in range(num_layers):
            layer_input = input_size if layer == 0 else hidden_size * self.num_directions
            self.cells.append(LSTMCell(layer_input, hidden_size))
            if bidirectional:
                self.cells.append(LSTMCell(layer_input, hidden_size))

    def _cell_idx(self, layer, direction):
        return layer * self.num_directions + direction

    def init_state(self, batch_size, device, dtype):
        return (torch.zeros(self.num_layers * self.num_directions, batch_size,
                            self.hidden_size, device=device, dtype=dtype),
                torch.zeros(self.num_layers * self.num_directions, batch_size,
                            self.hidden_size, device=device, dtype=dtype))

    def reset_state(self):
        self._state = None

    def forward(self, input, hx=None, cx=None):
        """
        Args:
            input: (seq_len, batch, input_size) 或 (batch, seq_len, input_size)
            hx:    (num_layers * num_directions, batch, hidden_size)
            cx:    (num_layers * num_directions, batch, hidden_size)

        Returns:
            output: (seq_len, batch, hidden_size * num_directions)
            (hx, cx): 最终隐藏状态和细胞状态
        """
        if self.batch_first:
            input = input.transpose(0, 1)

        seq_len, batch_size, _ = input.shape

        if self.stateful and self._state is not None:
            hx, cx = self._state
        if hx is None or cx is None:
            hx, cx = self.init_state(batch_size, input.device, input.dtype)

        layer_input = input
        final_hx, final_cx = [], []

        for layer in range(self.num_layers):
            # ── 正向 ──
            idx_f = self._cell_idx(layer, 0)
            cell_f = self.cells[idx_f]
            h_f, c_f = hx[idx_f], cx[idx_f]
            fwd_out = []
            for t in range(seq_len):
                h_f, c_f = cell_f(layer_input[t], h_f, c_f)
                fwd_out.append(h_f)
            fwd_output = torch.stack(fwd_out, dim=0)
            final_hx.append(h_f)
            final_cx.append(c_f)

            # ── 反向 ──
            if self.bidirectional:
                idx_b = self._cell_idx(layer, 1)
                cell_b = self.cells[idx_b]
                h_b, c_b = hx[idx_b], cx[idx_b]
                bwd_out = []
                for t in range(seq_len - 1, -1, -1):
                    h_b, c_b = cell_b(layer_input[t], h_b, c_b)
                    bwd_out.append(h_b)
                bwd_output = torch.stack(bwd_out[::-1], dim=0)
                final_hx.append(h_b)
                final_cx.append(c_b)
                layer_input = torch.cat([fwd_output, bwd_output], dim=-1)
            else:
                layer_input = fwd_output

            # 层间 dropout (最后一层除外)
            if self.drop is not None and layer < self.num_layers - 1:
                layer_input = self.drop(layer_input)

        output = layer_input
        hx_out = torch.stack(final_hx, dim=0)
        cx_out = torch.stack(final_cx, dim=0)

        if self.stateful:
            self._state = (hx_out.detach(), cx_out.detach())

        if self.batch_first:
            output = output.transpose(0, 1)

        return output, (hx_out, cx_out)


# ──────────────────────────────────────────────
# 示例 & 测试
# ──────────────────────────────────────────────
def run_demo():
    print("=" * 60)
    print("  LSTM 长短期记忆网络 示例")
    print("=" * 60)

    torch.manual_seed(42)

    # ── 1. 基础序列处理 ──
    print("\n[1] 基础 LSTM 序列处理 (seq_len=20, input_size=16, hidden_size=32)")
    lstm = LSTM(input_size=16, hidden_size=32, num_layers=1, batch_first=True)
    x = torch.randn(2, 20, 16)
    out, (hx, cx) = lstm(x)
    print(f"    输入:  {x.shape}")
    print(f"    输出:  {out.shape}")
    print(f"    h_n:   {hx.shape}")
    print(f"    c_n:   {cx.shape}")

    # ── 2. 遗忘门分析 ──
    print("\n[2] 遗忘门分析 — 观察遗忘门如何控制记忆保留")
    cell = LSTMCell(16, 32)
    x_seq = torch.randn(1, 10, 16)
    h, c = torch.zeros(1, 32), torch.zeros(1, 32)
    forget_values = []
    for t in range(10):
        gates = x_seq[:, t] @ cell.weight_ih.t() + h @ cell.weight_hh.t() + cell.bias
        f_t = torch.sigmoid(gates.chunk(4, dim=-1)[1])
        h, c = cell(x_seq[:, t], h, c)
        forget_values.append(f_t.mean().item())
    print(f"    遗忘门均值 (10步): {[f'{v:.3f}' for v in forget_values]}")
    print("    → 接近1=保留旧记忆, 接近0=遗忘旧记忆")
    print("    → 遗忘门是LSTM能'学会忘记'的关键 (相比RNN被动遗忘)")

    # ── 3. 细胞状态动态观察 ──
    print("\n[3] 细胞状态动态 — c_t 的变化轨迹")
    h, c = torch.zeros(1, 16), torch.zeros(1, 16)
    cell2 = LSTMCell(8, 16)
    x_demo = torch.randn(1, 30, 8)
    c_norms = []
    for t in range(30):
        h, c = cell2(x_demo[:, t], h, c)
        c_norms.append(c.norm().item())
    print(f"    c_t 范数 (前5步):  {[f'{v:.3f}' for v in c_norms[:5]]}")
    print(f"    c_t 范数 (后5步):  {[f'{v:.3f}' for v in c_norms[-5:]]}")
    print("    → c_t 不像RNN的h_t那样被反复压缩, 加性更新让信息持久保留")

    # ── 4. 梯度对比: LSTM vs Vanilla RNN ──
    print("\n[4] 梯度对比 — LSTM vs Vanilla RNN (序列长度=200)")
    seq_len_long = 200
    x_long = torch.randn(1, seq_len_long, 16)
    target = torch.randn(1, seq_len_long, 32)

    lstm_model = LSTM(input_size=16, hidden_size=32, batch_first=True)
    rnn_model = nn.RNN(input_size=16, hidden_size=32, batch_first=True)

    out_l, _ = lstm_model(x_long)
    out_r, _ = rnn_model(x_long)
    loss_l = F.mse_loss(out_l, target)
    loss_r = F.mse_loss(out_r, target)
    loss_l.backward()
    loss_r.backward()

    lstm_grad = lstm_model.cells[0].weight_ih.grad.norm().item()
    rnn_grad = rnn_model.weight_ih_l0.grad.norm().item()
    print(f"    LSTM weight_ih 梯度范数: {lstm_grad:.6e}")
    print(f"    RNN  weight_ih 梯度范数: {rnn_grad:.6e}")
    print(f"    LSTM/RNN 梯度比:         {lstm_grad / (rnn_grad + 1e-12):.2f}x")
    print("    → LSTM梯度显著更大: 加性更新 c_t = f⊙c + i⊙g̃ 让梯度无损传递")
    print("    → RNN梯度消失: h_t = tanh(Wh·h), 反复乘Wh导致指数衰减")

    # ── 5. 正弦波预测 ──
    print("\n[5] 序列预测 — 正弦波")
    t_vals = torch.linspace(0, 4 * math.pi, 80)
    sin_seq = torch.sin(t_vals).unsqueeze(0).unsqueeze(-1)  # (1, 80, 1)
    pred_model = LSTM(input_size=1, hidden_size=32, num_layers=2, batch_first=True, dropout=0.1)
    optimizer = torch.optim.Adam(pred_model.parameters(), lr=0.01)

    print("    训练中 (500步)...")
    for step in range(500):
        optimizer.zero_grad()
        pred, _ = pred_model(sin_seq[:, :-1])
        loss = F.mse_loss(pred, sin_seq[:, 1:].expand_as(pred)[:, :, :1])
        loss.backward()
        optimizer.step()
        if (step + 1) % 100 == 0:
            with torch.no_grad():
                pred2, _ = pred_model(sin_seq[:, :-1])
                l = F.mse_loss(pred2[:, :, :1], sin_seq[:, 1:])
            print(f"    step {step+1:3d} | loss = {l.item():.6f}")

    print("    → LSTM能学习正弦波的周期性模式 (h_t充当周期记忆)")

    # ── 6. 与 PyTorch nn.LSTM 对比 ──
    print("\n[6] 与 PyTorch nn.LSTM 对比验证")
    my_lstm = LSTM(input_size=16, hidden_size=32, num_layers=2, batch_first=True)
    pt_lstm = nn.LSTM(input_size=16, hidden_size=32, num_layers=2, batch_first=True)
    # 拷贝权重
    for layer in range(2):
        pt_lstm.weight_ih_l[layer].data = my_lstm.cells[layer].weight_ih.data
        pt_lstm.weight_hh_l[layer].data = my_lstm.cells[layer].weight_hh.data
        pt_lstm.bias_ih_l[layer].data = my_lstm.cells[layer].bias.data
        pt_lstm.bias_hh_l[layer].data = torch.zeros_like(my_lstm.cells[layer].bias.data)
    x_test = torch.randn(1, 5, 16)
    with torch.no_grad():
        out_my, _ = my_lstm(x_test)
        out_pt, _ = pt_lstm(x_test)
    diff = (out_my - out_pt).abs().max().item()
    print(f"    最大差异: {diff:.2e}  (bias_hh_l 处理方式略有不同)")

    # ── 7. Stateful 模式演示 ──
    print("\n[7] Stateful LSTM — 跨 batch 保持状态")
    sf_lstm = LSTM(input_size=16, hidden_size=32, stateful=True, batch_first=True)
    x1 = torch.randn(1, 10, 16)
    x2 = torch.randn(1, 10, 16)
    sf_lstm(x1)
    sf_lstm(x2)
    print("    连续两个batch, 隐藏状态自动延续 (适用于超长序列分批训练)")

    print("\n" + "=" * 60)
    print("  所有示例运行完成!")
    print("=" * 60)


def run_benchmark():
    print("=" * 60)
    print("  LSTM 性能基准测试")
    print("=" * 60)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n设备: {device}")

    configs = [
        (4, 64, 16, 32, 1),
        (4, 128, 32, 64, 2),
        (2, 256, 64, 128, 2),
        (2, 512, 128, 256, 3),
    ]

    for batch, seq_len, input_size, hidden_size, num_layers in configs:
        x = torch.randn(batch, seq_len, input_size, device=device)
        model = LSTM(input_size, hidden_size, num_layers=num_layers, batch_first=True).to(device)
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

        print(f"  batch={batch}, seq={seq_len}, in={input_size}, hid={hidden_size}, layers={num_layers} → {elapsed:.2f} ms/iter")

    print("\n基准测试完成!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LSTM 长短期记忆网络实现")
    parser.add_argument("--benchmark", action="store_true", help="运行性能基准测试")
    args = parser.parse_args()

    if args.benchmark:
        run_benchmark()
    else:
        run_demo()
