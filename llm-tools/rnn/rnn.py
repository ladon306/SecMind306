"""
Vanilla RNN 循环神经网络实现
============================

包含:
  1. RNNCell — 单步 RNN 单元
  2. RNN     — 多层双向 RNN

核心公式:
  h_t = tanh(W_ih · x_t + b_ih + W_hh · h_{t-1} + b_hh)

关键概念:
  - 隐藏状态 h_t 是网络的"记忆", 携带历史信息
  - BPTT (Backpropagation Through Time): 将RNN按时间步展开后用标准反向传播
  - 梯度消失: 长序列中梯度经反复乘以 W_hh 后趋近于0, 导致远距依赖无法学习

用法:
  python rnn.py              # 运行示例
  python rnn.py --benchmark  # 性能基准测试
"""

import argparse
import time

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence


# ──────────────────────────────────────────────
# 1. RNN 单元
# ──────────────────────────────────────────────
class RNNCell(nn.Module):
    """
    单步 Vanilla RNN 单元

    h_t = nonlinearity(W_ih · x_t + b_ih + W_hh · h_{t-1} + b_hh)

    Args:
        input_size:   输入特征维度
        hidden_size:  隐藏状态维度
        bias:         是否使用偏置
        nonlinearity: 激活函数 'tanh' 或 'relu'
    """

    def __init__(self, input_size, hidden_size, bias=True, nonlinearity="tanh"):
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.nonlinearity = nonlinearity

        self.weight_ih = nn.Parameter(torch.Tensor(input_size, hidden_size))
        self.weight_hh = nn.Parameter(torch.Tensor(hidden_size, hidden_size))
        if bias:
            self.bias_ih = nn.Parameter(torch.Tensor(hidden_size))
            self.bias_hh = nn.Parameter(torch.Tensor(hidden_size))
        else:
            self.register_parameter("bias_ih", None)
            self.register_parameter("bias_hh", None)

        self.reset_parameters()

    def reset_parameters(self):
        nn.init.xavier_uniform_(self.weight_ih)
        nn.init.orthogonal_(self.weight_hh)
        if self.bias_ih is not None:
            nn.init.zeros_(self.bias_ih)
            nn.init.zeros_(self.bias_hh)

    def forward(self, x_t, h_prev):
        """
        Args:
            x_t:    (batch, input_size)  当前时间步输入
            h_prev: (batch, hidden_size) 上一时间步隐藏状态

        Returns:
            h_t: (batch, hidden_size) 当前隐藏状态
        """
        gates = x_t @ self.weight_ih + self.bias_ih + h_prev @ self.weight_hh + self.bias_hh
        if self.nonlinearity == "tanh":
            return torch.tanh(gates)
        else:
            return F.relu(gates)


# ──────────────────────────────────────────────
# 2. 多层 RNN
# ──────────────────────────────────────────────
class RNN(nn.Module):
    """
    多层 (双向) RNN

    - 堆叠: 第 i 层输出作为第 i+1 层输入
    - 双向: 正向 + 反向隐藏状态拼接
    - 支持 packed sequence (变长序列)

    Args:
        input_size:    输入特征维度
        hidden_size:   隐藏状态维度
        num_layers:    层数
        nonlinearity:  'tanh' 或 'relu'
        batch_first:   输入是否 (batch, seq, feature) 格式
        bidirectional: 是否双向
    """

    def __init__(self, input_size, hidden_size, num_layers=1,
                 nonlinearity="tanh", batch_first=False, bidirectional=False):
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.batch_first = batch_first
        self.bidirectional = bidirectional
        self.num_directions = 2 if bidirectional else 1

        # 构建各层 RNNCell
        self.cells = nn.ModuleList()
        for layer in range(num_layers):
            layer_input_size = input_size if layer == 0 else hidden_size * self.num_directions
            # 正向
            self.cells.append(RNNCell(layer_input_size, hidden_size, nonlinearity=nonlinearity))
            # 反向
            if bidirectional:
                self.cells.append(RNNCell(layer_input_size, hidden_size, nonlinearity=nonlinearity))

    def _cell_index(self, layer, direction):
        return layer * self.num_directions + direction

    def forward(self, input, hx=None):
        """
        Args:
            input: (seq_len, batch, input_size) 或 (batch, seq_len, input_size)
            hx:    (num_layers * num_directions, batch, hidden_size) 初始隐藏状态

        Returns:
            output: (seq_len, batch, hidden_size * num_directions)
            hx:     (num_layers * num_directions, batch, hidden_size)
        """
        if self.batch_first:
            input = input.transpose(0, 1)

        seq_len, batch_size, _ = input.shape

        if hx is None:
            hx = torch.zeros(self.num_layers * self.num_directions, batch_size,
                             self.hidden_size, device=input.device, dtype=input.dtype)

        # 逐层处理
        layer_input = input
        final_hx = []
        for layer in range(self.num_layers):
            # ── 正向 ──
            fwd_idx = self._cell_index(layer, 0)
            fwd_cell = self.cells[fwd_idx]
            h_fwd = hx[fwd_idx]
            fwd_outputs = []
            for t in range(seq_len):
                h_fwd = fwd_cell(layer_input[t], h_fwd)
                fwd_outputs.append(h_fwd)
            fwd_output = torch.stack(fwd_outputs, dim=0)
            final_hx.append(h_fwd)

            # ── 反向 ──
            if self.bidirectional:
                bwd_idx = self._cell_index(layer, 1)
                bwd_cell = self.cells[bwd_idx]
                h_bwd = hx[bwd_idx]
                bwd_outputs = []
                for t in range(seq_len - 1, -1, -1):
                    h_bwd = bwd_cell(layer_input[t], h_bwd)
                    bwd_outputs.append(h_bwd)
                bwd_output = torch.stack(bwd_outputs[::-1], dim=0)
                final_hx.append(h_bwd)
                layer_input = torch.cat([fwd_output, bwd_output], dim=-1)
            else:
                layer_input = fwd_output

        output = layer_input
        hx_out = torch.stack(final_hx, dim=0)

        if self.batch_first:
            output = output.transpose(0, 1)

        return output, hx_out


# ──────────────────────────────────────────────
# 示例 & 测试
# ──────────────────────────────────────────────
def run_demo():
    print("=" * 60)
    print("  Vanilla RNN 循环神经网络 示例")
    print("=" * 60)

    torch.manual_seed(42)

    # ── 1. 基础序列处理 ──
    print("\n[1] 基础序列处理 (seq_len=20, input_size=16, hidden_size=32)")
    rnn = RNN(input_size=16, hidden_size=32, num_layers=1, batch_first=True)
    x = torch.randn(2, 20, 16)
    output, hx = rnn(x)
    print(f"    输入:  {x.shape}")
    print(f"    输出:  {output.shape}")
    print(f"    隐藏:  {hx.shape}")

    # ── 2. 双向 RNN ──
    print("\n[2] 双向 RNN")
    birnn = RNN(input_size=16, hidden_size=32, bidirectional=True, batch_first=True)
    out_bi, hx_bi = birnn(x)
    print(f"    输出:  {out_bi.shape}  (hidden_size * 2)")
    print(f"    隐藏:  {hx_bi.shape}  (num_layers * 2)")

    # ── 3. 多层 RNN ──
    print("\n[3] 3 层 RNN")
    deep_rnn = RNN(input_size=16, hidden_size=32, num_layers=3, batch_first=True)
    out_deep, hx_deep = deep_rnn(x)
    print(f"    输出:  {out_deep.shape}")
    print(f"    隐藏:  {hx_deep.shape}")

    # ── 4. 与 PyTorch nn.RNN 对比验证 ──
    print("\n[4] 与 PyTorch nn.RNN 对比验证")
    my_rnn = RNN(input_size=16, hidden_size=32, num_layers=2, batch_first=True)
    pt_rnn = nn.RNN(input_size=16, hidden_size=32, num_layers=2, batch_first=True)
    # 拷贝权重使两者一致
    for layer in range(2):
        pt_rnn.weight_ih_l[layer].data = my_rnn.cells[layer * 1].weight_ih.t().data
        pt_rnn.weight_hh_l[layer].data = my_rnn.cells[layer * 1].weight_hh.t().data
        pt_rnn.bias_ih_l[layer].data = my_rnn.cells[layer * 1].bias_ih.data
        pt_rnn.bias_hh_l[layer].data = my_rnn.cells[layer * 1].bias_hh.data
    x_test = torch.randn(1, 10, 16)
    with torch.no_grad():
        out_my, _ = my_rnn(x_test)
        out_pt, _ = pt_rnn(x_test)
    diff = (out_my - out_pt).abs().max().item()
    print(f"    最大差异: {diff:.2e}  (应接近0)")

    # ── 5. 梯度消失实验: RNN vs LSTM ──
    print("\n[5] 梯度消失实验 — Vanilla RNN vs LSTM (序列长度=200)")
    seq_len_long = 200
    x_long = torch.randn(1, seq_len_long, 16)
    target_long = torch.randn(1, seq_len_long, 32)

    rnn_model = RNN(input_size=16, hidden_size=32, batch_first=True)
    lstm_model = nn.LSTM(input_size=16, hidden_size=32, batch_first=True)

    out_rnn, _ = rnn_model(x_long)
    out_lstm, _ = lstm_model(x_long)

    loss_rnn = F.mse_loss(out_rnn, target_long)
    loss_lstm = F.mse_loss(out_lstm, target_long)
    loss_rnn.backward()
    loss_lstm.backward()

    rnn_grad = rnn_model.cells[0].weight_hh.grad
    lstm_grad = lstm_model.weight_hh_l0.grad

    print(f"    RNN  W_hh 梯度范数:  {rnn_grad.norm().item():.6e}")
    print(f"    LSTM W_hh 梯度范数:  {lstm_grad.norm().item():.6e}")
    ratio = rnn_grad.norm().item() / (lstm_grad.norm().item() + 1e-12)
    print(f"    RNN/LSTM 梯度比:     {ratio:.4f}  (远小于1说明RNN梯度消失严重)")
    print("    → 原因: BPTT中梯度反复乘以W_hh, |λ|<1时呈指数衰减")
    print("    → LSTM通过加性更新c_t = f⊙c_{t-1} + i⊙g̃ 避免了此问题")

    print("\n" + "=" * 60)
    print("  所有示例运行完成!")
    print("=" * 60)


def run_benchmark():
    print("=" * 60)
    print("  Vanilla RNN 性能基准测试")
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
        model = RNN(input_size, hidden_size, num_layers=num_layers, batch_first=True).to(device)
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
    parser = argparse.ArgumentParser(description="Vanilla RNN 循环神经网络实现")
    parser.add_argument("--benchmark", action="store_true", help="运行性能基准测试")
    args = parser.parse_args()

    if args.benchmark:
        run_benchmark()
    else:
        run_demo()
