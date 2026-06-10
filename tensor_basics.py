"""
张量基础学习 - PyTorch 张量操作入门
"""
import torch
import numpy as np

print("=" * 60)
print("PyTorch 张量基础学习")
print("=" * 60)

# ============================================================
# 1. 创建张量
# ============================================================
print("\n【1. 创建张量】")

# 从列表创建
tensor1 = torch.tensor([1, 2, 3, 4, 5])
print(f"从列表创建：{tensor1}")

# 创建 2D 张量（矩阵）
tensor2 = torch.tensor([[1, 2, 3], [4, 5, 6]])
print(f"2D 张量:\n{tensor2}")

# 创建全 0 张量
zeros = torch.zeros(3, 4)
print(f"全 0 张量 (3x4):\n{zeros}")

# 创建全 1 张量
ones = torch.ones(2, 3)
print(f"全 1 张量 (2x3):\n{ones}")

# 创建随机张量
random_tensor = torch.rand(2, 2)
print(f"随机张量 (0-1 之间):\n{random_tensor}")

# 创建指定形状的未初始化张量
empty_tensor = torch.empty(2, 3)
print(f"未初始化张量 (包含随机数据):\n{empty_tensor}")

# 从 numpy 数组转换
np_array = np.array([1, 2, 3, 4])
from_numpy = torch.from_numpy(np_array)
print(f"从 numpy 转换：{from_numpy}")

# ============================================================
# 2. 张量属性
# ============================================================
print("\n【2. 张量属性】")

tensor = torch.tensor([[1, 2, 3], [4, 5, 6]])
print(f"张量：{tensor}")
print(f"形状 (shape): {tensor.shape}")
print(f"维度 (dim): {tensor.dim()}")
print(f"元素总数 (numel): {tensor.numel()}")
print(f"数据类型 (dtype): {tensor.dtype}")
print(f"设备 (device): {tensor.device}")

# ============================================================
# 3. 张量索引和切片
# ============================================================
print("\n【3. 张量索引和切片】")

tensor = torch.tensor([[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]])
print(f"原始张量:\n{tensor}")

print(f"第一个元素：{tensor[0, 0]}")
print(f"第二行：{tensor[1, :]}")
print(f"第三列：{tensor[:, 2]}")
print(f"左上角 2x2:\n{tensor[:2, :2]}")

# ============================================================
# 4. 张量运算
# ============================================================
print("\n【4. 张量运算】")

a = torch.tensor([[1, 2], [3, 4]], dtype=torch.float32)
b = torch.tensor([[5, 6], [7, 8]], dtype=torch.float32)

print(f"a =\n{a}")
print(f"b =\n{b}")

# 加法
print(f"a + b =\n{a + b}")
print(f"torch.add(a, b) =\n{torch.add(a, b)}")

# 减法
print(f"a - b =\n{a - b}")

# 乘法（元素级）
print(f"a * b (元素级乘) =\n{a * b}")

# 矩阵乘法
print(f"a @ b (矩阵乘法) =\n{a @ b}")
print(f"torch.matmul(a, b) =\n{torch.matmul(a, b)}")

# 除法
print(f"a / b =\n{a / b}")

# 幂运算
print(f"a ** 2 =\n{a ** 2}")

# ============================================================
# 5. 张量变形
# ============================================================
print("\n【5. 张量变形】")

tensor = torch.arange(1, 13)  # 1 到 12
print(f"原始张量 (12 个元素): {tensor}")

# reshape
reshaped = tensor.reshape(3, 4)
print(f"reshape(3, 4):\n{reshaped}")

# view (类似 reshape，但要求内存连续)
viewed = tensor.view(4, 3)
print(f"view(4, 3):\n{viewed}")

# transpose (转置)
transposed = reshaped.t()
print(f"转置后:\n{transposed}")

# squeeze (移除维度为 1 的维度)
tensor_3d = torch.randn(1, 3, 1, 4)
print(f"原始形状：{tensor_3d.shape}")
squeezed = torch.squeeze(tensor_3d)
print(f"squeeze 后：{squeezed.shape}")

# unsqueeze (增加维度)
tensor_2d = torch.tensor([[1, 2, 3]])
print(f"原始形状：{tensor_2d.shape}")
unsqueezed = torch.unsqueeze(tensor_2d, 0)
print(f"unsqueeze 后：{unsqueezed.shape}")

# ============================================================
# 6. 张量拼接
# ============================================================
print("\n【6. 张量拼接】")

a = torch.tensor([[1, 2], [3, 4]], dtype=torch.float32)
b = torch.tensor([[5, 6], [7, 8]], dtype=torch.float32)

# 按行拼接 (dim=0)
cat_0 = torch.cat([a, b], dim=0)
print(f"按行拼接 (dim=0):\n{cat_0}")

# 按列拼接 (dim=1)
cat_1 = torch.cat([a, b], dim=1)
print(f"按列拼接 (dim=1):\n{cat_1}")

# stack (在新维度上堆叠)
stacked = torch.stack([a, b], dim=0)
print(f"stack 后形状：{stacked.shape}")

# ============================================================
# 7. 常用数学函数
# ============================================================
print("\n【7. 常用数学函数】")

tensor = torch.tensor([1.0, 4.0, 9.0, 16.0])
print(f"原始张量：{tensor}")

print(f"sqrt: {torch.sqrt(tensor)}")
print(f"exp: {torch.exp(tensor)}")
print(f"log: {torch.log(tensor)}")
print(f"abs: {torch.abs(torch.tensor([-1, -2, 3]))}")
print(f"sin: {torch.sin(torch.tensor([0.0, 3.14159/2]))}")
print(f"cos: {torch.cos(torch.tensor([0.0, 3.14159/2]))}")

# ============================================================
# 8. 统计函数
# ============================================================
print("\n【8. 统计函数】")

tensor = torch.tensor([[1., 2., 3.], [4., 5., 6.]])
print(f"张量:\n{tensor}")

print(f"总和：{torch.sum(tensor)}")
print(f"平均值：{torch.mean(tensor)}")
print(f"最大值：{torch.max(tensor)}")
print(f"最小值：{torch.min(tensor)}")
print(f"标准差：{torch.std(tensor)}")

# 按维度统计
print(f"每列的和：{torch.sum(tensor, dim=0)}")
print(f"每行的和：{torch.sum(tensor, dim=1)}")

# ============================================================
# 9. GPU 加速 (如果有可用 GPU)
# ============================================================
print("\n【9. GPU 加速】")

if torch.cuda.is_available():
    print("[OK] GPU 可用!")
    gpu_tensor = torch.tensor([1, 2, 3]).cuda()
    print(f"GPU 张量：{gpu_tensor}")
    print(f"GPU 设备：{gpu_tensor.device}")
    
    # 移回 CPU
    cpu_tensor = gpu_tensor.cpu()
    print(f"移回 CPU: {cpu_tensor}")
else:
    print("[INFO] GPU 不可用，使用 CPU")

print("\n" + "=" * 60)
print("张量基础学习完成!")
print("=" * 60)
