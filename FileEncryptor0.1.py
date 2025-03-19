import tkinter as tk
from tkinter import filedialog, messagebox
import os
import random
import struct


class FileEncryptor:
    def __init__(self, root):
        self.root = root
        self.root.title("文件加密软件")
        self.root.geometry("400x200")
        self.root.resizable(False, False)

        # 创建UI元素
        self.create_ui()

    def create_ui(self):
        # 文件路径标签和输入框
        self.path_label = tk.Label(self.root, text="选择文件：")
        self.path_label.pack(pady=5)

        self.path_entry = tk.Entry(self.root, width=40)
        self.path_entry.pack()

        # 选择文件按钮
        self.select_button = tk.Button(self.root, text="选择文件", command=self.select_file)
        self.select_button.pack(pady=5)

        # 密码标签和输入框
        self.password_label = tk.Label(self.root, text="输入密码：")
        self.password_label.pack(pady=5)

        self.password_entry = tk.Entry(self.root, show="*", width=20)
        self.password_entry.pack()

        # 加密按钮
        self.encrypt_button = tk.Button(self.root, text="加密文件", command=self.encrypt_file)
        self.encrypt_button.pack(pady=5)

        # 解密按钮
        self.decrypt_button = tk.Button(self.root, text="解密文件", command=self.decrypt_file)
        self.decrypt_button.pack(pady=5)

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, file_path)

    def custom_encrypt(self, data, password):
        # 使用密码生成一个随机种子
        random.seed(len(password) * sum(ord(c) for c in password))

        # 生成一个随机密钥
        key = [random.randint(0, 255) for _ in range(len(data))]

        # 将密钥转换为字节
        key_bytes = bytes(key)

        # 使用异或操作进行加密
        encrypted_data = bytes([d ^ k for d, k in zip(data, key_bytes)])

        # 将密钥和加密后数据一起返回
        return key_bytes + encrypted_data

    def custom_decrypt(self, data, password):
        # 密钥长度存储在前4个字节中
        if len(data) < 4:
            messagebox.showerror("错误", "无效的加密文件")
            return None

        # 提取密钥长度
        key_length = struct.unpack('<I', data[:4])[0]

        # 提取密钥和加密数据
        key_bytes = data[4:4 + key_length]
        encrypted_data = data[4 + key_length:]

        # 使用密码生成一个随机种子
        random.seed(len(password) * sum(ord(c) for c in password))

        # 重新生成原始密钥
        regenerated_key = [random.randint(0, 255) for _ in range(key_length)]

        # 检查密钥是否匹配
        if bytes(regenerated_key) != key_bytes:
            messagebox.showerror("错误", "密码错误或文件已损坏")
            return None

        # 使用异或操作进行解密
        decrypted_data = bytes([d ^ k for d, k in zip(encrypted_data, key_bytes)])
        return decrypted_data

    def encrypt_file(self):
        file_path = self.path_entry.get()
        password = self.password_entry.get()

        if not file_path:
            messagebox.showerror("错误", "请选择文件")
            return

        if not password:
            messagebox.showerror("错误", "请输入密码")
            return

        try:
            # 读取文件内容
            with open(file_path, 'rb') as file:
                data = file.read()

            # 加密数据
            encrypted_data = self.custom_encrypt(data, password)

            # 写入加密后的文件
            encrypted_file_path = file_path + ".enc"
            with open(encrypted_file_path, 'wb') as encrypted_file:
                # 写入密钥长度和加密数据
                encrypted_file.write(struct.pack('<I', len(encrypted_data) - len(data)) + encrypted_data)

            messagebox.showinfo("成功", f"文件已加密并保存为：{encrypted_file_path}")

        except Exception as e:
            messagebox.showerror("错误", f"加密文件时出错：{str(e)}")

    def decrypt_file(self):
        file_path = self.path_entry.get()
        password = self.password_entry.get()

        if not file_path:
            messagebox.showerror("错误", "请选择文件")
            return

        if not password:
            messagebox.showerror("错误", "请输入密码")
            return

        try:
            # 读取加密文件内容
            with open(file_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()

            # 解密数据
            decrypted_data = self.custom_decrypt(encrypted_data, password)

            if decrypted_data is None:
                return

            # 写入解密后的文件
            decrypted_file_path = os.path.splitext(file_path)[0]
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)

            messagebox.showinfo("成功", f"文件已解密并保存为：{decrypted_file_path}")

        except Exception as e:
            messagebox.showerror("错误", f"解密文件时出错：{str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptor(root)
    root.mainloop()