import tkinter as tk
from tkinter import filedialog, messagebox, Scrollbar, Frame
import rsa
import time
from gmpy2 import gcdext, powmod
from libnum import n2s

class RsaApp:

    def __init__(self, master):
        self.master = master
        self.master.title("RSA加密解密器")
        self.master.geometry("650x500")  # 初始窗口大小，调整为合适的大小
        self.master.resizable(True, True)  # 允许窗口大小调整

        # 主布局框架
        main_frame = Frame(master)
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)

        # 密钥生成方式
        self.key_gen_method_var = tk.StringVar(value='auto')
        key_gen_frame = Frame(main_frame)
        key_gen_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        tk.Label(key_gen_frame, text="选择密钥生成方式:").grid(row=0, column=0, sticky="w")
        tk.Radiobutton(key_gen_frame, text="自动生成", variable=self.key_gen_method_var, value='auto',
                       command=self.toggle_key_inputs).grid(row=0, column=1, sticky="w")
        tk.Radiobutton(key_gen_frame, text="手动输入", variable=self.key_gen_method_var, value='manual',
                       command=self.toggle_key_inputs).grid(row=0, column=2, sticky="w")

        # 模数比特数选择
        self.bit_size_var = tk.IntVar(value=128)
        tk.Label(main_frame, text="选择模数比特数:").grid(row=1, column=0, sticky="w", padx=5)
        tk.OptionMenu(main_frame, self.bit_size_var, 128, 256, 512, 1024, 2048).grid(row=1, column=1, sticky="ew")

        # 手动输入公私钥
        tk.Label(main_frame, text="公钥:").grid(row=2, column=0, sticky="nw", padx=5)
        self.pub_key_entry = tk.Text(main_frame, height=4, wrap=tk.WORD)
        self.pub_key_entry.grid(row=2, column=1, sticky="nsew", padx=5, pady=5)

        tk.Label(main_frame, text="私钥:").grid(row=3, column=0, sticky="nw", padx=5)
        self.priv_key_entry = tk.Text(main_frame, height=4, wrap=tk.WORD)
        self.priv_key_entry.grid(row=3, column=1, sticky="nsew", padx=5, pady=5)

        # 输入和输出方式选择
        self.input_method_var = tk.StringVar(value='keyboard')
        tk.Label(main_frame, text="选择输入方式:").grid(row=4, column=0, sticky="w", padx=5)
        input_frame = Frame(main_frame)
        input_frame.grid(row=4, column=1, sticky="w")
        tk.Radiobutton(input_frame, text="键盘输入", variable=self.input_method_var, value='keyboard').grid(row=0, column=0)
        tk.Radiobutton(input_frame, text="文件输入", variable=self.input_method_var, value='file').grid(row=0, column=1)

        self.output_method_var = tk.StringVar(value='screen')
        tk.Label(main_frame, text="选择输出方式:").grid(row=5, column=0, sticky="w", padx=5)
        output_frame = Frame(main_frame)
        output_frame.grid(row=5, column=1, sticky="w")
        tk.Radiobutton(output_frame, text="屏幕输出", variable=self.output_method_var, value='screen').grid(row=0, column=0)
        tk.Radiobutton(output_frame, text="文件输出", variable=self.output_method_var, value='file').grid(row=0, column=1)

        # 输入框
        tk.Label(main_frame, text="输入内容:").grid(row=6, column=0, sticky="nw", padx=5)
        self.in_entry = tk.Text(main_frame, height=5, wrap=tk.WORD)
        self.in_entry.grid(row=6, column=1, sticky="nsew", padx=5, pady=5)

        # 输出框
        tk.Label(main_frame, text="输出内容:").grid(row=7, column=0, sticky="nw", padx=5)
        self.out_entry = tk.Text(main_frame, height=5, wrap=tk.WORD)
        self.out_entry.grid(row=7, column=1, sticky="nsew", padx=5, pady=5)

        # 操作按钮
        button_frame = Frame(main_frame)
        button_frame.grid(row=8, column=1, sticky="ew", padx=5, pady=5)
        tk.Button(button_frame, text="生成密钥", command=self.generate_keys).grid(row=0, column=0, padx=5)
        tk.Button(button_frame, text="加密", command=self.encode_click).grid(row=0, column=1, padx=5)
        tk.Button(button_frame, text="解密", command=self.decode_click).grid(row=0, column=2, padx=5)
        tk.Button(button_frame, text="选择文件", command=self.select_file).grid(row=0, column=3, padx=5)

        # 调整网格权重，使控件自适应窗口大小
        main_frame.grid_rowconfigure(2, weight=1)  # 公钥文本框
        main_frame.grid_rowconfigure(3, weight=1)  # 私钥文本框
        main_frame.grid_rowconfigure(6, weight=1)  # 输入框
        main_frame.grid_rowconfigure(7, weight=1)  # 输出框
        main_frame.grid_columnconfigure(1, weight=1)  # 主要内容列扩展

        # 初始化生成密钥
        self.generate_keys()
        self.common_modulus_frame = None

        # 创建加解密工具界面
        self.create_common_modulus_interface()

    def toggle_common_modulus_interface(self):
        if self.common_modulus_frame is None:
            self.create_common_modulus_interface()
        else:
            self.destroy_common_modulus_interface()

    def toggle_key_inputs(self):
        state = tk.NORMAL if self.key_gen_method_var.get() == 'manual' else tk.DISABLED
        self.pub_key_entry.config(state=state)
        self.priv_key_entry.config(state=state)

    def generate_keys(self):
        if self.key_gen_method_var.get() == 'auto':
            bit_size = self.bit_size_var.get()
            self.pubkey, self.privkey = rsa.newkeys(bit_size)
            self.display_keys()
        else:
            try:
                self.pubkey = rsa.PublicKey.load_pkcs1(self.pub_key_entry.get('1.0', tk.END).strip().encode('utf-8'))
                self.privkey = rsa.PrivateKey.load_pkcs1(self.priv_key_entry.get('1.0', tk.END).strip().encode('utf-8'))
                self.display_keys()
            except Exception as e:
                messagebox.showerror("错误", str(e))

    def display_keys(self):
        """显示公钥和私钥"""
        self.pub_key_entry.delete('1.0', tk.END)
        self.pub_key_entry.insert('1.0', self.pubkey.save_pkcs1().decode('utf-8'))

        self.priv_key_entry.delete('1.0', tk.END)
        self.priv_key_entry.insert('1.0', self.privkey.save_pkcs1().decode('utf-8'))

    def select_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            with open(filename, 'r') as file:
                self.in_entry.delete('1.0', tk.END)
                self.in_entry.insert('1.0', file.read())

    def encode_click(self):
        input_text = self.get_input()
        if input_text:
            try:
                start_time = time.time()
                encrypted_integer = int.from_bytes(rsa.encrypt(input_text.encode('utf-8'), self.pubkey), byteorder='big')
                end_time = time.time()
                result = f"加密结果（数字形式）:\n{encrypted_integer}\n\n加密时间: {end_time - start_time:.6f}秒"
                self.output_result(result, 'encrypted.txt')
            except Exception as e:
                messagebox.showerror("错误", str(e))

    def decode_click(self):
        input_text = self.get_input()
        priv_key_str = self.priv_key_entry.get('1.0', tk.END).strip()
        if input_text and priv_key_str:
            try:
                encrypted_bytes = int(input_text).to_bytes((int(input_text).bit_length() + 7) // 8, byteorder='big')
                privkey = rsa.PrivateKey.load_pkcs1(priv_key_str.encode('utf-8'))
                start_time = time.time()
                decrypted_text = rsa.decrypt(encrypted_bytes, privkey).decode('utf-8')
                end_time = time.time()
                result = f"解密结果:\n{decrypted_text}\n\n解密时间: {end_time - start_time:.6f}秒"
                self.output_result(result, 'decrypted.txt')
            except Exception as e:
                messagebox.showerror("错误", str(e))

    def get_input(self):
        """从输入框获取内容"""
        if self.input_method_var.get() == 'keyboard':
            return self.in_entry.get('1.0', tk.END).strip()
        elif self.input_method_var.get() == 'file':
            filename = filedialog.askopenfilename()
            if filename:
                with open(filename, 'r') as file:
                    return file.read().strip()
        return ""

    def output_result(self, result, filename=None):
        self.out_entry.delete('1.0', tk.END)
        self.out_entry.insert('1.0', result)
        if self.output_method_var.get() == 'file' and filename:
            with open(filename, 'w') as file:
                file.write(result)

    def create_common_modulus_interface(self):
        self.common_modulus_frame = tk.Frame(self.master)
        self.common_modulus_frame.grid(row=9, column=0, columnspan=2, sticky="nsew")

        tk.Label(self.common_modulus_frame, text="模数 n:").grid(row=0, column=0, sticky="e")
        self.entry_n = tk.Entry(self.common_modulus_frame)
        self.entry_n.grid(row=0, column=1)
        tk.Label(self.common_modulus_frame, text="密文 c1:").grid(row=1, column=0, sticky="e")
        self.entry_c1 = tk.Entry(self.common_modulus_frame)
        self.entry_c1.grid(row=1, column=1)
        tk.Label(self.common_modulus_frame, text="密文 c2:").grid(row=2, column=0, sticky="e")
        self.entry_c2 = tk.Entry(self.common_modulus_frame)
        self.entry_c2.grid(row=2, column=1)
        tk.Label(self.common_modulus_frame, text="公钥指数 e1:").grid(row=3, column=0, sticky="e")
        self.entry_e1 = tk.Entry(self.common_modulus_frame)
        self.entry_e1.grid(row=3, column=1)
        tk.Label(self.common_modulus_frame, text="公钥指数 e2:").grid(row=4, column=0, sticky="e")
        self.entry_e2 = tk.Entry(self.common_modulus_frame)
        self.entry_e2.grid(row=4, column=1)

        # 解密结果显示框
        tk.Label(self.common_modulus_frame, text="解密结果:").grid(row=5, column=0, sticky="e")
        self.entry_result = tk.Entry(self.common_modulus_frame)
        self.entry_result.grid(row=5, column=1)

        tk.Button(self.common_modulus_frame, text="解密", command=self.decrypt_common_modulus).grid(row=6, column=0, columnspan=2)
    
    def decrypt_common_modulus(self):
        try:
            n = int(self.entry_n.get())
            c1 = int(self.entry_c1.get())
            c2 = int(self.entry_c2.get())
            e1 = int(self.entry_e1.get())
            e2 = int(self.entry_e2.get())

            # 解密消息
            s = gcdext(e1, e2)
            m = int(pow(c1, s[1], n) * pow(c2, s[2], n) % n)
            result = n2s(m)
            self.entry_result.delete(0, tk.END)
            self.entry_result.insert(0, result)
        except ValueError:
            messagebox.showerror("输入错误", "请输入有效的数字！")

# 启动主窗口
root = tk.Tk()
app = RsaApp(root)
root.mainloop()
