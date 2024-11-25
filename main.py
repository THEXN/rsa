import tkinter as tk
from tkinter import filedialog, messagebox, Scrollbar, Frame, Toplevel, Label, Button, Canvas, ttk
import rsa
import time
from gmpy2 import gcdext, powmod
from libnum import n2s
import base64
from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder as der_encoder
from math import gcd
from PIL import Image, ImageTk, ImageDraw
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import sys
import os


def resource_path(relative_path):
    """ 获取资源的绝对路径，适用于 dev 和 PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# 公钥 PEM 格式生成函数
# region
class RSAPublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer())
    )

def create_pem_public_key(e, n):
    rsa_pub_key = RSAPublicKey()
    rsa_pub_key.setComponentByName('modulus', n)
    rsa_pub_key.setComponentByName('publicExponent', e)
    der_encoded = der_encoder.encode(rsa_pub_key)
    b64_encoded = base64.b64encode(der_encoded).decode('utf-8')
    pem_public_key = f"-----BEGIN RSA PUBLIC KEY-----\n{b64_encoded}\n-----END RSA PUBLIC KEY-----"
    return pem_public_key

# endregion
class RsaApp:

    def __init__(self, master):
        self.master = master
        self.master.title("RSA加密解密器")
        self.master.geometry("650x600")  # 初始窗口大小
        self.master.resizable(True, True)  # 允许窗口大小调整

        # 主布局框架
        main_frame = Frame(master)
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)

        # 密钥生成方式
        self.key_gen_method_var = tk.StringVar(value='auto')
        key_gen_frame = Frame(main_frame)
        key_gen_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        tk.Label(key_gen_frame, text="选择密钥生成方式:").grid(row=0, column=0, sticky="w")
        tk.Radiobutton(key_gen_frame, text="自动生成", variable=self.key_gen_method_var, value='auto',
                       command=self.toggle_key_inputs).grid(row=0, column=1, sticky="w")
        tk.Radiobutton(key_gen_frame, text="手动输入", variable=self.key_gen_method_var, value='manual',
                       command=self.toggle_key_inputs).grid(row=0, column=2, sticky="w")

        # 模数比特数选择
        self.bit_size_var = tk.IntVar(value=128)
        tk.Label(main_frame, text="选择模数比特数:").grid(row=1, column=0, sticky="w", padx=5)
        tk.OptionMenu(main_frame, self.bit_size_var, 128, 256, 512, 1024, 2048).grid(row=1, column=1, sticky="ew")

        # 手动输入 e 和 n
        tk.Label(main_frame, text="模数 n:").grid(row=2, column=0, sticky="w", padx=5)
        self.n_entry = tk.Entry(main_frame, state="disabled")
        self.n_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)

        tk.Label(main_frame, text="指数 e:").grid(row=3, column=0, sticky="w", padx=5)
        self.e_entry = tk.Entry(main_frame, state="disabled")
        self.e_entry.grid(row=3, column=1, sticky="ew", padx=5, pady=5)

        # 公私钥显示框
        tk.Label(main_frame, text="公钥:").grid(row=4, column=0, sticky="nw", padx=5)
        self.pub_key_entry = tk.Text(main_frame, height=4, wrap=tk.WORD)
        self.pub_key_entry.grid(row=4, column=1, sticky="nsew", padx=5, pady=5)

        tk.Label(main_frame, text="私钥:").grid(row=5, column=0, sticky="nw", padx=5)
        self.priv_key_entry = tk.Text(main_frame, height=4, wrap=tk.WORD)
        self.priv_key_entry.grid(row=5, column=1, sticky="nsew", padx=5, pady=5)



        
        tk.Label(main_frame, text="选择输出方式:").grid(row=7, column=0, sticky="w", padx=5)
        output_frame = Frame(main_frame)
        output_frame.grid(row=7, column=1, sticky="w")
        self.output_method_var = tk.StringVar(value='screen')
        tk.Radiobutton(output_frame, text="屏幕输出", variable=self.output_method_var, value='screen').grid(row=0, column=0)
        tk.Radiobutton(output_frame, text="文件输出", variable=self.output_method_var, value='file').grid(row=0, column=1)

        # 输入框
        tk.Label(main_frame, text="输入内容:").grid(row=8, column=0, sticky="nw", padx=5)
        self.in_entry = tk.Text(main_frame, height=5, wrap=tk.WORD)
        self.in_entry.grid(row=8, column=1, sticky="nsew", padx=5, pady=5)

        # 输出框
        tk.Label(main_frame, text="输出内容:").grid(row=9, column=0, sticky="nw", padx=5)
        self.out_entry = tk.Text(main_frame, height=5, wrap=tk.WORD)
        self.out_entry.grid(row=9, column=1, sticky="nsew", padx=5, pady=5)

        # 操作按钮
        button_frame = Frame(main_frame)
        button_frame.grid(row=10, column=0, columnspan=2, sticky="ew", padx=5, pady=5)  # 占两列，让按钮居中显示

        # 在 button_frame 中添加按钮
        tk.Button(button_frame, text="生成密钥", command=self.generate_keys).grid(row=0, column=0, padx=5)
        tk.Button(button_frame, text="加密", command=self.encode_click).grid(row=0, column=1, padx=5)
        tk.Button(button_frame, text="解密", command=self.decode_click).grid(row=0, column=2, padx=5)
        tk.Button(button_frame, text="选择文件", command=self.select_file).grid(row=0, column=3, padx=5)
        tk.Button(button_frame, text="共模攻击", command=self.toggle_common_modulus_interface).grid(row=0, column=4, padx=5)
        tk.Button(button_frame, text="循环攻击", command=self.toggle_private_key_interface).grid(row=0, column=5, padx=5)
        tk.Button(button_frame, text="关于", command=self.show_about).grid(row=0, column=6, padx=5)

        
        # 调整网格权重
        main_frame.grid_rowconfigure(4, weight=1)  # 公钥文本框
        main_frame.grid_rowconfigure(5, weight=1)  # 私钥文本框
        main_frame.grid_rowconfigure(8, weight=1)  # 输入框
        main_frame.grid_rowconfigure(9, weight=1)  # 输出框
        main_frame.grid_columnconfigure(1, weight=1)  # 主要内容列扩展

        # 初始化为 None，第一次点击时再创建
        self.common_modulus_frame = None
        self.private_key_frame = None
        # 初始化生成密钥
        self.generate_keys()

    # 关于
    #region
    def show_about(self):
        about_window = Toplevel(self.master)
        about_window.title("关于")
        about_window.geometry("374x320")

        # 获取屏幕宽高，居中显示窗口
        screen_width = about_window.winfo_screenwidth()
        screen_height = about_window.winfo_screenheight()
        position_top = int(screen_height / 2 - 320 / 2)
        position_left = int(screen_width / 2 - 374 / 2)
        about_window.geometry(f"374x320+{position_left}+{position_top}")

        # 设置窗口图标
        icon_path = resource_path('logo.ico')
        about_window.iconbitmap(icon_path)

        # 加载背景图
        jpg_path = resource_path('tr.jpg')
        background_image = Image.open(jpg_path)
        # 转换为 Tkinter 可用的图片
        background_photo = ImageTk.PhotoImage(background_image)

        # 使用 Canvas 显示背景
        canvas = tk.Canvas(about_window, width=374, height=320, highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        canvas.create_image(0, 0, anchor="nw", image=background_photo)
        canvas.image = background_photo

        # 添加文字控件
        # 添加文字（带阴影效果）
        canvas.create_text(187, 92, text="作者: 不醒人室", font=("Arial", 14, "bold"), fill="black")  # 阴影
        canvas.create_text(185, 90, text="作者: 不醒人室", font=("Arial", 14, "bold"), fill="white")  # 主文字

        canvas.create_text(187, 122, text="版本: 1.1.2", font=("Arial", 12), fill="black")  # 阴影
        canvas.create_text(185, 120, text="版本: 1.1.2", font=("Arial", 12), fill="white")  # 主文字

        canvas.create_text(187, 152, text="GitHub:", font=("Arial", 12), fill="black")  # 阴影
        canvas.create_text(185, 150, text="GitHub:", font=("Arial", 12), fill="white")  # 主文字


        # 添加 GitHub 按钮
        github_button = ttk.Button(about_window, text="GitHub仓库", command=lambda: self.open_github("https://github.com/THEXN/rsa"))
        canvas.create_window(185, 190, window=github_button)


    def open_github(self, url):
        import webbrowser
        webbrowser.open(url)

    #endregion
        
    # rsa加密解密算法逻辑
    # region
    def toggle_common_modulus_interface(self):
        if self.common_modulus_frame is None:
            self.create_common_modulus_interface()
        else:
            self.destroy_common_modulus_interface()

    def generate_keys(self):
        if self.key_gen_method_var.get() == 'auto':
            # 自动生成模式，生成新的一对公钥和私钥
            bit_size = self.bit_size_var.get()
            self.pubkey, self.privkey = rsa.newkeys(bit_size)
            self.display_keys()
        else:
            # 手动模式，仅生成公钥，不覆盖现有的私钥
            try:
                e = int(self.e_entry.get().strip())
                n = int(self.n_entry.get().strip())
                self.pubkey = rsa.PublicKey(n, e)
                self.display_keys()  # 显示新公钥，但保持私钥不变
            except ValueError:
                messagebox.showerror("输入错误", "请输入有效的整数 e 和 n。")
            except Exception as e:
                messagebox.showerror("错误", str(e))

    def display_keys(self):
        """显示公钥和私钥"""
        # 显示公钥
        self.pub_key_entry.delete('1.0', 'end')
        self.pub_key_entry.insert('1.0', self.pubkey.save_pkcs1().decode('utf-8'))

        # 显示私钥，如果私钥存在
        self.priv_key_entry.delete('1.0', 'end')
        if self.privkey:
            self.priv_key_entry.insert('1.0', self.privkey.save_pkcs1().decode('utf-8'))
        else:
            self.priv_key_entry.insert('1.0', "无可用私钥")

    def toggle_key_inputs(self):
        """切换手动输入和自动生成模式"""
        if self.key_gen_method_var.get() == 'auto':
            # 自动模式下禁用手动输入框
            self.e_entry.config(state='disabled')
            self.n_entry.config(state='disabled')
        else:
            # 手动模式下启用输入框
            self.e_entry.config(state='normal')
            self.n_entry.config(state='normal')

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
                start_time = time.perf_counter()
                encrypted_integer = int.from_bytes(rsa.encrypt(input_text.encode('utf-8'), self.pubkey), byteorder='big')
                end_time = time.perf_counter()
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
                start_time = time.perf_counter()
                decrypted_text = rsa.decrypt(encrypted_bytes, privkey).decode('utf-8')
                end_time = time.perf_counter()
                result = f"解密结果:\n{decrypted_text}\n\n解密时间: {end_time - start_time:.6f}秒"
                self.output_result(result, 'decrypted.txt')
            except Exception as e:
                messagebox.showerror("错误", str(e))

    def get_input(self):
        """从输入框获取内容"""
        return self.in_entry.get('1.0', tk.END).strip() 

    def output_result(self, result, filename=None):
        self.out_entry.delete('1.0', tk.END)
        self.out_entry.insert('1.0', result)
        if self.output_method_var.get() == 'file' and filename:
            with open(filename, 'w') as file:
                file.write(result)

    def save_to_file(self, filename, content):
        with open(filename, 'w') as file:
            file.write(content)
        messagebox.showinfo("文件保存", f"内容已保存到 {filename}")
    # endregion
    
    #共模攻击逻辑
    # region
    # 切换共模攻击界面显示与隐藏
    def toggle_common_modulus_interface(self):
        # 如果 common_modulus_frame 尚未创建，则创建
        if self.common_modulus_frame is None:
            self.create_common_modulus_interface()  # 第一次调用时创建界面

        # 确保不为空后再调用 winfo_ismapped()
        if self.common_modulus_frame and self.common_modulus_frame.winfo_ismapped():
            self.common_modulus_frame.grid_remove()  # 隐藏当前显示的共模攻击界面
        else:
            # 显示共模攻击界面，并覆盖之前的界面
            self.common_modulus_frame.grid(row=12, column=0, columnspan=2, sticky="nsew")  # 在相同的位置显示


    def create_common_modulus_interface(self):
        self.common_modulus_frame = tk.Frame(self.master)       
        # 创建共模攻击界面（初始隐藏）
        self.common_modulus_frame = tk.Frame(self.master)

        tk.Label(self.common_modulus_frame, text="模数 n:").grid(row=0, column=0, sticky="e")
        self.entry_n = tk.Entry(self.common_modulus_frame)
        self.entry_n.grid(row=0, column=1)

        tk.Label(self.common_modulus_frame, text="模数 n1:").grid(row=1, column=0, sticky="e")
        self.entry_n1 = tk.Entry(self.common_modulus_frame)
        self.entry_n1.grid(row=1, column=1)

        tk.Label(self.common_modulus_frame, text="模数 n2:").grid(row=2, column=0, sticky="e")
        self.entry_n2 = tk.Entry(self.common_modulus_frame)
        self.entry_n2.grid(row=2, column=1)

        tk.Label(self.common_modulus_frame, text="密文 c1:").grid(row=3, column=0, sticky="e")
        self.entry_c1 = tk.Entry(self.common_modulus_frame)
        self.entry_c1.grid(row=3, column=1)

        tk.Label(self.common_modulus_frame, text="密文 c2:").grid(row=4, column=0, sticky="e")
        self.entry_c2 = tk.Entry(self.common_modulus_frame)
        self.entry_c2.grid(row=4, column=1)

        tk.Label(self.common_modulus_frame, text="公钥指数 e1:").grid(row=5, column=0, sticky="e")
        self.entry_e1 = tk.Entry(self.common_modulus_frame)
        self.entry_e1.grid(row=5, column=1)

        tk.Label(self.common_modulus_frame, text="公钥指数 e2:").grid(row=6, column=0, sticky="e")
        self.entry_e2 = tk.Entry(self.common_modulus_frame)
        self.entry_e2.grid(row=6, column=1)

        # 公钥加载按钮
        tk.Button(self.common_modulus_frame, text="加载公钥1", command=self.load_public_key1).grid(row=7, column=0, padx=5, pady=5)
        tk.Button(self.common_modulus_frame, text="加载公钥2", command=self.load_public_key2).grid(row=7, column=1, padx=5, pady=5)

        # 解密结果显示框
        tk.Label(self.common_modulus_frame, text="解密结果:").grid(row=8, column=0, sticky="e")
        self.entry_result = tk.Entry(self.common_modulus_frame)
        self.entry_result.grid(row=8, column=1)

        # 解密按钮
        tk.Button(self.common_modulus_frame, text="解密", command=self.decrypt_common_modulus).grid(row=9, column=0, columnspan=2, padx=5, pady=5)

    
    def decrypt_common_modulus(self):
        try:
            n = self.entry_n.get()
            c1 = int(self.entry_c1.get())
            c2 = int(self.entry_c2.get())
            e1 = int(self.entry_e1.get())
            e2 = int(self.entry_e2.get())

            # 如果 n 不为空，直接使用 n 进行解密
            if n:
                n = int(n)  # 将输入的 n 转换为整数
            else:
                # 如果 n 为空，验证 n1 和 n2 是否相同
                n1 = int(self.entry_n1.get())
                n2 = int(self.entry_n2.get())

                if n1 != n2:
                    messagebox.showerror("错误", "模数 n1 和 n2 不相同！")
                    return
                n = n1  # 如果 n1 和 n2 相同，则使用 n1（或者 n2）作为 n

            # 解密过程
            s = gcdext(e1, e2)  # 求解 e1 和 e2 的扩展欧几里得
            m = int(pow(c1, s[1], n) * pow(c2, s[2], n) % n)  # 解密公式
            result = n2s(m)  # 转换成字符串
            self.entry_result.delete(0, tk.END)
            self.entry_result.insert(0, result)

        except ValueError:
            messagebox.showerror("输入错误", "请输入有效的数字！")

            
    def load_public_key1(self):
        """加载第一个公钥文件并解析 e1 和 n1"""
        filename = filedialog.askopenfilename(title="选择第一个公钥文件", filetypes=(("PEM 文件", "*.pem"), ("所有文件", "*.*")))
        if filename:
            try:
                with open(filename, 'rb') as f:
                    pubkey_data = f.read()
                    pubkey = rsa.PublicKey.load_pkcs1(pubkey_data)
                
                    # 将 n 填充到 n1
                    self.entry_n1.delete(0, tk.END)
                    self.entry_n1.insert(0, str(pubkey.n))
                
                    # 填充 e1
                    self.entry_e1.delete(0, tk.END)
                    self.entry_e1.insert(0, str(pubkey.e))
                
                    messagebox.showinfo("公钥1加载成功", "第一个公钥文件已加载，模数 n1 和指数 e1 已自动填充。")
            except Exception as e:
                messagebox.showerror("加载失败", f"无法解析第一个公钥文件: {e}")

    def load_public_key2(self):
        """加载第二个公钥文件并解析 e2 和 n2"""
        filename = filedialog.askopenfilename(title="选择第二个公钥文件", filetypes=(("PEM 文件", "*.pem"), ("所有文件", "*.*")))
        if filename:
            try:
                with open(filename, 'rb') as f:
                    pubkey_data = f.read()
                    pubkey = rsa.PublicKey.load_pkcs1(pubkey_data)
                
                    # 将 n 填充到 n2
                    self.entry_n2.delete(0, tk.END)
                    self.entry_n2.insert(0, str(pubkey.n))
                
                    # 填充 e2
                    self.entry_e2.delete(0, tk.END)
                    self.entry_e2.insert(0, str(pubkey.e))
                
                    messagebox.showinfo("公钥2加载成功", "第二个公钥文件已加载，模数 n2 和指数 e2 已自动填充。")
            except Exception as e:
                messagebox.showerror("加载失败", f"无法解析第二个公钥文件: {e}")

    def verify_and_set_n(self):
        """在解密前验证 n1 和 n2 一致性并设置 n"""
        n1 = self.entry_n1.get()
        n2 = self.entry_n2.get()
    
        if n1 and n2:
            if n1 == n2:
                self.entry_n.delete(0, tk.END)
                self.entry_n.insert(0, n1)
            else:
                messagebox.showerror("模数不匹配", "模数 n1 和 n2 不一致，请检查公钥文件。")
    # endregion
    
    #循环攻击逻辑
    # region
    # 切换私钥计算界面显示与隐藏
    def toggle_private_key_interface(self):
        # 如果 private_key_frame 尚未创建，则创建
        if self.private_key_frame is None:
            self.create_private_key_interface()  # 第一次调用时创建界面

        # 确保不为空后再调用 winfo_ismapped()
        if self.private_key_frame and self.private_key_frame.winfo_ismapped():
            self.private_key_frame.grid_remove()  # 隐藏当前显示的私钥计算界面
        else:
            # 显示私钥计算界面，并覆盖之前的界面
            self.private_key_frame.grid(row=12, column=0, columnspan=2, sticky="nsew")  # 在相同的位置显示


    # 创建私钥计算界面
    def create_private_key_interface(self):
        self.private_key_frame = tk.Frame(self.master)
    
        # 输入框 p
        tk.Label(self.private_key_frame, text="质数 p:").grid(row=0, column=0, sticky="e")
        self.entry_p = tk.Entry(self.private_key_frame)
        self.entry_p.grid(row=0, column=1)

        # 输入框 q
        tk.Label(self.private_key_frame, text="质数 q:").grid(row=1, column=0, sticky="e")
        self.entry_q = tk.Entry(self.private_key_frame)
        self.entry_q.grid(row=1, column=1)

        # 输入框 e
        tk.Label(self.private_key_frame, text="公钥指数 e:").grid(row=2, column=0, sticky="e")
        self.entry_e = tk.Entry(self.private_key_frame)
        self.entry_e.grid(row=2, column=1)

        # 计算按钮
        tk.Button(self.private_key_frame, text="计算私钥 d", command=self.compute_private_key).grid(row=3, column=0, padx=5, pady=5)
        tk.Button(self.private_key_frame, text="从PEM文件提取参数", command=self.extract_params_from_pem).grid(row=3, column=1, padx=5, pady=5)
        # 显示私钥 d 的输入框
        tk.Label(self.private_key_frame, text="私钥 d:").grid(row=4, column=0, sticky="e")
        self.entry_d = tk.Entry(self.private_key_frame)
        self.entry_d.grid(row=4, column=1)
        # 显示模数 n 的标签
        tk.Label(self.private_key_frame, text="模数 n:").grid(row=5, column=0, sticky="e")
        self.entry_n = tk.Entry(self.private_key_frame)
        self.entry_n.grid(row=5, column=1)

        # 显示找到的 k 值的标签
        tk.Label(self.private_key_frame, text="找到的 k:").grid(row=6, column=0, sticky="e")
        self.entry_k = tk.Entry(self.private_key_frame)
        self.entry_k.grid(row=6, column=1)

    # 计算私钥 d
    def compute_private_key(self):
        try:
            p = int(self.entry_p.get())
            q = int(self.entry_q.get())
            e = int(self.entry_e.get())
            n = p * q
            phi_n = (p - 1) * (q - 1)

            # 检查 e 和 φ(n) 是否互质
            if gcd(e, phi_n) != 1:
                messagebox.showerror("错误", "e 必须与 φ(n) 互质")
                return

            # 计算 d
            d = self.mod_inverse(e, phi_n)

            # 显示结果
            self.entry_d.delete(0, tk.END)
            self.entry_d.insert(0, str(d))
            
            self.entry_n.delete(0, tk.END)
            self.entry_n.insert(0, str(n))

        except ValueError:
            messagebox.showerror("输入错误", "请输入有效的数字！")

    # 求逆元的扩展欧几里得算法
    def mod_inverse(self, a, m):
        m0, x0, x1 = m, 0, 1
        if m == 1:
            return 0
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        if x1 < 0:
            x1 += m0
        return x1
    
        # 从PEM文件提取所有参数
    def extract_params_from_pem(self):
        # 选择PEM文件
        filename = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if not filename:
            return

        try:
            with open(filename, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,  # 如果私钥有密码保护，需要提供密码
                    backend=default_backend()
                )

            # 获取公钥
            public_key = private_key.public_key()

            # 提取公钥参数
            public_numbers = public_key.public_numbers()
            n = public_numbers.n
            e = public_numbers.e

            # 提取私钥参数
            private_numbers = private_key.private_numbers()
            d = private_numbers.d
            p = private_numbers.p
            q = private_numbers.q
            dmp1 = private_numbers.dmp1
            dmq1 = private_numbers.dmq1
            iqmp = private_numbers.iqmp

            # 显示结果
            self.entry_p.delete(0, tk.END)
            self.entry_p.insert(0, str(p))

            self.entry_q.delete(0, tk.END)
            self.entry_q.insert(0, str(q))

            self.entry_e.delete(0, tk.END)
            self.entry_e.insert(0, str(e))

            self.entry_d.delete(0, tk.END)
            self.entry_d.insert(0, str(d))

            self.entry_n.delete(0, tk.END)
            self.entry_n.insert(0, str(n))

            self.entry_k.delete(0, tk.END)
            self.entry_k.insert(0, str(iqmp))

        except Exception as e:
            messagebox.showerror("错误", f"无法解析PEM文件: {e}")
    # endregion                   
                
# 启动主窗口
root = tk.Tk()
icon_path = resource_path('logo.ico')
root.iconbitmap(icon_path)
app = RsaApp(root)
root.mainloop()
