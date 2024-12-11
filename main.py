# 导入tkinter库，用于创建GUI
# 导入base64库，用于编码和解码二进制数据为文本格式
import base64
# 文件路径操作或操作系统级别的功能
import os
import sys
import time
import tkinter as tk
# 从math库导入gcd函数，用于求两个数的最大公约数
from math import e, gcd
# 从tkinter中导入特定组件
from tkinter import filedialog, messagebox, Toplevel, ttk

# 导入rsa库，用于执行RSA加密/解密操作
import rsa
# 从PIL库导入Image, ImageTk, 和 ImageDraw，用于图像处理
from PIL import Image, ImageTk
# 从cryptography.hazmat.backends库导入default_backend，用于提供默认后端实现
from cryptography.hazmat.backends import default_backend
# 从cryptography.hazmat.primitives库导入serialization，用于序列化密钥
from cryptography.hazmat.primitives import serialization
# 从gmpy2库导入gcdext（扩展欧几里得算法）和powmod（模幂运算），用于数学计算
from gmpy2 import gcdext
# 从libnum库导入n2s函数，可能用于数字到字符串的转换
from libnum import n2s
# 从pyasn1.codec.der库导入encoder，用于将ASN.1对象编码为DER格式
from pyasn1.codec.der import encoder as der_encoder
# 从pyasn1.type库导入univ和namedtype，用于ASN.1结构的定义
from pyasn1.type import univ, namedtype


def resource_path(relative_path):
    try:
        # 尝试获取由PyInstaller创建的临时文件夹路径
        # 当应用程序被PyInstaller打包时，所有资源文件都会被放置在一个临时文件夹中，
        # 并且这个文件夹的路径会被存储在_MEIPASS这个特殊变量中。
        base_path = sys._MEIPASS
    except Exception:
        # 如果没有找到_MEIPASS变量，则说明当前是在开发环境中运行
        # 或者应用程序不是通过PyInstaller打包的。
        # 在这种情况下，使用当前脚本所在的目录作为基础路径。
        base_path = os.path.abspath(".")

    # 使用os.path.join将基础路径和传入的相对路径连接起来，得到资源文件的绝对路径。
    return os.path.join(base_path, relative_path)


# 公钥 PEM 格式生成函数
# region
# 定义一个ASN.1结构体，表示RSA公钥
class RSAPublicKey(univ.Sequence):
    # 定义序列中包含的组件类型
    componentType = namedtype.NamedTypes(
        # 模数（大整数）
        namedtype.NamedType('modulus', univ.Integer()),
        # 公共指数
        namedtype.NamedType('publicExponent', univ.Integer())
    )


def create_pem_public_key(e, n):
    # 创建一个空的RSA公钥实例
    rsa_pub_key = RSAPublicKey()

    # 设置模数
    rsa_pub_key.setComponentByName('modulus', n)

    # 设置公共指数
    rsa_pub_key.setComponentByName('publicExponent', e)

    # 将ASN.1对象编码为DER格式
    der_encoded = der_encoder.encode(rsa_pub_key)

    # 对DER编码的数据进行Base64编码
    b64_encoded = base64.b64encode(der_encoded).decode('utf-8')

    # 构造PEM格式的字符串
    pem_public_key = f"-----BEGIN RSA PUBLIC KEY-----\n{b64_encoded}\n-----END RSA PUBLIC KEY-----"

    # 返回PEM格式的公钥
    return pem_public_key


# endregion
class RsaApp:

    def __init__(self, master):
        # 保存主窗口对象
        self.pubkey = None
        self.master = master

        # 设置主窗口标题
        self.master.title("RSA加密解密器")

        # 设置主窗口初始大小
        self.master.geometry("650x600")  # 初始窗口大小

        # 允许用户调整窗口大小
        self.master.resizable(True, True)  # 允许窗口大小调整

        # 创建主布局框架，并将其放置在主窗口中
        main_frame = tk.Frame(master)
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)

        # 密钥生成方式选择
        self.key_gen_method_var = tk.StringVar(value='auto')  # 默认为自动生成
        key_gen_frame = tk.Frame(main_frame)
        key_gen_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        tk.Label(key_gen_frame, text="选择密钥生成方式:").grid(row=0, column=0, sticky="w")
        tk.Radiobutton(key_gen_frame, text="自动生成", variable=self.key_gen_method_var, value='auto',
                       command=self.toggle_key_inputs).grid(row=0, column=1, sticky="w")
        tk.Radiobutton(key_gen_frame, text="手动输入", variable=self.key_gen_method_var, value='manual',
                       command=self.toggle_key_inputs).grid(row=0, column=2, sticky="w")

        # 模数比特数选择
        self.bit_size_var = tk.IntVar(value=1024)  # 默认模数比特数为128位
        tk.Label(main_frame, text="选择模数比特数:").grid(row=1, column=0, sticky="w", padx=5)
        tk.OptionMenu(main_frame, self.bit_size_var, 128, 256, 512, 1024, 2048).grid(row=1, column=1, sticky="ew")

        # 创建一个新的框架用于田字格布局
        entries_frame = tk.Frame(main_frame)
        entries_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        main_frame.grid_rowconfigure(2, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        # 模数 n 和 指数 e 的输入框
        tk.Label(entries_frame, text="模数 n:").grid(row=0, column=0, sticky="w", padx=5)
        self.n_entry = tk.Entry(entries_frame, state="disabled")  # 默认禁用
        self.n_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        tk.Label(entries_frame, text="指数 e:").grid(row=0, column=2, sticky="w", padx=5)
        self.e_entry = tk.Entry(entries_frame, state="disabled")  # 默认禁用
        self.e_entry.grid(row=0, column=3, sticky="ew", padx=5, pady=5)

        # 质数 p 和 质数 q 的输入框
        tk.Label(entries_frame, text="质数 p:").grid(row=1, column=0, sticky="w", padx=5)
        self.p_entry = tk.Entry(entries_frame, state="disabled")  # 默认禁用
        self.p_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        tk.Label(entries_frame, text="质数 q:").grid(row=1, column=2, sticky="w", padx=5)
        self.q_entry = tk.Entry(entries_frame, state="disabled")  # 默认禁用
        self.q_entry.grid(row=1, column=3, sticky="ew", padx=5, pady=5)

        # 调整网格权重，使某些行和列可以扩展
        entries_frame.grid_rowconfigure(0, weight=1)
        entries_frame.grid_rowconfigure(1, weight=1)
        entries_frame.grid_columnconfigure(1, weight=1)
        entries_frame.grid_columnconfigure(3, weight=1)

        # 公私钥显示文本框
        tk.Label(main_frame, text="公钥:").grid(row=3, column=0, sticky="nw", padx=5)
        self.pub_key_entry = tk.Text(main_frame, height=4, wrap=tk.WORD)
        self.pub_key_entry.grid(row=3, column=1, sticky="nsew", padx=5, pady=5)

        tk.Label(main_frame, text="私钥:").grid(row=4, column=0, sticky="nw", padx=5)
        self.priv_key_entry = tk.Text(main_frame, height=4, wrap=tk.WORD)
        self.priv_key_entry.grid(row=4, column=1, sticky="nsew", padx=5, pady=5)

        # 输出方式选择
        tk.Label(main_frame, text="选择输出方式:").grid(row=5, column=0, sticky="w", padx=5)
        output_frame = tk.Frame(main_frame)
        output_frame.grid(row=5, column=1, sticky="w")
        self.output_method_var = tk.StringVar(value='screen')  # 默认为屏幕输出
        tk.Radiobutton(output_frame, text="屏幕输出", variable=self.output_method_var, value='screen').grid(row=0,
                                                                                                            column=0)
        tk.Radiobutton(output_frame, text="文件输出", variable=self.output_method_var, value='file').grid(row=0,
                                                                                                          column=1)

        # 输入内容文本框
        tk.Label(main_frame, text="输入内容:").grid(row=6, column=0, sticky="nw", padx=5)
        self.in_entry = tk.Text(main_frame, height=5, wrap=tk.WORD)
        self.in_entry.grid(row=6, column=1, sticky="nsew", padx=5, pady=5)

        # 输出内容文本框
        tk.Label(main_frame, text="输出内容:").grid(row=7, column=0, sticky="nw", padx=5)
        self.out_entry = tk.Text(main_frame, height=5, wrap=tk.WORD)
        self.out_entry.grid(row=7, column=1, sticky="nsew", padx=5, pady=5)

        # 操作按钮
        button_frame = tk.Frame(main_frame)
        button_frame.grid(row=8, column=0, columnspan=2, sticky="ew", padx=5, pady=5)  # 占两列，让按钮居中显示

        # 在 button_frame 中添加按钮
        tk.Button(button_frame, text="生成密钥", command=self.generate_keys).grid(row=0, column=0, padx=5)
        tk.Button(button_frame, text="加密", command=self.encode_click).grid(row=0, column=1, padx=5)
        tk.Button(button_frame, text="解密", command=self.decode_click).grid(row=0, column=2, padx=5)
        tk.Button(button_frame, text="选择文件", command=self.select_file).grid(row=0, column=3, padx=5)
        tk.Button(button_frame, text="共模攻击", command=self.toggle_common_modulus_interface).grid(row=0, column=4,
                                                                                                    padx=5)
        tk.Button(button_frame, text="循环攻击", command=self.toggle_private_key_interface).grid(row=0, column=5,
                                                                                                 padx=5)
        tk.Button(button_frame, text="保存公私钥", command=self.save_keys).grid(row=0, column=6, padx=5)
        tk.Button(button_frame, text="关于", command=self.show_about).grid(row=0, column=7, padx=5)

        # 调整网格权重，使某些行和列可以扩展
        main_frame.grid_rowconfigure(3, weight=1)  # 公钥文本框
        main_frame.grid_rowconfigure(4, weight=1)  # 私钥文本框
        main_frame.grid_rowconfigure(6, weight=1)  # 输入框
        main_frame.grid_rowconfigure(7, weight=1)  # 输出框
        main_frame.grid_columnconfigure(1, weight=1)  # 主要内容列扩展

        # 初始化为 None，第一次点击时再创建
        self.common_modulus_frame = None
        self.private_key_frame = None

        # 初始化生成密钥
        self.generate_keys()

    # 关于
    def show_about(self):
        # 创建一个新的顶级窗口（Toplevel），作为关于窗口
        about_window = Toplevel(self.master)
        about_window.title("关于")  # 设置窗口标题
        about_window.geometry("374x320")  # 设置窗口初始大小

        # 获取屏幕宽度和高度，以便将窗口居中显示
        screen_width = about_window.winfo_screenwidth()
        screen_height = about_window.winfo_screenheight()
        position_top = int(screen_height / 2 - 320 / 2)  # 计算窗口顶部位置
        position_left = int(screen_width / 2 - 374 / 2)  # 计算窗口左侧位置
        about_window.geometry(f"374x320+{position_left}+{position_top}")  # 更新窗口位置

        # 设置窗口图标
        icon_path = resource_path('logo.ico')  # 获取图标文件路径
        about_window.iconbitmap(icon_path)  # 设置窗口图标

        # 加载背景图片
        jpg_path = resource_path('tr.jpg')  # 获取背景图片路径
        background_image = Image.open(jpg_path)  # 打开背景图片
        # 将PIL图像转换为Tkinter可以使用的PhotoImage
        background_photo = ImageTk.PhotoImage(background_image)

        # 使用Canvas控件来显示背景图片
        canvas = tk.Canvas(about_window, width=374, height=320, highlightthickness=0)  # 创建Canvas
        canvas.pack(fill="both", expand=True)  # 将Canvas填充到整个窗口
        # 在Canvas上创建背景图片
        canvas.create_image(0, 0, anchor="nw", image=background_photo)
        # 保存对背景图片的引用，防止被垃圾回收
        canvas.image = background_photo

        # 添加文字控件
        # 添加文字（带阴影效果）
        canvas.create_text(187, 92, text="作者: 不醒人室", font=("Arial", 14, "bold"), fill="black")  # 阴影
        canvas.create_text(185, 90, text="作者: 不醒人室", font=("Arial", 14, "bold"), fill="white")  # 主文字

        canvas.create_text(187, 122, text="版本: 1.1.3", font=("Arial", 12), fill="black")  # 阴影
        canvas.create_text(185, 120, text="版本: 1.1.3", font=("Arial", 12), fill="white")  # 主文字

        canvas.create_text(187, 152, text="GitHub:", font=("Arial", 12), fill="black")  # 阴影
        canvas.create_text(185, 150, text="GitHub:", font=("Arial", 12), fill="white")  # 主文字

        # 添加 GitHub 按钮
        github_button = ttk.Button(about_window, text="GitHub仓库",
                                   command=lambda: self.open_github("https://github.com/THEXN/rsa"))
        # 在Canvas上放置按钮
        canvas.create_window(185, 190, window=github_button)

    def open_github(self, url):
        # 导入webbrowser模块，用于打开网页
        import webbrowser
        # 使用默认浏览器打开指定URL
        webbrowser.open(url)

    # rsa加密解密算法逻辑
    # region

    def save_keys(self):
        """
        直接保存公私钥文本框的内容为 PEM 格式文件。
        公钥保存为 public.pem，私钥保存为 private.pem。
        """
        try:
            # 获取公私钥文本框的内容
            pub_key = self.pub_key_entry.get('1.0', 'end').strip()  # 获取公钥内容
            priv_key = self.priv_key_entry.get('1.0', 'end').strip()  # 获取私钥内容

            # 确保公私钥内容非空
            if not pub_key or not priv_key:
                messagebox.showerror("错误", "公私钥信息不能为空！")
                return

            # 保存公钥为 public.pem
            with open("public.pem", "w", encoding="utf-8") as pub_file:
                pub_file.write(pub_key)

            # 保存私钥为 private.pem
            with open("private.pem", "w", encoding="utf-8") as priv_file:
                priv_file.write(priv_key)

            messagebox.showinfo("成功", "公私钥已分别保存为 public.pem 和 private.pem")

        except Exception as e:
            messagebox.showerror("错误", f"保存失败: {e}")

    def toggle_common_modulus_interface(self):
        """
        切换共模攻击界面的显示和隐藏。
        如果当前没有共模攻击界面，则创建一个；否则，销毁现有的界面。
        """
        if self.common_modulus_frame is None:
            self.create_common_modulus_interface()
        else:
            self.destroy_common_modulus_interface()

    def generate_keys(self):
        """
        生成公钥和私钥。
        根据用户选择的模式（自动或手动），生成新的密钥对或仅生成公钥。
        """
        if self.key_gen_method_var.get() == 'auto':
            bit_size = self.bit_size_var.get()  # 获取用户选择的模数比特数
            self.pubkey, self.privkey = rsa.newkeys(bit_size)  # 使用rsa库生成密钥对
        else:
            # 手动模式，根据提供的参数生成公钥，如果可能则生成私钥
            try:
                e = int(self.e_entry.get().strip())
                n = int(self.n_entry.get().strip())

                # 检查是否提供了 p 和 q
                p = int(self.p_entry.get().strip()) if self.p_entry.get().strip() else None
                q = int(self.q_entry.get().strip()) if self.q_entry.get().strip() else None

                if p is not None and q is not None:
                    if p * q != n:
                        messagebox.showerror("输入错误", "p 和 q 的乘积必须等于 n。")
                        return  # 退出函数，不生成密钥

                    # 如果提供了 p 和 q，并且 n 是 p 和 q 的乘积，则计算私钥
                    phi_n = (p - 1) * (q - 1)
                    if gcd(e, phi_n) == 1:
                        d = self.mod_inverse(e, phi_n)
                        # 检查是否已存在私钥
                        if self.privkey is not None:
                            response = messagebox.askyesno("警告", "已存在私钥，是否替换？")
                            if response:
                                self.privkey = rsa.PrivateKey(n, e, d, p, q)
                            else:
                                return  # 保持现有私钥不变
                        else:
                            self.privkey = rsa.PrivateKey(n, e, d, p, q)
                    else:
                        messagebox.showerror("错误", "e 必须与 φ(n) 互质")
                else:
                    # 如果没有提供有效的 p 和 q，则不生成私钥
                    pass  # 不生成私钥，保持现有私钥不变

                # 生成公钥
                self.pubkey = rsa.PublicKey(n, e)

            except ValueError:
                messagebox.showerror("输入错误", "请输入有效的整数 e、n、p 和 q。")
            except Exception as e:
                messagebox.showerror("错误", str(e))

        self.display_keys()  # 显示生成的公钥和私钥
    def display_keys(self):
        """
        显示公钥和私钥。
        公钥总是显示在界面上，而私钥只在存在时显示。
        """
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
        """
        切换手动输入和自动生成模式。
        在自动模式下禁用手动输入框，在手动模式下启用输入框。
        """
        if self.key_gen_method_var.get() == 'auto':
            # 自动模式下禁用手动输入框
            self.e_entry.config(state='disabled')
            self.n_entry.config(state='disabled')
            self.p_entry.config(state='disabled')
            self.q_entry.config(state='disabled')
        else:
            # 手动模式下启用输入框
            self.e_entry.config(state='normal')
            self.n_entry.config(state='normal')
            self.p_entry.config(state='normal')
            self.q_entry.config(state='normal')

    def select_file(self):
        """
        选择文件并读取其内容到输入框中。
        """
        filename = filedialog.askopenfilename()
        if filename:
            with open(filename, 'r') as file:
                self.in_entry.delete('1.0', tk.END)
                self.in_entry.insert('1.0', file.read())

    def encode_click(self):
        """
        处理加密点击事件。
        将输入文本加密，并将结果以数字形式显示。
        """
        input_text = self.get_input()
        if input_text:
            try:
                start_time = time.perf_counter()
                encrypted_integer = int.from_bytes(rsa.encrypt(input_text.encode('utf-8'), self.pubkey),
                                                   byteorder='big')
                end_time = time.perf_counter()
                result = f"加密结果（数字形式）:\n{encrypted_integer}\n\n加密时间: {end_time - start_time:.6f}秒"
                self.output_result(result, 'encrypted.txt')
            except Exception as e:
                messagebox.showerror("错误", str(e))

    def decode_click(self):
        """
        处理解密点击事件。
        将输入的数字解密为原始文本。
        """
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
        """
        从输入框获取内容。
        """
        return self.in_entry.get('1.0', tk.END).strip()

    def output_result(self, result, filename=None):
        """
        显示结果并在需要时保存到文件。
        """
        # 显示完整的结果到文本框
        self.out_entry.delete('1.0', tk.END)
        self.out_entry.insert('1.0', result)

        # 如果选择文件输出
        if self.output_method_var.get() == 'file' and filename:
            # 分割字符串，排除首尾部分
            parts = result.split('\n')
            # 加密数字结果位于中间，取第二个元素（索引1）
            if len(parts) > 1:
                encrypted_number = parts[1].strip()  # 移除可能的前后空格

                # 保存加密数字结果到文件
                with open(filename, 'w') as file:
                    file.write(encrypted_number)
                messagebox.showinfo("文件保存", f"结果已保存到 {filename}")
            else:
                messagebox.showwarning("文件保存", "没有找到加密结果。")

    def save_to_file(self, filename, content):
        """
        将内容保存到指定文件。
        """
        with open(filename, 'w') as file:
            file.write(content)
        messagebox.showinfo("文件保存", f"内容已保存到 {filename}")

    # endregion

    # 共模攻击逻辑
    # region

    def toggle_common_modulus_interface(self):
        """
        切换共模攻击界面的显示与隐藏。
        如果 common_modulus_frame 尚未创建，则创建；否则，根据当前状态显示或隐藏。
        """
        if self.common_modulus_frame is None:
            self.create_common_modulus_interface()  # 第一次调用时创建界面

        # 确保不为空后再调用 winfo_ismapped()
        if self.common_modulus_frame and self.common_modulus_frame.winfo_ismapped():
            self.common_modulus_frame.grid_remove()  # 隐藏当前显示的共模攻击界面
        else:
            # 显示共模攻击界面，并覆盖之前的界面
            self.common_modulus_frame.grid(row=12, column=0, columnspan=2, sticky="nsew")  # 在相同的位置显示

    def create_common_modulus_interface(self):
        """
        创建共模攻击界面（初始隐藏）。
        """
        self.common_modulus_frame = tk.Frame(self.master)

        # 模数 n 输入框
        tk.Label(self.common_modulus_frame, text="模数 n:").grid(row=0, column=0, sticky="e")
        self.entry_n = tk.Entry(self.common_modulus_frame)
        self.entry_n.grid(row=0, column=1)

        # 模数 n1 输入框
        tk.Label(self.common_modulus_frame, text="模数 n1:").grid(row=1, column=0, sticky="e")
        self.entry_n1 = tk.Entry(self.common_modulus_frame)
        self.entry_n1.grid(row=1, column=1)

        # 模数 n2 输入框
        tk.Label(self.common_modulus_frame, text="模数 n2:").grid(row=2, column=0, sticky="e")
        self.entry_n2 = tk.Entry(self.common_modulus_frame)
        self.entry_n2.grid(row=2, column=1)

        # 密文 c1 输入框
        tk.Label(self.common_modulus_frame, text="密文 c1:").grid(row=3, column=0, sticky="e")
        self.entry_c1 = tk.Entry(self.common_modulus_frame)
        self.entry_c1.grid(row=3, column=1)

        # 密文 c2 输入框
        tk.Label(self.common_modulus_frame, text="密文 c2:").grid(row=4, column=0, sticky="e")
        self.entry_c2 = tk.Entry(self.common_modulus_frame)
        self.entry_c2.grid(row=4, column=1)

        # 公钥指数 e1 输入框
        tk.Label(self.common_modulus_frame, text="公钥指数 e1:").grid(row=5, column=0, sticky="e")
        self.entry_e1 = tk.Entry(self.common_modulus_frame)
        self.entry_e1.grid(row=5, column=1)

        # 公钥指数 e2 输入框
        tk.Label(self.common_modulus_frame, text="公钥指数 e2:").grid(row=6, column=0, sticky="e")
        self.entry_e2 = tk.Entry(self.common_modulus_frame)
        self.entry_e2.grid(row=6, column=1)

        # 公钥加载按钮
        tk.Button(self.common_modulus_frame, text="加载公钥1", command=self.load_public_key1).grid(row=7, column=0,
                                                                                                   padx=5, pady=5)
        tk.Button(self.common_modulus_frame, text="加载公钥2", command=self.load_public_key2).grid(row=7, column=1,
                                                                                                   padx=5, pady=5)

        # 解密结果显示框
        tk.Label(self.common_modulus_frame, text="解密结果:").grid(row=8, column=0, sticky="e")
        self.entry_result = tk.Entry(self.common_modulus_frame)
        self.entry_result.grid(row=8, column=1)

        # 解密按钮
        tk.Button(self.common_modulus_frame, text="解密", command=self.decrypt_common_modulus).grid(row=9, column=0,
                                                                                                    columnspan=2,
                                                                                                    padx=5, pady=5)

    def decrypt_common_modulus(self):
        """
        执行共模攻击解密操作。
        根据输入的模数、密文和公钥指数进行解密。
        """
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
        """
        加载第一个公钥文件并解析 e1 和 n1。
        """
        filename = filedialog.askopenfilename(title="选择第一个公钥文件",
                                              filetypes=(("PEM 文件", "*.pem"), ("所有文件", "*.*")))
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
        """
        加载第二个公钥文件并解析 e2 和 n2。
        """
        filename = filedialog.askopenfilename(title="选择第二个公钥文件",
                                              filetypes=(("PEM 文件", "*.pem"), ("所有文件", "*.*")))
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
        """
        在解密前验证 n1 和 n2 一致性并设置 n。
        """
        n1 = self.entry_n1.get()
        n2 = self.entry_n2.get()

        if n1 and n2:
            if n1 == n2:
                self.entry_n.delete(0, tk.END)
                self.entry_n.insert(0, n1)
            else:
                messagebox.showerror("模数不匹配", "模数 n1 和 n2 不一致，请检查公钥文件。")

    # endregion

    # 循环攻击逻辑
    # region

    def toggle_private_key_interface(self):
        """切换私钥计算界面显示与隐藏。"""
        if self.private_key_frame is None:
            self.create_private_key_interface()  # 第一次调用时创建界面

        if self.private_key_frame and self.private_key_frame.winfo_ismapped():
            self.private_key_frame.grid_remove()  # 隐藏当前显示的私钥计算界面
        else:
            self.private_key_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")  # 在相同的位置显示

    def create_private_key_interface(self):
        """创建私钥计算界面，包括输入框、按钮等。"""
        self.private_key_frame = tk.Frame(self.master)

        # 输入框 n
        tk.Label(self.private_key_frame, text="模数 n:").grid(row=0, column=0, sticky="e")
        self.entry_n = tk.Entry(self.private_key_frame)
        self.entry_n.grid(row=0, column=1)

        # 输入框 e
        tk.Label(self.private_key_frame, text="公钥指数 e:").grid(row=1, column=0, sticky="e")
        self.entry_e = tk.Entry(self.private_key_frame)
        self.entry_e.grid(row=1, column=1)

        # 显示找到的 p
        tk.Label(self.private_key_frame, text="质数 p:").grid(row=2, column=0, sticky="e")
        self.entry_p = tk.Entry(self.private_key_frame)
        self.entry_p.grid(row=2, column=1)

        # 显示找到的 q
        tk.Label(self.private_key_frame, text="质数 q:").grid(row=3, column=0, sticky="e")
        self.entry_q = tk.Entry(self.private_key_frame)
        self.entry_q.grid(row=3, column=1)

        # 显示私钥 d
        tk.Label(self.private_key_frame, text="私钥 d:").grid(row=4, column=0, sticky="e")
        self.entry_d = tk.Entry(self.private_key_frame)
        self.entry_d.grid(row=4, column=1)

        # 显示找到的 k
        tk.Label(self.private_key_frame, text="找到的 k:").grid(row=5, column=0, sticky="e")
        self.entry_k = tk.Entry(self.private_key_frame)
        self.entry_k.grid(row=5, column=1)

        # 按钮
        tk.Button(self.private_key_frame, text="执行循环攻击", command=self.perform_cycle_attack).grid(row=6, column=0, columnspan=2, pady=10)

    def perform_cycle_attack(self):
        """执行基于循环攻击逻辑的 RSA 参数恢复。"""
        try:
            e = int(self.entry_e.get())
            n = int(self.entry_n.get())
            for k in range(1, 10000):  # 遍历可能的 k 值
                candidate = e * k - 1
                if candidate % 2 != 0:  # 必须是偶数
                    continue
                        

                phi_n_candidates = []
                for i in range(2, int(candidate ** 0.5) + 1):  # 因数分解
                    if candidate % i == 0:
                        phi_n_candidates.append(i)
                        phi_n_candidates.append(candidate // i)

                for phi_n in phi_n_candidates:
                    p = self.solve_quadratic(phi_n, n)
                    if p is not None:
                        q = n // p
                        if p * q == n:
                            # 找到 p, q，计算私钥 d
                            phi_n = (p - 1) * (q - 1)
                            d = self.mod_inverse(e, phi_n)

                            # 显示结果
                            self.entry_p.delete(0, tk.END)
                            self.entry_p.insert(0, str(p))

                            self.entry_q.delete(0, tk.END)
                            self.entry_q.insert(0, str(q))

                            self.entry_d.delete(0, tk.END)
                            self.entry_d.insert(0, str(d))
                            
                            self.entry_k.delete(0, tk.END)
                            self.entry_k.insert(0, str(k))

                            messagebox.showinfo("成功", "循环攻击成功！")
                            return

            messagebox.showerror("失败", "循环攻击未能找到有效的因子。")

        except ValueError:
            messagebox.showerror("输入错误", "请输入有效的数字！")

    def solve_quadratic(self, phi_n, n):
        """
        求解关于 p 和 q 的二次方程。
        φ(n) = (p - 1) * (q - 1) = pq - (p + q) + 1
        n = p * q
        """
        discriminant = (n - phi_n + 1) ** 2 - 4 * n
        if discriminant < 0:
            return None  # 无解，判别式为负数

        sqrt_d = int(discriminant ** 0.5)
        if sqrt_d * sqrt_d != discriminant:
            return None  # 判别式非完全平方数，无解

        # 计算可能的 p 和 q
        p1 = (n - phi_n + 1 + sqrt_d) // 2
        p2 = (n - phi_n + 1 - sqrt_d) // 2

        # 检查 p 和 q 是否有效
        if p1 > 0 and n % p1 == 0:
            return p1
        if p2 > 0 and n % p2 == 0:
            return p2

        return None  # 未找到有效的 p 或 q

    def mod_inverse(self, a, m):
        """使用扩展欧几里得算法求模逆。"""
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

    # endregion


# 启动主窗口
# 创建一个 Tkinter 主窗口
root = tk.Tk()
# 获取图标文件的绝对路径
icon_path = resource_path('logo.ico')
# 设置主窗口的图标
root.iconbitmap(icon_path)
# 实例化 RsaApp 类，并传入主窗口对象
app = RsaApp(root)
# 启动 Tkinter 事件循环，使窗口保持显示状态
root.mainloop()
