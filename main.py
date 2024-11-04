import tkinter as tk
from tkinter import filedialog, messagebox, Scrollbar, Frame, Toplevel
import rsa
from sympy import gcd, gcdex  # 确保已安装 sympy
import time
import random


class RsaApp:
    def __init__(self, master):
        self.master = master
        self.master.title("RSA加密解密器")

        # Create a frame for key generation options
        key_gen_frame = tk.Frame(master)
        key_gen_frame.pack(pady=10)

        # Key generation method selection
        self.key_gen_method_var = tk.StringVar(value='auto')
        tk.Label(key_gen_frame, text="选择密钥生成方式:").pack(side=tk.LEFT)
        tk.Radiobutton(key_gen_frame, text="自动生成", variable=self.key_gen_method_var, value='auto', command=self.toggle_key_inputs).pack(side=tk.LEFT)
        tk.Radiobutton(key_gen_frame, text="手动输入", variable=self.key_gen_method_var, value='manual', command=self.toggle_key_inputs).pack(side=tk.LEFT)

        # Bit size selection for auto generation
        self.bit_size_var = tk.IntVar(value=128)
        tk.Label(master, text="选择模数比特数:").pack()
        self.bit_size_menu = tk.OptionMenu(master, self.bit_size_var, 128, 256, 512, 1024, 2048)
        self.bit_size_menu.pack()

        # Manual key inputs
        self.pub_key_entry = tk.Text(master, height=4, width=50, state=tk.DISABLED)
        self.priv_key_entry = tk.Text(master, height=4, width=50, state=tk.DISABLED)
        tk.Label(master, text="公钥:").pack()
        self.pub_key_entry.pack()
        tk.Label(master, text="私钥:").pack()
        self.priv_key_entry.pack()

        # Input method selection
        self.input_method_var = tk.StringVar(value='keyboard')
        tk.Label(master, text="选择输入方式:").pack()
        tk.Radiobutton(master, text="键盘输入", variable=self.input_method_var, value='keyboard').pack()
        tk.Radiobutton(master, text="文件输入", variable=self.input_method_var, value='file').pack()

        # Output method selection
        self.output_method_var = tk.StringVar(value='screen')
        tk.Label(master, text="选择输出方式:").pack()
        tk.Radiobutton(master, text="屏幕输出", variable=self.output_method_var, value='screen').pack()
        tk.Radiobutton(master, text="文件输出", variable=self.output_method_var, value='file').pack()

        # Input Text Box with scrollbar
        self.in_frame = tk.Frame(master)
        self.in_frame.pack()
        self.in_entry = tk.Text(self.in_frame, height=5, width=50)
        self.in_entry.pack(side=tk.LEFT)
        self.in_scroll = tk.Scrollbar(self.in_frame, command=self.in_entry.yview)
        self.in_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.in_entry.config(yscrollcommand=self.in_scroll.set)

        # Output Text Box with scrollbar
        self.out_frame = tk.Frame(master)
        self.out_frame.pack()
        self.out_entry = tk.Text(self.out_frame, height=5, width=50)
        self.out_entry.pack(side=tk.LEFT)
        self.out_scroll = tk.Scrollbar(self.out_frame, command=self.out_entry.yview)
        self.out_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.out_entry.config(yscrollcommand=self.out_scroll.set)

        # Buttons
        button_frame = Frame(master)
        button_frame.pack(pady=5)
        tk.Button(button_frame, text="生成密钥", command=self.generate_keys).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="加密", command=self.encode_click).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="解密", command=self.decode_click).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="选择文件", command=self.select_file).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="共模攻击", command=self.toggle_common_modulus_interface).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="关于", command=self.show_about).pack(side=tk.LEFT, padx=5)

        # Generate keys initially
        self.generate_keys()
        self.common_modulus_frame = None
    def toggle_common_modulus_interface(self):
        if self.common_modulus_frame is None:
            self.create_common_modulus_interface()
        else:
            self.destroy_common_modulus_interface()
            
    def toggle_key_inputs(self):
        if self.key_gen_method_var.get() == 'auto':
            self.pub_key_entry.config(state=tk.DISABLED)
            self.priv_key_entry.config(state=tk.DISABLED)
            self.bit_size_menu.config(state=tk.NORMAL)
        else:
            self.pub_key_entry.config(state=tk.NORMAL)
            self.priv_key_entry.config(state=tk.NORMAL)
            self.bit_size_menu.config(state=tk.DISABLED)

    def generate_keys(self):
        if self.key_gen_method_var.get() == 'auto':
            bit_size = self.bit_size_var.get()
            self.pubkey, self.privkey = rsa.newkeys(bit_size)
            self.pub_key_entry.config(state=tk.NORMAL)
            self.priv_key_entry.config(state=tk.NORMAL)
            self.pub_key_entry.delete('1.0', tk.END)
            self.priv_key_entry.delete('1.0', tk.END)
            self.pub_key_entry.insert('1.0', self.pubkey.save_pkcs1().decode('utf-8'))
            self.priv_key_entry.insert('1.0', self.privkey.save_pkcs1().decode('utf-8'))
            self.pub_key_entry.config(state=tk.DISABLED)
            self.priv_key_entry.config(state=tk.DISABLED)
        else:
            pub_key_str = self.pub_key_entry.get('1.0', tk.END).strip()
            priv_key_str = self.priv_key_entry.get('1.0', tk.END).strip()
            try:
                self.pubkey = rsa.PublicKey.load_pkcs1(pub_key_str.encode('utf-8'))
                self.privkey = rsa.PrivateKey.load_pkcs1(priv_key_str.encode('utf-8'))
            except Exception as e:
                messagebox.showerror("错误", str(e))
                return

    def select_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            with open(filename, 'r') as file:
                data = file.read()
                self.in_entry.delete('1.0', tk.END)
                self.in_entry.insert('1.0', data)

    def encode_click(self):
        input_text = self.get_input()
        if input_text:
            try:
                start_time = time.time()
                encrypted_text = rsa.encrypt(input_text.encode('utf-8'), self.pubkey)
                # Convert encrypted bytes to an integer
                encrypted_integer = int.from_bytes(encrypted_text, byteorder='big')
                end_time = time.time()

                self.output_result(f"加密结果（数字形式）:\n{encrypted_integer}\n\n加密时间: {end_time - start_time:.6f}秒")

                if self.output_method_var.get() == 'file':
                    self.save_to_file('encrypted.txt', str(encrypted_integer))

            except Exception as e:
                messagebox.showerror("错误", str(e))

    def decode_click(self):
        input_text = self.get_input()
        priv_key_str = self.priv_key_entry.get('1.0', tk.END).strip()
        if input_text and priv_key_str:
            try:
                # Convert the input integer back to bytes
                encrypted_integer = int(input_text)
                encrypted_bytes = encrypted_integer.to_bytes((encrypted_integer.bit_length() + 7) // 8, byteorder='big')

                privkey = rsa.PrivateKey.load_pkcs1(priv_key_str.encode('utf-8'))
                start_time = time.time()
                decrypted_text = rsa.decrypt(encrypted_bytes, privkey).decode('utf-8')
                end_time = time.time()

                self.output_result(f"解密结果:\n{decrypted_text}\n\n解密时间: {end_time - start_time:.6f}秒")
            except rsa.DecryptionError:
                messagebox.showerror("错误", "解密失败：无效的私钥或数据。")
            except Exception as e:
                messagebox.showerror("错误", str(e))

    def create_common_modulus_interface(self):
        self.common_modulus_frame = tk.Frame(self.master)
        self.common_modulus_frame.pack(pady=10)

        tk.Label(self.common_modulus_frame, text="加密结果1:").grid(row=0, column=0)
        self.c1_entry = tk.Entry(self.common_modulus_frame)
        self.c1_entry.grid(row=0, column=1)

        tk.Label(self.common_modulus_frame, text="公钥e1:").grid(row=1, column=0)
        self.e1_entry = tk.Entry(self.common_modulus_frame)
        self.e1_entry.grid(row=1, column=1)

        tk.Label(self.common_modulus_frame, text="加密结果2:").grid(row=2, column=0)
        self.c2_entry = tk.Entry(self.common_modulus_frame)
        self.c2_entry.grid(row=2, column=1)

        tk.Label(self.common_modulus_frame, text="公钥e2:").grid(row=3, column=0)
        self.e2_entry = tk.Entry(self.common_modulus_frame)
        self.e2_entry.grid(row=3, column=1)


        tk.Button(self.common_modulus_frame, text="执行共模攻击", command=self.perform_common_modulus_attack).grid(row=4, columnspan=2)
        
    def destroy_common_modulus_interface(self):
        if self.common_modulus_frame:
            self.common_modulus_frame.destroy()
            self.common_modulus_frame = None

    def check_coprime(self, a, b):
        return gcd(a, b) == 1

    def perform_common_modulus_attack(self):
        try:
            c1 = int(self.c1_entry.get())
            c2 = int(self.c2_entry.get())
            e1 = int(self.e1_entry.get())
            e2 = int(self.e2_entry.get())
            n = self.pubkey.n  # 使用当前公钥的模数

            # 执行共模攻击
            decrypted_message = self.common_modulus_attack(c1, c2, e1, e2, n)
            self.output_result(f"恢复的明文: {decrypted_message}")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def show_about(self):
        about_window = Toplevel(self.master)
        about_window.title("关于")
        about_window.geometry("300x200")

        # 设置窗口图标
        about_window.iconbitmap("./logo.ico")  # 替换为你的图标路径

        tk.Label(about_window, text="作者: 不醒人室").pack(pady=10)
        tk.Label(about_window, text="版本: 1.0.4").pack(pady=5)
        tk.Label(about_window, text="GitHub:").pack(pady=5)

        github_button = tk.Button(about_window, text="GitHub仓库", command=lambda: self.open_github("https://github.com/THEXN/rsa"))
        github_button.pack(pady=10)

    def open_github(self, url):
        import webbrowser
        webbrowser.open(url)

    def common_modulus_attack(self, c1, c2, e1, e2, n):
        g, x, y = gcdex(e1, e2)
        if g != 1:
            raise ValueError("e1和e2的gcd不为1，无法使用共模攻击。")

        # 计算恢复的明文
        m = (pow(c1, x, n) * pow(c2, y, n)) % n
        return m

    def get_input(self):
        if self.input_method_var.get() == 'keyboard':
            return self.in_entry.get('1.0', 'end').strip()
        elif self.input_method_var.get() == 'file':
            return self.in_entry.get('1.0', 'end').strip()  # Assuming input is loaded from file

    def output_result(self, result):
        self.out_entry.delete('1.0', tk.END)
        self.out_entry.insert('1.0', result)

    def save_to_file(self, filename, content):
        with open(filename, 'w') as file:
            file.write(content)
        messagebox.showinfo("文件保存", f"内容已保存到 {filename}")


# Create the main Tkinter window
root = tk.Tk()
root.iconbitmap('./logo.ico')
app = RsaApp(root)
root.mainloop()
