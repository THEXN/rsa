import tkinter as tk
from tkinter import filedialog, messagebox, Scrollbar, Frame
import base64
import rsa
import time


class RsaApp:
    def __init__(self, master):
        self.master = master
        self.master.title("RSA加密解密器")

        # Create a frame for key generation options
        key_gen_frame = Frame(master)
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
        self.in_frame = Frame(master)
        self.in_frame.pack()
        self.in_entry = tk.Text(self.in_frame, height=5, width=50)
        self.in_entry.pack(side=tk.LEFT)
        self.in_scroll = Scrollbar(self.in_frame, command=self.in_entry.yview)
        self.in_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.in_entry.config(yscrollcommand=self.in_scroll.set)

        # Output Text Box with scrollbar
        self.out_frame = Frame(master)
        self.out_frame.pack()
        self.out_entry = tk.Text(self.out_frame, height=5, width=50)
        self.out_entry.pack(side=tk.LEFT)
        self.out_scroll = Scrollbar(self.out_frame, command=self.out_entry.yview)
        self.out_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.out_entry.config(yscrollcommand=self.out_scroll.set)

        # Buttons
        button_frame = Frame(master)
        button_frame.pack(pady=5)
        tk.Button(button_frame, text="生成密钥", command=self.generate_keys).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="加密", command=self.encode_click).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="解密", command=self.decode_click).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="选择文件", command=self.select_file).pack(side=tk.LEFT, padx=5)

        # Generate keys initially
        self.generate_keys()

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
                encrypted_base64 = base64.b64encode(encrypted_text).decode('utf-8')
                end_time = time.time()

                self.output_result(f"加密结果:\n{encrypted_base64}\n\n加密时间: {end_time - start_time:.6f}秒")

                if self.output_method_var.get() == 'file':
                    self.save_to_file('encrypted.txt', encrypted_base64)

            except Exception as e:
                messagebox.showerror("错误", str(e))

    def decode_click(self):
        input_text = self.get_input()  # 获取加密后的文本
        priv_key_str = self.priv_key_entry.get('1.0', tk.END).strip()  # 获取当前输入的私钥
        if input_text and priv_key_str:
            try:
                encrypted_bytes = base64.b64decode(input_text)  # 解码 Base64
                privkey = rsa.PrivateKey.load_pkcs1(priv_key_str.encode('utf-8'))  # 从输入加载私钥
                start_time = time.time()
                decrypted_text = rsa.decrypt(encrypted_bytes, privkey).decode('utf-8')  # 使用私钥解密
                end_time = time.time()

                self.output_result(f"解密结果:\n{decrypted_text}\n\n解密时间: {end_time - start_time:.6f}秒")
            except rsa.DecryptionError:
                messagebox.showerror("错误", "解密失败：无效的私钥或数据。")
            except Exception as e:
                messagebox.showerror("错误", str(e))

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
app = RsaApp(root)
root.mainloop()
