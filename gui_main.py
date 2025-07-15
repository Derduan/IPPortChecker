import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import threading
import os
import sys
import random
import string
import socket
import concurrent.futures
import time
import re
import collections

# 自动安装依赖
for pkg in ['pandas', 'requests', 'tqdm']:
    try:
        __import__(pkg)
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
import pandas as pd
import requests
from tqdm import tqdm

# 极简风格：不设置主题和字体，仅适当留白

def is_valid_ip(ip):
    pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    if not pattern.match(ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

def is_valid_port(port):
    try:
        port = int(port)
        return 1 <= port <= 65535
    except Exception:
        return False

def random_suffix(length=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def get_column_mapping(df, log_func):
    columns = df.columns.tolist()
    log_func(f"检测到的列名：{columns}")
    mapping = {'ip': None, 'country': None, 'port': None}
    ip_names = ['ip', 'ip地址', 'ip address', 'ipaddress']
    country_names = ['国家', 'country', 'code', '国家代码']
    port_names = ['端口', 'port', '端口号']
    for col in columns:
        col_l = col.strip().replace(' ', '').lower()
        if any(col_l == name.replace(' ', '').lower() for name in ip_names):
            mapping['ip'] = col
        if any(col_l == name.replace(' ', '').lower() for name in country_names):
            mapping['country'] = col
        if any(col_l == name.replace(' ', '').lower() for name in port_names):
            mapping['port'] = col
    for key in mapping:
        if not mapping[key]:
            mapping[key] = input(f"请输入{key}列名（可选项：{columns}）：").strip()
    return mapping

def read_ip_ports_from_txt(file_path, log_func):
    ip_ports = []
    countries = set()
    pattern1 = re.compile(r'^([0-9.]+):([0-9]+)(?:#(.+))?$')  # IP:端口#国家
    pattern2 = re.compile(r'^([0-9.]+)[,， ]+([0-9]+)[,， ]*(.+)?$')  # IP,端口,国家
    pattern3 = re.compile(r'^([0-9.]+)[,， ]+([0-9]+)$')  # IP,端口
    pattern4 = re.compile(r'^([0-9.]+)$')  # IP
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                m1 = pattern1.match(line)
                if m1:
                    ip, port, country = m1.group(1), m1.group(2), m1.group(3) or 'UNK'
                else:
                    m2 = pattern2.match(line)
                    if m2:
                        ip, port, country = m2.group(1), m2.group(2), m2.group(3) or 'UNK'
                    else:
                        m3 = pattern3.match(line)
                        if m3:
                            ip, port, country = m3.group(1), m3.group(2), 'UNK'
                        else:
                            m4 = pattern4.match(line)
                            if m4:
                                ip, port, country = m4.group(1), 443, 'UNK'
                            else:
                                log_func(f'无法识别的行格式: {line}，已跳过')
                                continue
                if not is_valid_ip(ip):
                    log_func(f'无效IP: {ip}，已跳过')
                    continue
                if not is_valid_port(port):
                    log_func(f'无效端口: {port}，已跳过')
                    continue
                ip_ports.append((ip, int(port), country.strip()))
                countries.add(country.strip())
        return ip_ports, list(countries)
    except Exception as e:
        log_func(f'读取TXT文件时出错: {e}')
        return [], []

def read_ip_ports_from_csv(file_path, country_code, mapping, log_func):
    try:
        df = pd.read_csv(file_path, encoding='utf-8')
    except Exception as e:
        log_func(f'无法读取CSV文件: {e}')
        return []
    try:
        filtered = df[df[mapping['country']].astype(str).str.upper() == country_code.upper()]
        ip_ports = []
        for _, row in filtered.iterrows():
            ip = str(row[mapping['ip']]).strip()
            port = row[mapping['port']]
            if not is_valid_ip(ip):
                log_func(f'无效IP: {ip}，已跳过')
                continue
            if not is_valid_port(port):
                log_func(f'无效端口: {port}，已跳过')
                continue
            ip_ports.append((ip, int(port)))
        ip_ports = list(set(ip_ports))
        log_func(f"找到 {len(ip_ports)} 个去重后的符合条件的IP和端口。")
        return ip_ports
    except Exception as e:
        log_func(f'处理CSV数据时出错: {e}')
        return []

def check_ip_port(ip_port, timeout=5):
    ip, port = ip_port
    try:
        start_time = time.time()
        with socket.create_connection((ip, port), timeout=timeout):
            end_time = time.time()
            latency = (end_time - start_time) * 1000
            return (ip, port, latency)
    except Exception:
        return (ip, port, None)

def run_detection(data_file, mode, countries, ip_count, user_suffix, log_func, progress_callback=None, stop_flag=None):
    all_top_ip_ports = []
    if not ip_count:
        ip_count = 100
    try:
        ip_count = int(ip_count)
    except Exception:
        ip_count = 100
    if not user_suffix:
        user_suffix = random_suffix()
    output_file = f"all_top_ip_ports_{user_suffix}.txt"
    all_ip_port_items = []  # [(ip, port, country)]
    file_ext = os.path.splitext(data_file)[1].lower()
    if file_ext == '.csv':
        try:
            df = pd.read_csv(data_file, encoding='utf-8')
        except Exception as e:
            log_func(f'无法读取CSV文件: {e}')
            return
        mapping = get_column_mapping(df, log_func)
        if mode == 'all':
            all_codes = df[mapping['country']].dropna().astype(str).str.upper().unique().tolist()
            log_func(f"检测所有国家，共{len(all_codes)}个：{all_codes}")
            country_codes = all_codes
        else:
            country_codes = [c.strip().upper() for c in countries.split(',') if c.strip()]
        for country_code in country_codes:
            ip_ports = read_ip_ports_from_csv(data_file, country_code, mapping, log_func)
            for ip, port in ip_ports:
                all_ip_port_items.append((ip, port, country_code))
    elif file_ext == '.txt':
        ip_ports, countries_list = read_ip_ports_from_txt(data_file, log_func)
        if not ip_ports:
            log_func('TXT文件未读取到有效IP和端口。')
            return
        log_func(f'共检测到{len(ip_ports)}个IP:端口，涉及国家：{countries_list}')
        if mode == 'all':
            all_ip_port_items = ip_ports
        else:
            sel = [s.strip().upper() for s in countries.split(',') if s.strip()]
            all_ip_port_items = [item for item in ip_ports if item[2].upper() in sel]
    else:
        log_func('暂不支持的文件类型。')
        return
    total = len(all_ip_port_items)
    if progress_callback:
        progress_callback(0, total)
    results = []
    completed = 0
    for ip, port, country in all_ip_port_items:
        if stop_flag and stop_flag.is_set():
            log_func("检测被用户手动停止。")
            break
        result = check_ip_port((ip, port))
        results.append((ip, port, result[2], country))
        completed += 1
        if progress_callback:
            progress_callback(completed, total)
    # 检测完成后按国家分组筛选最优
    country_group = collections.defaultdict(list)
    for ip, port, latency, country in results:
        if latency is not None:
            country_group[country].append((ip, port, latency))
    for country_code, ip_port_list in country_group.items():
        ip_port_list.sort(key=lambda x: x[2])
        top_ip_ports = ip_port_list[:ip_count]
        all_top_ip_ports.extend([(ip, port, latency, country_code) for ip, port, latency in top_ip_ports])
    try:
        with open(output_file, 'w', encoding='utf-8') as file:
            for ip, port, _, country in all_top_ip_ports:
                file.write(f"{ip}:{port}#{country}\n")
        log_func(f"所有国家的IP和端口已合并保存到文件：{output_file}")
        if len(all_top_ip_ports) == 0:
            log_func(f"警告：输出文件 {output_file} 为空，没有任何有效检测结果！")
    except Exception as e:
        log_func(f"保存合并文件时出错: {e}")
    log_func("检测流程结束。")

class IPDetectGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("优选IP端口检测工具")
        self.data_file = tk.StringVar()
        self.mode = tk.StringVar(value="all")
        self.countries = tk.StringVar()
        self.ip_count = tk.StringVar()
        self.user_suffix = tk.StringVar()
        self.stop_flag = threading.Event()
        self.create_widgets()

    def create_widgets(self):
        pad = {'padx': 8, 'pady': 6}
        tk.Label(self.root, text="选择数据文件:").grid(row=0, column=0, sticky="e", **pad)
        tk.Entry(self.root, textvariable=self.data_file, width=40).grid(row=0, column=1, **pad)
        tk.Button(self.root, text="浏览", command=self.browse_file).grid(row=0, column=2, **pad)

        tk.Label(self.root, text="检测模式:").grid(row=1, column=0, sticky="e", **pad)
        tk.Radiobutton(self.root, text="全部国家", variable=self.mode, value="all").grid(row=1, column=1, sticky="w", **pad)
        tk.Radiobutton(self.root, text="部分国家", variable=self.mode, value="part").grid(row=1, column=1, sticky="e", **pad)

        tk.Label(self.root, text="国家代码(逗号分隔):").grid(row=2, column=0, sticky="e", **pad)
        tk.Entry(self.root, textvariable=self.countries, width=40).grid(row=2, column=1, columnspan=2, sticky="w", **pad)

        tk.Label(self.root, text="保存数量(留空默认100):").grid(row=3, column=0, sticky="e", **pad)
        tk.Entry(self.root, textvariable=self.ip_count, width=10).grid(row=3, column=1, sticky="w", **pad)

        tk.Label(self.root, text="输出编号(留空自动):").grid(row=4, column=0, sticky="e", **pad)
        tk.Entry(self.root, textvariable=self.user_suffix, width=10).grid(row=4, column=1, sticky="w", **pad)

        tk.Button(self.root, text="开始检测", command=self.start_detection, name="start_btn").grid(row=5, column=0, pady=12)
        self.stop_btn = tk.Button(self.root, text="停止检测", command=self.stop_detection, state='disabled')
        self.stop_btn.grid(row=5, column=2, pady=12)

        self.log_area = scrolledtext.ScrolledText(self.root, width=70, height=16, state='disabled', font=('Consolas', 10))
        self.log_area.grid(row=6, column=0, columnspan=3, padx=10, pady=8)

        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=400, mode="determinate")
        self.progress.grid(row=7, column=0, columnspan=3, padx=10, pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("数据文件", "*.csv *.txt")])
        if file_path:
            self.data_file.set(file_path)

    def log(self, msg):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, msg + '\n')
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')
        self.root.update()

    def update_progress(self, value, total):
        self.progress['maximum'] = total
        self.progress['value'] = value
        self.root.update_idletasks()

    def start_detection(self):
        if not self.data_file.get():
            messagebox.showerror("错误", "请选择数据文件！")
            return
        if self.mode.get() == "part" and not self.countries.get().strip():
            messagebox.showerror("错误", "请输入要检测的国家代码！")
            return
        self.log_area.config(state='normal')
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state='disabled')
        self.progress['value'] = 0
        self.root.nametowidget(".start_btn").config(state='disabled')
        self.stop_btn.config(state='normal')
        self.stop_flag.clear()
        threading.Thread(target=self._run_detection_thread, daemon=True).start()

    def stop_detection(self):
        self.stop_flag.set()
        self.log("检测已请求停止，请稍候...")
        self.stop_btn.config(state='disabled')

    def _run_detection_thread(self):
        try:
            run_detection(
                self.data_file.get(),
                self.mode.get(),
                self.countries.get(),
                self.ip_count.get(),
                self.user_suffix.get(),
                self.log,
                self.update_progress,
                self.stop_flag
            )
            messagebox.showinfo("检测完成", "IP端口检测已完成！")
        except Exception as e:
            self.log(f"检测过程中发生异常: {e}")
        finally:
            self.root.nametowidget(".start_btn").config(state='normal')
            self.stop_btn.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = IPDetectGUI(root)
    root.mainloop() 