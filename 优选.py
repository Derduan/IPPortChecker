import pandas as pd
import socket
import concurrent.futures
import time
import sys
import os
import random
import string
import re

try:
    from tqdm import tqdm
except ImportError:
    print("未检测到tqdm库，正在安装...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "tqdm"])
    from tqdm import tqdm

try:
    import requests
except ImportError:
    print("未检测到requests库，正在安装...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

from typing import List, Tuple, Dict, Optional

# ========== 工具函数 ==========
def safe_read_csv(file_path):
    for enc in ['utf-8', 'gbk']:
        try:
            return pd.read_csv(file_path, encoding=enc)
        except Exception:
            continue
    print(f'无法读取CSV文件: {file_path}')
    return None

def safe_write_lines(filename, lines):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for line in lines:
                f.write(line)
        print(f'成功写入文件：{filename}')
    except Exception as e:
        print(f'写入文件失败: {e}')

def safe_requests_get(url, timeout=5):
    try:
        return requests.get(url, timeout=timeout)
    except Exception as e:
        print(f'网络请求失败: {e}')
        return None

def safe_input_int(prompt, default=None):
    try:
        val = input(prompt).strip()
        if not val and default is not None:
            return default
        return int(val)
    except Exception:
        print(f'输入无效，使用默认值{default}')
        return default

def random_suffix(length=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def get_ip_count(default_count=100):
    try:
        ip_count_str = input("请输入要保存的IP数量（留空默认100）: ").strip()
        if not ip_count_str:
            return default_count
        ip_count = int(ip_count_str)
        if ip_count <= 0:
            print(f"输入无效，使用默认值{default_count}")
            return default_count
        return ip_count
    except Exception:
        print(f"输入无效，使用默认值{default_count}")
        return default_count

def choose_data_file() -> str:
    files = [f for f in os.listdir('.') if f.lower().endswith('.csv') or f.lower().endswith('.txt')]
    if not files:
        print('当前目录下未找到任何CSV或TXT文件！')
        sys.exit(1)
    print('检测到以下数据文件：')
    for idx, fname in enumerate(files, 1):
        print(f'{idx}. {fname}')
    while True:
        try:
            choice = int(input(f'请选择要检测的数据文件（输入序号1-{len(files)}）：').strip())
            if 1 <= choice <= len(files):
                return files[choice-1]
            else:
                print('输入序号超出范围，请重新输入。')
        except Exception:
            print('输入无效，请输入数字序号。')

def check_local_vpn():
    try:
        resp = safe_requests_get('https://api.ipify.org', timeout=5)
        if not resp:
            print('无法获取本机公网IP，跳过VPN检测。')
            return
        ip = resp.text
        print(f'本机公网IP: {ip}')
        resp2 = safe_requests_get(f'http://ip-api.com/json/{ip}?fields=proxy,hosting,mobile,query', timeout=5)
        if not resp2:
            print('无法检测本机VPN状态。')
            return
        data = resp2.json()
        print(f'本机IP属性: {data}')
        if data.get('proxy') or data.get('hosting') or data.get('mobile'):
            print('警告：检测到本机可能处于VPN/代理/IDC环境，建议断开VPN后再运行检测，以保证结果准确性。')
            confirm = input('确认继续请输Y，否则按回车退出: ').strip().lower()
            if confirm != 'y':
                print('已取消检测。')
                sys.exit(0)
        else:
            print('本机未检测到VPN/代理环境。')
    except Exception as e:
        print(f'检测本机VPN状态时出错: {e}')

def get_column_mapping(df):
    columns = df.columns.tolist()
    print("检测到的列名：", columns)
    mapping = {'ip': None, 'country': None, 'port': None}
    # 常见中英文列名映射
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

def is_valid_ip(ip):
    # 简单IPv4校验
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

def read_ip_ports_from_txt(file_path: str) -> list:
    import re
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
                                print(f'无法识别的行格式: {line}，已跳过')
                                continue
                if not is_valid_ip(ip):
                    print(f'无效IP: {ip}，已跳过')
                    continue
                if not is_valid_port(port):
                    print(f'无效端口: {port}，已跳过')
                    continue
                ip_ports.append((ip, int(port), country.strip()))
                countries.add(country.strip())
        return ip_ports, list(countries)
    except Exception as e:
        print(f'读取TXT文件时出错: {e}')
        return [], []

def read_ip_ports_from_csv(file_path: str, country_code: str, mapping: Dict[str, str]) -> List[Tuple[str, int]]:
    df = safe_read_csv(file_path)
    if df is None:
        return []
    try:
        filtered = df[df[mapping['country']].astype(str).str.upper() == country_code.upper()]
        ip_ports = []
        for _, row in filtered.iterrows():
            ip = str(row[mapping['ip']]).strip()
            port = row[mapping['port']]
            if not is_valid_ip(ip):
                print(f'无效IP: {ip}，已跳过')
                continue
            if not is_valid_port(port):
                print(f'无效端口: {port}，已跳过')
                continue
            ip_ports.append((ip, int(port)))
        ip_ports = list(set(ip_ports))
        print(f"找到 {len(ip_ports)} 个去重后的符合条件的IP和端口。")
        return ip_ports
    except Exception as e:
        print(f'处理CSV数据时出错: {e}')
        return []

def check_ip_port(ip_port: Tuple[str, int], timeout: int = 5) -> Tuple[str, int, Optional[float]]:
    ip, port = ip_port
    try:
        start_time = time.time()
        with socket.create_connection((ip, port), timeout=timeout):
            end_time = time.time()
            latency = (end_time - start_time) * 1000
            return (ip, port, latency)
    except Exception as e:
        # 可以选择打印详细错误日志
        return (ip, port, None)

def check_ip_ports(ip_ports: List[Tuple[str, int]], num_threads: int = 100, timeout: int = 5) -> List[Tuple[str, int, Optional[float]]]:
    if len(ip_ports) > 1000:
        print(f"警告：本次将检测{len(ip_ports)}个IP:端口，数量较大，检测时间可能较长，请耐心等待...")
    print(f"开始检测 {len(ip_ports)} 个IP和端口...")
    results = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(check_ip_port, ip_port, timeout) for ip_port in ip_ports]
            for f in tqdm(concurrent.futures.as_completed(futures), total=len(ip_ports), desc="检测进度"):
                try:
                    results.append(f.result())
                except Exception as e:
                    print(f'检测线程异常: {e}')
    except Exception as e:
        print(f'线程池异常: {e}')
    print(f"检测完成，共检测到 {len(results)} 个结果。")
    return results

def get_top_ip_ports(results: List[Tuple[str, int, Optional[float]]], n: int) -> List[Tuple[str, int, float]]:
    try:
        valid_results = [result for result in results if result[2] is not None]
        print(f"成功连接的IP和端口数量: {len(valid_results)}")
        valid_results.sort(key=lambda x: x[2])
        return valid_results[:n]
    except Exception as e:
        print(f'筛选最优IP时出错: {e}')
        return []

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description="IP端口检测工具")
    parser.add_argument('--csv', type=str, default=None, help='CSV文件路径')
    parser.add_argument('--country', type=str, help='国家代码（如CN,US,JP）')
    parser.add_argument('--count', type=int, default=None, help='保存的IP数量')
    parser.add_argument('--threads', type=int, default=100, help='并发线程数')
    parser.add_argument('--timeout', type=int, default=5, help='端口检测超时时间（秒）')
    args = parser.parse_args()
    return args

def save_ip_ports_to_txt(results: List[Tuple[str, int, float]], output_file: str, country: str):
    """保存到txt文件，格式为IP:端口#国家"""
    try:
        with open(output_file, 'w', encoding='utf-8') as file:
            for ip, port, _ in results:
                file.write(f"{ip}:{port}#{country}\n")
        print(f"成功将IP和端口保存到文件：{output_file}")
    except Exception as e:
        print(f"保存文件时出错: {e}")

def save_failed_ip_ports(results: List[Tuple[str, int, Optional[float]]], output_file: str):
    """保存检测失败的IP:端口"""
    failed = [f"{ip}:{port}" for ip, port, latency in results if latency is None]
    if failed:
        with open(output_file, 'w', encoding='utf-8') as f:
            for line in failed:
                f.write(line + '\n')
        print(f"失败的IP和端口已保存到：{output_file}")

def main():
    check_local_vpn()
    data_file = choose_data_file()
    file_ext = os.path.splitext(data_file)[1].lower()
    all_top_ip_ports = []
    if file_ext == '.csv':
        try:
            args = parse_args()
            country_codes_arg = args.country
            ip_count = args.count if args.count else get_ip_count()
            num_threads = args.threads
            timeout = args.timeout
        except Exception:
            country_codes_arg = None
            ip_count = get_ip_count()
            num_threads = 100
            timeout = 5
        df = safe_read_csv(data_file)
        if df is None:
            return
        mapping = get_column_mapping(df)
        if not country_codes_arg:
            mode = input("请选择检测模式：1-检测所有国家  2-筛选检测部分国家（输入1或2）：").strip()
            if mode == '1':
                all_codes = df[mapping['country']].dropna().astype(str).str.upper().unique().tolist()
                print(f"检测所有国家，共{len(all_codes)}个：{all_codes}")
                country_codes = all_codes
            else:
                country_codes = input("请输入要筛选的国家代码 (如 TW, JP): ").strip().split(',')
        else:
            country_codes = country_codes_arg.split(',')
        for country_code in [c.strip().upper() for c in country_codes]:
            ip_ports = read_ip_ports_from_csv(data_file, country_code, mapping)
            if not ip_ports:
                print(f"未找到国家代码 {country_code} 的IP和端口，跳过该国家。")
                continue
            results = check_ip_ports(ip_ports, num_threads=num_threads, timeout=timeout)
            if not results:
                print(f"国家代码 {country_code} 的IP和端口未能成功连接，跳过该国家。")
                continue
            top_ip_ports = get_top_ip_ports(results, ip_count)
            if not top_ip_ports:
                print(f"未能找到 {ip_count} 个延时最低的IP和端口，跳过该国家。")
                continue
            all_top_ip_ports.extend([(ip, port, latency, country_code) for ip, port, latency in top_ip_ports])
    elif file_ext == '.txt':
        ip_ports, countries = read_ip_ports_from_txt(data_file)
        if not ip_ports:
            print('TXT文件未读取到有效IP和端口。')
            return
        print(f'共检测到{len(ip_ports)}个IP:端口，涉及国家：{countries}')
        ip_count = get_ip_count()
        num_threads = 100
        timeout = 5
        if len(countries) > 1:
            mode = input("请选择检测模式：1-检测所有国家  2-筛选检测部分国家（输入1或2）：").strip()
            if mode == '2':
                sel = input("请输入要筛选的国家代码 (如 TW, JP): ").strip().split(',')
                sel = [s.strip().upper() for s in sel]
                ip_ports = [item for item in ip_ports if item[2] in sel]
        from collections import defaultdict
        country_group = defaultdict(list)
        for ip, port, country in ip_ports:
            country_group[country].append((ip, port))
        for country_code, ip_port_list in country_group.items():
            results = check_ip_ports(ip_port_list, num_threads=num_threads, timeout=timeout)
            if not results:
                print(f"国家代码 {country_code} 的IP和端口未能成功连接，跳过该国家。")
                continue
            top_ip_ports = get_top_ip_ports(results, ip_count)
            if not top_ip_ports:
                print(f"未能找到 {ip_count} 个延时最低的IP和端口，跳过该国家。")
                continue
            all_top_ip_ports.extend([(ip, port, latency, country_code) for ip, port, latency in top_ip_ports])
    else:
        print('暂不支持的文件类型。')
        return
    user_suffix = input("请输入输出文件编号（留空则自动生成）：").strip()
    if not user_suffix:
        user_suffix = random_suffix()
    output_file = f"all_top_ip_ports_{user_suffix}.txt"
    try:
        with open(output_file, 'w', encoding='utf-8') as file:
            for ip, port, _, country in all_top_ip_ports:
                file.write(f"{ip}:{port}#{country}\n")
        print(f"所有国家的IP和端口已合并保存到文件：{output_file}")
        if len(all_top_ip_ports) == 0:
            print(f"警告：输出文件 {output_file} 为空，没有任何有效检测结果！")
    except Exception as e:
        print(f"保存合并文件时出错: {e}")
    print("程序运行结束。")

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f'程序运行出现异常: {e}')
