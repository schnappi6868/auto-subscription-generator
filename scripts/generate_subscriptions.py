#!/usr/bin/env python3
"""
自动订阅生成脚本
从输入源文件夹读取.txt文件中的链接，合并节点并生成Clash兼容的YAML文件
"""

import os
import re
import base64
import json
import requests
import yaml
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs
import time

def decode_base64(data):
    """解码Base64数据，自动补全"""
    if not data:
        return None
    data = str(data).strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    try:
        return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
    except:
        try:
            return base64.b64decode(data).decode('utf-8', errors='ignore')
        except:
            return None

def parse_ss(ss_url):
    """解析SS链接"""
    try:
        # 移除 ss:// 前缀
        url = ss_url[5:]
        
        # 检查是否有@符号
        if '@' in url:
            # 格式: method:password@server:port
            parts = url.split('@')
            method_password = parts[0]
            server_port = parts[1]
            
            # 解码method:password部分
            if ':' in method_password:
                # 已经是明文的method:password
                method, password = method_password.split(':', 1)
            else:
                # Base64编码的
                decoded = decode_base64(method_password)
                if decoded and ':' in decoded:
                    method, password = decoded.split(':', 1)
                else:
                    return None
            
            server, port = server_port.split(':', 1)
            port = int(port)
            
            return {
                'name': f"SS-{server}:{port}",
                'type': 'ss',
                'server': server,
                'port': port,
                'cipher': method,
                'password': password,
                'udp': True
            }
        else:
            # 完整Base64编码格式
            decoded = decode_base64(url)
            if decoded:
                # 格式: method:password@server:port
                if '@' in decoded:
                    parts = decoded.split('@')
                    method_password, server_port = parts[0], parts[1]
                    if ':' in method_password and ':' in server_port:
                        method, password = method_password.split(':', 1)
                        server, port = server_port.split(':', 1)
                        return {
                            'name': f"SS-{server}:{port}",
                            'type': 'ss',
                            'server': server,
                            'port': int(port),
                            'cipher': method,
                            'password': password,
                            'udp': True
                        }
    except Exception as e:
        print(f"解析SS链接失败 {ss_url[:50]}: {e}")
    return None

def parse_vmess(vmess_url):
    """解析VMess链接"""
    try:
        # 移除 vmess:// 前缀并解码
        encoded = vmess_url[8:]
        decoded = decode_base64(encoded)
        if not decoded:
            return None
            
        # 解析JSON配置
        config = json.loads(decoded)
        
        # 创建基础配置
        proxy_config = {
            'name': f"VMess-{config.get('ps', config.get('add', 'unknown'))}",
            'type': 'vmess',
            'server': config.get('add', ''),
            'port': int(config.get('port', 0)),
            'uuid': config.get('id', ''),
            'alterId': int(config.get('aid', 0)),
            'cipher': config.get('scy', 'auto'),
            'udp': True,
            'tls': config.get('tls') == 'tls',
            'skip-cert-verify': False
        }
        
        # 添加servername
        sni = config.get('sni', config.get('host', ''))
        if sni:
            proxy_config['servername'] = sni
        
        # 网络类型设置
        network = config.get('net', 'tcp')
        if network == 'ws':
            proxy_config['network'] = 'ws'
            ws_opts = {
                'path': config.get('path', '/')
            }
            host = config.get('host', '')
            if host:
                ws_opts['headers'] = {'Host': host}
            proxy_config['ws-opts'] = ws_opts
        elif network == 'h2':
            proxy_config['network'] = 'h2'
            proxy_config['h2-opts'] = {
                'host': [config.get('host', '')],
                'path': config.get('path', '/')
            }
        elif network == 'grpc':
            proxy_config['network'] = 'grpc'
            proxy_config['grpc-opts'] = {
                'grpc-service-name': config.get('path', '')
            }
        
        return proxy_config
    except Exception as e:
        print(f"解析VMess链接失败 {vmess_url[:50]}: {e}")
    return None

def parse_trojan(trojan_url):
    """解析Trojan链接"""
    try:
        # 移除 trojan:// 前缀
        url = trojan_url[9:]
        
        # 解析URL
        if '#' in url:
            url_part, fragment = url.split('#', 1)
        else:
            url_part, fragment = url, ''
            
        if '@' in url_part:
            # 格式: password@server:port
            password_part, server_port = url_part.split('@', 1)
            password = password_part
            server, port = server_port.split(':', 1)
            
            # 解析查询参数
            query_params = {}
            if '?' in port:
                port_part, query = port.split('?', 1)
                port = port_part
                query_params = parse_qs(query)
            
            config = {
                'name': f"Trojan-{server}:{port}",
                'type': 'trojan',
                'server': server,
                'port': int(port),
                'password': password,
                'udp': True,
                'sni': query_params.get('sni', [''])[0] or server,
                'skip-cert-verify': False
            }
            
            # 添加fragment作为name
            if fragment:
                config['name'] = fragment
            
            return config
    except Exception as e:
        print(f"解析Trojan链接失败 {trojan_url[:50]}: {e}")
    return None

def parse_vless(vless_url):
    """解析VLESS链接"""
    try:
        # 移除 vless:// 前缀
        url = vless_url[8:]
        
        # 解析URL
        parsed = urlparse(f'vless://{url}')
        
        config = {
            'name': f"VLESS-{parsed.hostname}:{parsed.port}",
            'type': 'vless',
            'server': parsed.hostname,
            'port': parsed.port,
            'uuid': parsed.username,
            'udp': True,
            'tls': True,
            'skip-cert-verify': False,
            'servername': parsed.hostname
        }
        
        # 解析查询参数
        if parsed.query:
            params = parse_qs(parsed.query)
            if 'type' in params:
                config['network'] = params['type'][0]
            if 'security' in params:
                config['tls'] = params['security'][0] == 'tls'
            if 'path' in params and config.get('network') == 'ws':
                config['ws-opts'] = {
                    'path': params['path'][0]
                }
            if 'host' in params and config.get('network') == 'ws':
                if 'ws-opts' not in config:
                    config['ws-opts'] = {}
                config['ws-opts']['headers'] = {
                    'Host': params['host'][0]
                }
        
        # 添加fragment作为name
        if parsed.fragment:
            config['name'] = parsed.fragment
            
        return config
    except Exception as e:
        print(f"解析VLESS链接失败 {vless_url[:50]}: {e}")
    return None

def parse_proxy(proxy_str):
    """解析单个代理链接"""
    if not isinstance(proxy_str, str) or not proxy_str:
        return None
    
    proxy_str = proxy_str.strip()
    
    if proxy_str.startswith('ss://'):
        return parse_ss(proxy_str)
    elif proxy_str.startswith('vmess://'):
        return parse_vmess(proxy_str)
    elif proxy_str.startswith('trojan://'):
        return parse_trojan(proxy_str)
    elif proxy_str.startswith('vless://'):
        return parse_vless(proxy_str)
    elif proxy_str.startswith('ssr://'):
        # SSR链接，暂时跳过
        print(f"跳过SSR链接: {proxy_str[:50]}...")
        return None
    elif len(proxy_str) > 10 and re.match(r'^[A-Za-z0-9+/=]+$', proxy_str):
        # 可能是Base64编码的完整订阅
        decoded = decode_base64(proxy_str)
        if decoded:
            # 尝试按行解析
            lines = decoded.split('\n')
            proxies = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#') and '://' in line:
                    proxy = parse_proxy(line)
                    if proxy:
                        proxies.append(proxy)
            return proxies if proxies else None
    return None

def read_links_from_file(file_path):
    """从文本文件读取链接"""
    links = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    links.append(line)
    except Exception as e:
        print(f"读取文件 {file_path} 时出错: {e}")
    return links

def fetch_subscription_content(url):
    """获取订阅内容"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/plain, */*; q=0.01'
    }
    
    try:
        print(f"正在获取: {url}")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        content = response.text.strip()
        print(f"  获取成功，长度: {len(content)} 字符")
        
        # 如果是Base64编码，尝试解码
        if content and len(content) > 10:
            # 检查是否是Base64（只包含Base64字符且长度合适）
            if re.match(r'^[A-Za-z0-9+/=\s]+$', content.replace('\n', '').replace('\r', '')):
                decoded = decode_base64(content)
                if decoded and any(keyword in decoded.lower() for keyword in ['ss://', 'vmess://', 'trojan://', 'vless://', 'proxies:', 'server:']):
                    print(f"  Base64解码成功")
                    return decoded
        
        return content
    except Exception as e:
        print(f"获取订阅失败 {url}: {e}")
        return None

def parse_proxies_from_content(content):
    """从内容中解析节点"""
    if not content:
        return []
    
    proxies = []
    
    # 先尝试解析为Clash YAML格式
    if 'proxies:' in content or 'Proxy:' in content.lower():
        try:
            # 尝试解析为YAML
            data = yaml.safe_load(content)
            if data and 'proxies' in data:
                print(f"  检测到Clash YAML格式，找到 {len(data['proxies'])} 个节点")
                return data['proxies'][:100]  # 限制数量
        except:
            pass
    
    # 按行解析
    lines = content.split('\n')
    print(f"  开始解析 {len(lines)} 行内容")
    
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # 尝试解析各种格式
        try:
            proxy = parse_proxy(line)
            if proxy:
                if isinstance(proxy, list):
                    proxies.extend(proxy)
                else:
                    proxies.append(proxy)
        except Exception as e:
            # 忽略解析错误，继续下一行
            pass
    
    print(f"  解析完成，找到 {len(proxies)} 个节点")
    return proxies

def generate_clash_config(proxies, filename):
    """生成Clash兼容的YAML配置"""
    if not proxies:
        print("  没有有效节点，跳过生成")
        return 0
    
    # 过滤掉None值
    proxies = [p for p in proxies if p]
    
    # 基础配置
    config = {
        'port': 7890,
        'socks-port': 7891,
        'mixed-port': 7893,
        'allow-lan': True,
        'mode': 'Rule',
        'log-level': 'info',
        'external-controller': '0.0.0.0:9090',
        'secret': '',
        'dns': {
            'enable': True,
            'listen': '0.0.0.0:53',
            'default-nameserver': ['223.5.5.5', '8.8.8.8'],
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'nameserver': [
                'https://doh.pub/dns-query',
                'https://dns.alidns.com/dns-query'
            ]
        },
        'proxies': proxies[:100],  # 限制最多100个节点
        'proxy-groups': [
            {
                'name': '🚀 节点选择',
                'type': 'select',
                'proxies': ['♻️ 自动选择', '🎯 全球直连', 'DIRECT'] + [p.get('name', f'节点{i}') for i, p in enumerate(proxies[:10])]
            },
            {
                'name': '♻️ 自动选择',
                'type': 'url-test',
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50,
                'proxies': [p.get('name', f'节点{i}') for i, p in enumerate(proxies[:50])]
            },
            {
                'name': '🎯 全球直连',
                'type': 'select',
                'proxies': ['DIRECT']
            }
        ],
        'rules': [
            'DOMAIN-SUFFIX,google.com,🚀 节点选择',
            'DOMAIN-SUFFIX,github.com,🚀 节点选择',
            'DOMAIN-SUFFIX,youtube.com,🚀 节点选择',
            'GEOIP,CN,🎯 全球直连',
            'MATCH,🚀 节点选择'
        ]
    }
    
    # 写入YAML文件
    output_path = os.path.join('订阅链接', f'{filename}.yaml')
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    
    print(f"已生成文件: {output_path}，包含 {len(proxies[:100])} 个节点")
    return len(proxies[:100])

def main():
    """主函数"""
    print("开始生成订阅...")
    
    # 确保输出目录存在
    os.makedirs('订阅链接', exist_ok=True)
    
    # 清理旧的订阅文件
    import glob
    old_files = glob.glob('订阅链接/*.yaml')
    for f in old_files:
        try:
            os.remove(f)
        except:
            pass
    
    # 遍历输入源文件夹
    input_dir = '输入源'
    if not os.path.exists(input_dir):
        print(f"输入源文件夹不存在: {input_dir}")
        # 创建示例文件
        os.makedirs(input_dir, exist_ok=True)
        with open(os.path.join(input_dir, 'example.txt'), 'w', encoding='utf-8') as f:
            f.write("# 在此添加订阅链接，每行一个\n")
            f.write("# 例如：\n")
            f.write("# https://example.com/subscribe.txt\n")
        print("已创建示例文件: 输入源/example.txt")
        return
    
    for filename in os.listdir(input_dir):
        if filename.endswith('.txt'):
            file_path = os.path.join(input_dir, filename)
            print(f"\n处理文件: {filename}")
            
            # 读取链接
            links = read_links_from_file(file_path)
            if not links:
                print(f"  未找到链接: {filename}")
                continue
            
            all_proxies = []
            
            # 获取每个链接的内容
            for i, link in enumerate(links):
                print(f"\n  获取链接 [{i+1}/{len(links)}]: {link[:60]}...")
                content = fetch_subscription_content(link)
                if content:
                    proxies = parse_proxies_from_content(content)
                    if proxies:
                        all_proxies.extend(proxies)
                        print(f"    找到 {len(proxies)} 个节点")
                    else:
                        print(f"    未找到有效节点")
                    
                    # 避免请求过快
                    if i < len(links) - 1:
                        time.sleep(2)
                else:
                    print(f"    获取内容失败")
            
            # 去重（基于服务器和端口）
            unique_proxies = []
            seen = set()
            for proxy in all_proxies:
                if proxy and isinstance(proxy, dict):
                    server = proxy.get('server', '')
                    port = proxy.get('port', 0)
                    if server and port:
                        key = f"{server}:{port}:{proxy.get('type', '')}"
                        if key not in seen:
                            seen.add(key)
                            unique_proxies.append(proxy)
            
            print(f"\n  去重后: {len(unique_proxies)} 个唯一节点")
            
            # 生成YAML文件
            if unique_proxies:
                base_name = os.path.splitext(filename)[0]
                count = generate_clash_config(unique_proxies, base_name)
                print(f"  生成文件完成，包含 {count} 个节点")
            else:
                print(f"  未找到有效节点，跳过生成")
                # 生成一个空的配置文件以避免错误
                config = {
                    'proxies': [],
                    'proxy-groups': [{
                        'name': '无可用节点',
                        'type': 'select',
                        'proxies': ['DIRECT']
                    }],
                    'rules': ['MATCH,无可用节点']
                }
                base_name = os.path.splitext(filename)[0]
                output_path = os.path.join('订阅链接', f'{base_name}.yaml')
                with open(output_path, 'w', encoding='utf-8') as f:
                    yaml.dump(config, f, allow_unicode=True)
                print(f"  已生成空配置文件: {output_path}")
    
    print("\n订阅生成完成！")

if __name__ == '__main__':
    main()
