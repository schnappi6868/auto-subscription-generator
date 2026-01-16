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
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    try:
        return base64.urlsafe_b64decode(data).decode('utf-8')
    except:
        try:
            return base64.b64decode(data).decode('utf-8')
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
        print(f"解析SS链接失败 {ss_url}: {e}")
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
        
        return {
            'name': f"VMess-{config.get('ps', config.get('add', 'unknown'))}",
            'type': 'vmess',
            'server': config.get('add', ''),
            'port': int(config.get('port', 0)),
            'uuid': config.get('id', ''),
            'alterId': int(config.get('aid', 0)),
            'cipher': config.get('scy', 'auto'),
            'udp': True,
            'tls': config.get('tls') == 'tls',
            'skip-cert-verify': False,
            'servername': config.get('sni', config.get('host', '')),
            'network': config.get('net', 'tcp'),
            'ws-opts': {
                'path': config.get('path', '/'),
                'headers': {
                    'Host': config.get('host', '')
                }
            } if config.get('net') == 'ws' else None,
            'h2-opts': {
                'host': [config.get('host', '')],
                'path': config.get('path', '/')
            } if config.get('net') == 'h2' else None
        }
    except Exception as e:
        print(f"解析VMess链接失败 {vmess_url}: {e}")
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
        print(f"解析Trojan链接失败 {trojan_url}: {e}")
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
        print(f"解析VLESS链接失败 {vless_url}: {e}")
    return None

def parse_proxy(proxy_str):
    """解析单个代理链接"""
    if proxy_str.startswith('ss://'):
        return parse_ss(proxy_str)
    elif proxy_str.startswith('vmess://'):
        return parse_vmess(proxy_str)
    elif proxy_str.startswith('trojan://'):
        return parse_trojan(proxy_str)
    elif proxy_str.startswith('vless://'):
        return parse_vless(proxy_str)
    elif proxy_str.startswith('ssr://'):
        # SSR链接，暂时跳过或简单处理
        print(f"跳过SSR链接: {proxy_str[:50]}...")
        return None
    elif re.match(r'^[A-Za-z0-9+/=]+$', len(proxy_str) > 10):
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
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        # 尝试解码Base64
        content = response.text
        try:
            decoded = decode_base64(content)
            if decoded and any(proto in decoded for proto in ['://', 'server=', 'Proxy']):
                return decoded
        except:
            pass
        
        return content
    except Exception as e:
        print(f"获取订阅失败 {url}: {e}")
        return None

def parse_proxies_from_content(content):
    """从内容中解析节点"""
    proxies = []
    
    # 先尝试解析为Base64
    if content and len(content) > 10 and re.match(r'^[A-Za-z0-9+/=\s]+$', content.replace('\n', '')):
        decoded = decode_base64(content)
        if decoded:
            content = decoded
    
    # 按行解析
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # 尝试解析各种格式
        proxy = parse_proxy(line)
        if proxy:
            if isinstance(proxy, list):
                proxies.extend(proxy)
            else:
                proxies.append(proxy)
    
    return proxies

def generate_clash_config(proxies, filename):
    """生成Clash兼容的YAML配置"""
    # 基础配置
    config = {
        'port': 7890,
        'socks-port': 7891,
        'redir-port': 7892,
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
            ],
            'fallback': [
                'https://doh.dns.sb/dns-query',
                'https://dns.cloudflare.com/dns-query'
            ]
        },
        'proxies': proxies[:100],  # 限制最多100个节点
        'proxy-groups': [
            {
                'name': '🚀 节点选择',
                'type': 'select',
                'proxies': ['♻️ 自动选择', '🎯 全球直连'] + [p['name'] for p in proxies[:20]]
            },
            {
                'name': '♻️ 自动选择',
                'type': 'url-test',
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50,
                'proxies': [p['name'] for p in proxies[:50]]
            },
            {
                'name': '📺 哔哩哔哩',
                'type': 'select',
                'proxies': ['🚀 节点选择', '♻️ 自动选择', '🎯 全球直连']
            },
            {
                'name': '🌍 国外媒体',
                'type': 'select',
                'proxies': ['🚀 节点选择', '♻️ 自动选择']
            },
            {
                'name': 'Ⓜ️ 微软服务',
                'type': 'select',
                'proxies': ['🚀 节点选择', '🎯 全球直连']
            },
            {
                'name': '🍎 苹果服务',
                'type': 'select',
                'proxies': ['🚀 节点选择', '🎯 全球直连']
            },
            {
                'name': '🎯 全球直连',
                'type': 'select',
                'proxies': ['DIRECT']
            },
            {
                'name': '🛑 广告拦截',
                'type': 'select',
                'proxies': ['REJECT', 'DIRECT']
            }
        ],
        'rules': [
            # 广告拦截规则
            'DOMAIN-SUFFIX,ads.com,🛑 广告拦截',
            'DOMAIN-KEYWORD,adservice,🛑 广告拦截',
            'DOMAIN-SUFFIX,doubleclick.net,🛑 广告拦截',
            'DOMAIN-SUFFIX,googleadservices.com,🛑 广告拦截',
            
            # Bilibili
            'DOMAIN-SUFFIX,bilibili.com,📺 哔哩哔哩',
            'DOMAIN-SUFFIX,bilibili.tv,📺 哔哩哔哩',
            'DOMAIN-SUFFIX,biliapi.com,📺 哔哩哔哩',
            'DOMAIN-SUFFIX,biliapi.net,📺 哔哩哔哩',
            'DOMAIN-SUFFIX,bilivideo.com,📺 哔哩哔哩',
            
            # 国外媒体
            'DOMAIN-SUFFIX,netflix.com,🌍 国外媒体',
            'DOMAIN-SUFFIX,disneyplus.com,🌍 国外媒体',
            'DOMAIN-SUFFIX,hbo.com,🌍 国外媒体',
            'DOMAIN-SUFFIX,hulu.com,🌍 国外媒体',
            'DOMAIN-SUFFIX,youtube.com,🌍 国外媒体',
            
            # 微软服务
            'DOMAIN-SUFFIX,microsoft.com,Ⓜ️ 微软服务',
            'DOMAIN-SUFFIX,windows.com,Ⓜ️ 微软服务',
            'DOMAIN-SUFFIX,office.com,Ⓜ️ 微软服务',
            'DOMAIN-SUFFIX,live.com,Ⓜ️ 微软服务',
            'DOMAIN-SUFFIX,azure.com,Ⓜ️ 微软服务',
            
            # 苹果服务
            'DOMAIN-SUFFIX,apple.com,🍎 苹果服务',
            'DOMAIN-SUFFIX,icloud.com,🍎 苹果服务',
            'DOMAIN-SUFFIX,appstore.com,🍎 苹果服务',
            'DOMAIN-SUFFIX,itunes.com,🍎 苹果服务',
            
            # 中国大陆直连
            'GEOIP,CN,🎯 全球直连',
            
            # 最终规则
            'MATCH,🚀 节点选择'
        ]
    }
    
    # 写入YAML文件
    output_path = os.path.join('订阅链接', f'{filename}.yaml')
    with open(output_path, 'w', encoding='utf-8') as f:
        # 使用safe_dump避免!!str问题
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    
    print(f"已生成文件: {output_path}，包含 {len(proxies)} 个节点")
    return len(proxies)

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
        return
    
    for filename in os.listdir(input_dir):
        if filename.endswith('.txt'):
            file_path = os.path.join(input_dir, filename)
            print(f"处理文件: {filename}")
            
            # 读取链接
            links = read_links_from_file(file_path)
            if not links:
                print(f"  未找到链接: {filename}")
                continue
            
            all_proxies = []
            
            # 获取每个链接的内容
            for i, link in enumerate(links):
                print(f"  获取链接 [{i+1}/{len(links)}]: {link[:50]}...")
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
                        time.sleep(1)
                else:
                    print(f"    获取内容失败")
            
            # 去重（基于服务器和端口）
            unique_proxies = []
            seen = set()
            for proxy in all_proxies:
                if proxy:
                    key = f"{proxy.get('server', '')}:{proxy.get('port', 0)}:{proxy.get('type', '')}"
                    if key not in seen:
                        seen.add(key)
                        unique_proxies.append(proxy)
            
            # 生成YAML文件
            if unique_proxies:
                base_name = os.path.splitext(filename)[0]
                count = generate_clash_config(unique_proxies, base_name)
                print(f"  总计: {count} 个唯一节点")
            else:
                print(f"  未找到有效节点")
    
    print("订阅生成完成！")

if __name__ == '__main__':
    main()
