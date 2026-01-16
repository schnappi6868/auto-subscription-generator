#!/usr/bin/env python3
"""
自动订阅生成脚本 - 简化版
支持 hysteria2, ss, vmess, trojan, vless 协议
生成简化配置：只有节点选择和自动选择两个策略组
所有国内IP直连
"""

import os
import re
import base64
import json
import requests
import yaml
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
import time

def safe_decode_base64(data):
    """安全解码Base64数据"""
    if not data:
        return None
    
    data = str(data).strip()
    data = data.replace('\n', '').replace('\r', '')
    
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    
    try:
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except:
        try:
            return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        except:
            return None

def clean_config(config):
    """清理配置，移除空值和无效字段"""
    if not isinstance(config, dict):
        return config
    
    cleaned = {}
    for key, value in config.items():
        if value is None or value == '':
            continue
        
        if isinstance(value, (list, dict)) and len(value) == 0:
            continue
        
        if isinstance(value, dict):
            cleaned_value = clean_config(value)
            if cleaned_value:
                cleaned[key] = cleaned_value
        elif isinstance(value, list):
            cleaned_list = [clean_config(item) for item in value if clean_config(item) is not None]
            if cleaned_list:
                cleaned[key] = cleaned_list
        else:
            cleaned[key] = value
    
    return cleaned

def parse_hysteria2(url):
    """解析Hysteria2链接"""
    try:
        url = url[11:]  # 移除 hysteria2://
        
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        if '@' in url:
            auth_part, server_part = url.split('@', 1)
            password = auth_part
        else:
            return None
        
        server = ""
        port = 443
        query_params = {}
        
        if '?' in server_part:
            server_port_part, query_str = server_part.split('?', 1)
            query_params = parse_qs(query_str)
        else:
            server_port_part = server_part
        
        if ':' in server_port_part:
            server, port_str = server_port_part.split(':', 1)
            port = int(port_str)
        else:
            server = server_port_part
        
        config = {
            'name': name if name else f"Hysteria2-{server}:{port}",
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
        }
        
        if query_params.get('sni'):
            config['sni'] = query_params['sni'][0]
        
        insecure = query_params.get('insecure', ['0'])[0] == '1' or query_params.get('allowInsecure', ['0'])[0] == '1'
        if insecure:
            config['skip-cert-verify'] = True
        
        if query_params.get('alpn'):
            config['alpn'] = query_params['alpn'][0].split(',')
        
        return clean_config(config)
        
    except Exception as e:
        print(f"  Hysteria2解析失败: {e}")
        return None

def parse_ss(url):
    """解析Shadowsocks链接"""
    try:
        url = url[5:]  # 移除 ss://
        
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        decoded = safe_decode_base64(url.split('@')[0] if '@' in url else url)
        
        if decoded and ':' in decoded:
            method, password = decoded.split(':', 1)
        else:
            if '@' in url:
                encoded_auth, server_part = url.split('@', 1)
                decoded_auth = safe_decode_base64(encoded_auth)
                if decoded_auth and ':' in decoded_auth:
                    method, password = decoded_auth.split(':', 1)
                else:
                    return None
            else:
                return None
        
        if '@' in url:
            _, server_part = url.split('@', 1)
        else:
            server_part = url
        
        if '?' in server_part:
            server_part, _ = server_part.split('?', 1)
        
        if ':' in server_part:
            server, port = server_part.split(':', 1)
            port = int(port)
        else:
            return None
        
        config = {
            'name': name if name else f"SS-{server}:{port}",
            'type': 'ss',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password,
            'udp': True
        }
        
        return clean_config(config)
        
    except Exception as e:
        print(f"  SS解析失败: {e}")
        return None

def parse_vmess(url):
    """解析VMess链接"""
    try:
        encoded = url[8:]  # 移除 vmess://
        decoded = safe_decode_base64(encoded)
        
        if not decoded:
            return None
        
        vmess_config = json.loads(decoded)
        
        config = {
            'name': vmess_config.get('ps', f"VMess-{vmess_config.get('add', 'unknown')}"),
            'type': 'vmess',
            'server': vmess_config.get('add', ''),
            'port': int(vmess_config.get('port', 443)),
            'uuid': vmess_config.get('id', ''),
            'alterId': int(vmess_config.get('aid', 0)),
            'cipher': vmess_config.get('scy', 'auto'),
            'udp': True,
        }
        
        if vmess_config.get('tls') == 'tls':
            config['tls'] = True
            config['skip-cert-verify'] = vmess_config.get('allowInsecure') in [True, 'true', '1']
        
        sni = vmess_config.get('sni') or vmess_config.get('host')
        if sni:
            config['servername'] = sni
        
        network = vmess_config.get('net', 'tcp')
        if network != 'tcp':
            config['network'] = network
            
            if network == 'ws':
                ws_opts = {}
                if vmess_config.get('path'):
                    ws_opts['path'] = vmess_config['path']
                if vmess_config.get('host'):
                    ws_opts['headers'] = {'Host': vmess_config['host']}
                if ws_opts:
                    config['ws-opts'] = ws_opts
        
        return clean_config(config)
        
    except Exception as e:
        print(f"  VMess解析失败: {e}")
        return None

def parse_trojan(url):
    """解析Trojan链接"""
    try:
        url = url[9:]  # 移除 trojan://
        
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        if '@' in url:
            password_part, server_part = url.split('@', 1)
            password = password_part
        else:
            return None
        
        server = ""
        port = 443
        query_params = {}
        
        if '?' in server_part:
            server_port_part, query_str = server_part.split('?', 1)
            query_params = parse_qs(query_str)
        else:
            server_port_part = server_part
        
        if ':' in server_port_part:
            server, port_str = server_port_part.split(':', 1)
            port = int(port_str)
        else:
            server = server_port_part
        
        config = {
            'name': name if name else f"Trojan-{server}:{port}",
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'sni': query_params.get('sni', [''])[0] or server,
            'skip-cert-verify': query_params.get('allowInsecure', ['0'])[0] == '1',
            'udp': True
        }
        
        return clean_config(config)
        
    except Exception as e:
        print(f"  Trojan解析失败: {e}")
        return None

def parse_vless(url):
    """解析VLESS链接"""
    try:
        url = url[8:]  # 移除 vless://
        
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        if '@' in url:
            uuid_part, server_part = url.split('@', 1)
            uuid = uuid_part
        else:
            return None
        
        server = ""
        port = 443
        query_params = {}
        
        if '?' in server_part:
            server_port_part, query_str = server_part.split('?', 1)
            query_params = parse_qs(query_str)
        else:
            server_port_part = server_part
        
        if ':' in server_port_part:
            server, port_str = server_port_part.split(':', 1)
            port = int(port_str)
        else:
            server = server_port_part
        
        config = {
            'name': name if name else f"VLESS-{server}:{port}",
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid,
            'udp': True,
        }
        
        security = query_params.get('security', [''])[0]
        if security in ['tls', 'xtls']:
            config['tls'] = True
            config['skip-cert-verify'] = query_params.get('allowInsecure', ['0'])[0] == '1'
        
        sni = query_params.get('sni', [''])[0] or server
        config['servername'] = sni
        
        return clean_config(config)
        
    except Exception as e:
        print(f"  VLESS解析失败: {e}")
        return None

def parse_proxy_url(url):
    """解析代理URL"""
    if not url or not isinstance(url, str):
        return None
    
    url = url.strip()
    
    if url.startswith('hysteria2://'):
        return parse_hysteria2(url)
    elif url.startswith('ss://'):
        return parse_ss(url)
    elif url.startswith('vmess://'):
        return parse_vmess(url)
    elif url.startswith('trojan://'):
        return parse_trojan(url)
    elif url.startswith('vless://'):
        return parse_vless(url)
    
    return None

def fetch_subscription(url):
    """获取订阅内容"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        content = response.text.strip()
        decoded = safe_decode_base64(content)
        
        if decoded:
            return decoded
        
        return content
        
    except Exception as e:
        print(f"    获取失败: {e}")
        return None

def process_subscription_content(content):
    """处理订阅内容"""
    if not content:
        return []
    
    proxies = []
    lines = content.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        proxy = parse_proxy_url(line)
        if proxy:
            proxies.append(proxy)
    
    return proxies

def generate_simple_clash_config(proxies, filename):
    """生成简化版Clash配置 - 只有两个策略组"""
    if not proxies:
        print("  没有有效节点，创建测试配置")
        proxies = [{
            'name': '测试节点',
            'type': 'ss',
            'server': 'example.com',
            'port': 443,
            'cipher': 'aes-256-gcm',
            'password': 'password',
            'udp': True
        }]
    
    cleaned_proxies = [clean_config(p) for p in proxies if p]
    
    # 简化配置：只有两个策略组
    config = {
        # 基础设置
        'port': 7890,
        'socks-port': 7891,
        'mixed-port': 7893,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        
        # DNS设置
        'dns': {
            'enable': True,
            'ipv6': False,
            'listen': '127.0.0.1:53',
            'default-nameserver': ['223.5.5.5', '119.29.29.29'],
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'nameserver': ['https://doh.pub/dns-query'],
            'fallback': ['https://dns.cloudflare.com/dns-query'],
            'fallback-filter': {
                'geoip': True,
                'ipcidr': ['240.0.0.0/4']
            }
        },
        
        # 代理节点
        'proxies': cleaned_proxies[:200],  # 最多200个节点
        
        # 策略组 - 只有两个
        'proxy-groups': [
            {
                'name': '节点选择',
                'type': 'select',
                'proxies': ['自动选择', 'DIRECT']
            },
            {
                'name': '自动选择',
                'type': 'url-test',  # 自动选择低延迟节点
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50,
                'proxies': [p.get('name', '节点') for p in cleaned_proxies[:200]]
            }
        ],
        
        # 规则 - 国内IP全部直连
        'rules': [
            # 国内域名直连
            'DOMAIN-SUFFIX,cn,DIRECT',
            'DOMAIN-SUFFIX,baidu.com,DIRECT',
            'DOMAIN-SUFFIX,qq.com,DIRECT',
            'DOMAIN-SUFFIX,taobao.com,DIRECT',
            'DOMAIN-SUFFIX,jd.com,DIRECT',
            'DOMAIN-SUFFIX,weibo.com,DIRECT',
            'DOMAIN-SUFFIX,sina.com,DIRECT',
            'DOMAIN-SUFFIX,sohu.com,DIRECT',
            'DOMAIN-SUFFIX,163.com,DIRECT',
            'DOMAIN-SUFFIX,126.com,DIRECT',
            'DOMAIN-SUFFIX,alibaba.com,DIRECT',
            'DOMAIN-SUFFIX,alicdn.com,DIRECT',
            'DOMAIN-SUFFIX,alipay.com,DIRECT',
            'DOMAIN-SUFFIX,wechat.com,DIRECT',
            'DOMAIN-SUFFIX,tencent.com,DIRECT',
            'DOMAIN-SUFFIX,bilibili.com,DIRECT',
            'DOMAIN-SUFFIX,zhihu.com,DIRECT',
            'DOMAIN-SUFFIX,douyin.com,DIRECT',
            'DOMAIN-SUFFIX,toutiao.com,DIRECT',
            'DOMAIN-SUFFIX,bytedance.com,DIRECT',
            'DOMAIN-SUFFIX,meituan.com,DIRECT',
            'DOMAIN-SUFFIX,dianping.com,DIRECT',
            'DOMAIN-SUFFIX,ctrip.com,DIRECT',
            'DOMAIN-SUFFIX,huya.com,DIRECT',
            'DOMAIN-SUFFIX,douyu.com,DIRECT',
            
            # 国内IP段直连
            'IP-CIDR,1.0.1.0/24,DIRECT',
            'IP-CIDR,1.0.2.0/23,DIRECT',
            'IP-CIDR,1.0.8.0/21,DIRECT',
            'IP-CIDR,1.0.32.0/19,DIRECT',
            'IP-CIDR,1.1.0.0/24,DIRECT',
            'IP-CIDR,1.1.2.0/23,DIRECT',
            'IP-CIDR,1.1.4.0/22,DIRECT',
            'IP-CIDR,1.1.8.0/21,DIRECT',
            'IP-CIDR,1.1.16.0/20,DIRECT',
            'IP-CIDR,1.1.32.0/19,DIRECT',
            'IP-CIDR,1.2.0.0/23,DIRECT',
            'IP-CIDR,1.2.2.0/24,DIRECT',
            'IP-CIDR,1.2.4.0/22,DIRECT',
            'IP-CIDR,1.2.8.0/21,DIRECT',
            'IP-CIDR,1.2.16.0/20,DIRECT',
            'IP-CIDR,1.2.32.0/19,DIRECT',
            'IP-CIDR,1.2.64.0/18,DIRECT',
            'IP-CIDR,1.3.0.0/16,DIRECT',
            'IP-CIDR,1.4.1.0/24,DIRECT',
            'IP-CIDR,1.4.2.0/23,DIRECT',
            'IP-CIDR,1.4.4.0/22,DIRECT',
            'IP-CIDR,1.4.8.0/21,DIRECT',
            'IP-CIDR,1.4.16.0/20,DIRECT',
            'IP-CIDR,1.4.32.0/19,DIRECT',
            'IP-CIDR,1.4.64.0/18,DIRECT',
            'IP-CIDR,1.8.0.0/16,DIRECT',
            'IP-CIDR,1.10.0.0/21,DIRECT',
            'IP-CIDR,1.10.8.0/23,DIRECT',
            'IP-CIDR,1.10.11.0/24,DIRECT',
            'IP-CIDR,1.10.12.0/22,DIRECT',
            'IP-CIDR,1.10.16.0/20,DIRECT',
            'IP-CIDR,1.10.32.0/19,DIRECT',
            'IP-CIDR,1.10.64.0/18,DIRECT',
            'IP-CIDR,1.12.0.0/14,DIRECT',
            'IP-CIDR,1.24.0.0/13,DIRECT',
            'IP-CIDR,1.45.0.0/16,DIRECT',
            'IP-CIDR,1.48.0.0/15,DIRECT',
            'IP-CIDR,1.50.0.0/16,DIRECT',
            'IP-CIDR,1.51.0.0/16,DIRECT',
            'IP-CIDR,1.56.0.0/13,DIRECT',
            'IP-CIDR,1.68.0.0/14,DIRECT',
            'IP-CIDR,1.80.0.0/13,DIRECT',
            'IP-CIDR,1.88.0.0/14,DIRECT',
            'IP-CIDR,1.92.0.0/15,DIRECT',
            'IP-CIDR,1.94.0.0/15,DIRECT',
            'IP-CIDR,1.116.0.0/14,DIRECT',
            'IP-CIDR,1.180.0.0/14,DIRECT',
            'IP-CIDR,1.184.0.0/15,DIRECT',
            'IP-CIDR,1.188.0.0/14,DIRECT',
            'IP-CIDR,1.192.0.0/13,DIRECT',
            'IP-CIDR,1.202.0.0/15,DIRECT',
            'IP-CIDR,1.204.0.0/14,DIRECT',
            
            # GEOIP中国直连（这个规则必须在IP-CIDR之后）
            'GEOIP,CN,DIRECT',
            
            # 最终规则 - 其他所有流量走节点选择
            'MATCH,节点选择'
        ]
    }
    
    config = clean_config(config)
    
    # 写入文件
    output_dir = '订阅链接'
    os.makedirs(output_dir, exist_ok=True)
    
    output_path = os.path.join(output_dir, f'{filename}.yaml')
    
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, 
                 allow_unicode=True, 
                 default_flow_style=False, 
                 sort_keys=False,
                 width=float("inf"))
    
    print(f"  生成配置文件: {output_path}")
    print(f"  包含 {len(cleaned_proxies[:200])} 个节点")
    
    return len(cleaned_proxies[:200])

def main():
    """主函数"""
    print("开始生成简化版Clash订阅...")
    
    input_dir = '输入源'
    os.makedirs(input_dir, exist_ok=True)
    
    # 查找输入文件
    txt_files = [f for f in os.listdir(input_dir) if f.endswith('.txt')]
    
    if not txt_files:
        print(f"没有找到输入文件，请在 '{input_dir}' 中创建.txt文件")
        return
    
    # 清理输出目录
    output_dir = '订阅链接'
    os.makedirs(output_dir, exist_ok=True)
    import glob
    for old_file in glob.glob(os.path.join(output_dir, '*.yaml')):
        try:
            os.remove(old_file)
        except:
            pass
    
    # 处理每个文件
    for filename in txt_files:
        print(f"\n处理文件: {filename}")
        filepath = os.path.join(input_dir, filename)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"  读取失败: {e}")
            continue
        
        if not urls:
            print("  没有订阅链接")
            continue
        
        print(f"  找到 {len(urls)} 个订阅链接")
        
        all_proxies = []
        
        for i, url in enumerate(urls):
            print(f"  [{i+1}/{len(urls)}] 处理: {url[:60]}...")
            
            content = fetch_subscription(url)
            if content:
                proxies = process_subscription_content(content)
                if proxies:
                    all_proxies.extend(proxies)
                    print(f"    找到 {len(proxies)} 个节点")
            
            if i < len(urls) - 1:
                time.sleep(1)
        
        # 去重
        unique_proxies = []
        seen = set()
        
        for proxy in all_proxies:
            if not proxy:
                continue
            
            key = f"{proxy.get('server', '')}:{proxy.get('port', '')}:{proxy.get('type', '')}"
            if key not in seen:
                seen.add(key)
                unique_proxies.append(proxy)
        
        print(f"  总计: {len(all_proxies)} 个节点，去重后: {len(unique_proxies)} 个")
        
        # 生成简化配置
        if unique_proxies:
            base_name = os.path.splitext(filename)[0]
            generate_simple_clash_config(unique_proxies, base_name)
        else:
            print("  没有有效节点")
    
    print("\n生成完成！")

if __name__ == '__main__':
    main()
