#!/usr/bin/env python3
"""
自动订阅生成脚本 - Clash兼容版
支持 hysteria2, ss, vmess, trojan, vless 协议
生成完全符合Clash规范的YAML
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
    
    # 自动补全
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
        # 跳过空值
        if value is None or value == '':
            continue
        
        # 跳过空列表和空字典
        if isinstance(value, (list, dict)) and len(value) == 0:
            continue
        
        # 递归清理嵌套结构
        if isinstance(value, dict):
            cleaned_value = clean_config(value)
            if cleaned_value:  # 只添加非空字典
                cleaned[key] = cleaned_value
        elif isinstance(value, list):
            cleaned_list = [clean_config(item) for item in value if clean_config(item) is not None]
            if cleaned_list:
                cleaned[key] = cleaned_list
        else:
            cleaned[key] = value
    
    return cleaned

def parse_hysteria2(url):
    """解析Hysteria2链接 - Clash兼容格式"""
    try:
        url = url[11:]  # 移除 hysteria2://
        
        # 解析名称
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        # 解析认证和服务器
        if '@' in url:
            auth_part, server_part = url.split('@', 1)
            password = auth_part
        else:
            return None
        
        # 解析服务器、端口和参数
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
        
        # Clash兼容的Hysteria2配置
        config = {
            'name': name if name else f"Hysteria2-{server}:{port}",
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
        }
        
        # 添加可选参数
        if query_params.get('sni'):
            config['sni'] = query_params['sni'][0]
        
        insecure = query_params.get('insecure', ['0'])[0] == '1' or query_params.get('allowInsecure', ['0'])[0] == '1'
        if insecure:
            config['skip-cert-verify'] = True
        
        if query_params.get('alpn'):
            config['alpn'] = query_params['alpn'][0].split(',')
        
        # 带宽设置（Hysteria2可能需要）
        config['down'] = '100 Mbps'
        config['up'] = '100 Mbps'
        
        return clean_config(config)
        
    except Exception as e:
        print(f"  Hysteria2解析失败: {e}")
        return None

def parse_ss(url):
    """解析Shadowsocks链接 - Clash兼容格式"""
    try:
        url = url[5:]  # 移除 ss://
        
        # 解析名称
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        # 尝试Base64解码
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
        
        # 解析服务器和端口
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
        
        # Clash兼容的SS配置
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
    """解析VMess链接 - Clash兼容格式"""
    try:
        encoded = url[8:]  # 移除 vmess://
        decoded = safe_decode_base64(encoded)
        
        if not decoded:
            return None
        
        vmess_config = json.loads(decoded)
        
        # 基础配置
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
        
        # TLS设置
        if vmess_config.get('tls') == 'tls':
            config['tls'] = True
            config['skip-cert-verify'] = vmess_config.get('allowInsecure') in [True, 'true', '1']
        
        # SNI
        sni = vmess_config.get('sni') or vmess_config.get('host')
        if sni:
            config['servername'] = sni
        
        # 网络类型
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
            elif network == 'h2':
                h2_opts = {}
                if vmess_config.get('host'):
                    h2_opts['host'] = [vmess_config['host']]
                if vmess_config.get('path'):
                    h2_opts['path'] = vmess_config['path']
                if h2_opts:
                    config['h2-opts'] = h2_opts
            elif network == 'grpc':
                grpc_opts = {}
                if vmess_config.get('path'):
                    grpc_opts['grpc-service-name'] = vmess_config['path']
                if grpc_opts:
                    config['grpc-opts'] = grpc_opts
        
        return clean_config(config)
        
    except Exception as e:
        print(f"  VMess解析失败: {e}")
        return None

def parse_trojan(url):
    """解析Trojan链接 - Clash兼容格式"""
    try:
        url = url[9:]  # 移除 trojan://
        
        # 解析名称
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        # 解析认证和服务器
        if '@' in url:
            password_part, server_part = url.split('@', 1)
            password = password_part
        else:
            return None
        
        # 解析服务器、端口和参数
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
        
        # Clash兼容的Trojan配置
        config = {
            'name': name if name else f"Trojan-{server}:{port}",
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'sni': query_params.get('sni', [''])[0] or server,
            'skip-cert-verify': query_params.get('allowInsecure', ['0'])[0] == '1' or query_params.get('insecure', ['0'])[0] == '1',
            'udp': True
        }
        
        # 网络类型
        if query_params.get('type'):
            network = query_params['type'][0]
            config['network'] = network
            
            if network == 'ws':
                ws_opts = {}
                if query_params.get('path'):
                    ws_opts['path'] = query_params['path'][0]
                if query_params.get('host'):
                    ws_opts['headers'] = {'Host': query_params['host'][0]}
                if ws_opts:
                    config['ws-opts'] = ws_opts
            elif network == 'grpc':
                grpc_opts = {}
                if query_params.get('serviceName'):
                    grpc_opts['grpc-service-name'] = query_params['serviceName'][0]
                if grpc_opts:
                    config['grpc-opts'] = grpc_opts
        
        return clean_config(config)
        
    except Exception as e:
        print(f"  Trojan解析失败: {e}")
        return None

def parse_vless(url):
    """解析VLESS链接 - 简化版（跳过复杂配置）"""
    try:
        url = url[8:]  # 移除 vless://
        
        # 解析名称
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        # 解析UUID和服务器
        if '@' in url:
            uuid_part, server_part = url.split('@', 1)
            uuid = uuid_part
        else:
            return None
        
        # 解析服务器、端口和参数
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
        
        # VLESS在Clash中支持有限，这里简化处理
        # 如果是Reality协议，可能不被支持，跳过或使用fallback
        security = query_params.get('security', [''])[0]
        
        if security == 'reality':
            # Reality协议可能不被完全支持，使用简化配置或跳过
            print(f"  跳过VLESS Reality协议: {name or server}")
            return None
        
        # 普通VLESS配置
        config = {
            'name': name if name else f"VLESS-{server}:{port}",
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid,
            'udp': True,
        }
        
        # TLS设置
        if security in ['tls', 'xtls', 'reality']:
            config['tls'] = True
            config['skip-cert-verify'] = query_params.get('allowInsecure', ['0'])[0] == '1'
        
        # SNI
        sni = query_params.get('sni', [''])[0] or query_params.get('host', [''])[0] or server
        config['servername'] = sni
        
        # 网络类型
        if query_params.get('type'):
            network = query_params['type'][0]
            config['network'] = network
            
            if network == 'ws':
                ws_opts = {}
                if query_params.get('path'):
                    ws_opts['path'] = query_params['path'][0]
                if query_params.get('host'):
                    ws_opts['headers'] = {'Host': query_params['host'][0]}
                if ws_opts:
                    config['ws-opts'] = ws_opts
        
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
    elif url.startswith('ssr://'):
        print(f"  跳过SSR协议: {url[:50]}...")
        return None
    
    return None

def fetch_subscription(url):
    """获取订阅内容"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/plain, */*',
    }
    
    try:
        print(f"  获取订阅: {url[:80]}...")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        content = response.text.strip()
        
        # 尝试Base64解码
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

def generate_clash_config(proxies, filename):
    """生成完全兼容Clash的配置"""
    if not proxies:
        print("  没有有效节点，创建测试配置")
        # 创建一个简单的测试节点
        proxies = [{
            'name': '测试节点',
            'type': 'ss',
            'server': 'example.com',
            'port': 443,
            'cipher': 'aes-256-gcm',
            'password': 'password',
            'udp': True
        }]
    
    # 确保所有配置都经过清理
    cleaned_proxies = [clean_config(p) for p in proxies if p]
    
    # Clash完全兼容的配置
    config = {
        'port': 7890,
        'socks-port': 7891,
        'mixed-port': 7893,
        'allow-lan': False,  # 安全考虑，默认关闭
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',  # 只监听本地
        'secret': '',
        'dns': {
            'enable': True,
            'ipv6': False,
            'listen': '127.0.0.1:53',
            'default-nameserver': [
                '223.5.5.5',
                '119.29.29.29'
            ],
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'nameserver': [
                'https://doh.pub/dns-query',
                'https://dns.alidns.com/dns-query'
            ],
            'fallback': [
                'https://doh.dns.sb/dns-query',
                'https://dns.cloudflare.com/dns-query'
            ],
            'fallback-filter': {
                'geoip': True,
                'ipcidr': [
                    '240.0.0.0/4'
                ]
            }
        },
        'proxies': cleaned_proxies[:100],  # 限制数量
        'proxy-groups': [
            {
                'name': 'PROXY',
                'type': 'select',
                'proxies': ['DIRECT', 'REJECT', 'Auto'] + [p.get('name', 'Node') for p in cleaned_proxies[:5]]
            },
            {
                'name': 'Auto',
                'type': 'url-test',
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300,
                'proxies': [p.get('name', 'Node') for p in cleaned_proxies[:30]]
            },
            {
                'name': 'Streaming',
                'type': 'select',
                'proxies': ['PROXY', 'Auto', 'DIRECT']
            },
            {
                'name': 'Global',
                'type': 'select',
                'proxies': ['DIRECT']
            }
        ],
        'rules': [
            # 广告拦截
            'DOMAIN-SUFFIX,ads.com,REJECT',
            'DOMAIN-KEYWORD,adsite,REJECT',
            
            # 国内直连
            'DOMAIN-SUFFIX,cn,DIRECT',
            'DOMAIN-SUFFIX,baidu.com,DIRECT',
            'DOMAIN-SUFFIX,qq.com,DIRECT',
            'DOMAIN-SUFFIX,taobao.com,DIRECT',
            'DOMAIN-SUFFIX,jd.com,DIRECT',
            'DOMAIN-SUFFIX,weibo.com,DIRECT',
            
            # 流媒体
            'DOMAIN-SUFFIX,netflix.com,Streaming',
            'DOMAIN-SUFFIX,disneyplus.com,Streaming',
            'DOMAIN-SUFFIX,youtube.com,Streaming',
            'DOMAIN-SUFFIX,bilibili.com,DIRECT',
            
            # 国外网站
            'DOMAIN-SUFFIX,google.com,PROXY',
            'DOMAIN-SUFFIX,github.com,PROXY',
            'DOMAIN-SUFFIX,twitter.com,PROXY',
            
            # GEOIP
            'GEOIP,CN,DIRECT',
            
            # 最终规则
            'MATCH,PROXY'
        ]
    }
    
    # 清理整个配置
    config = clean_config(config)
    
    # 写入文件
    output_dir = '订阅链接'
    os.makedirs(output_dir, exist_ok=True)
    
    output_path = os.path.join(output_dir, f'{filename}.yaml')
    
    # 使用安全的YAML转储
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, 
                 allow_unicode=True, 
                 default_flow_style=False, 
                 sort_keys=False,
                 width=float("inf"),
                 explicit_start=False)
    
    print(f"  生成配置文件: {output_path}")
    print(f"  包含 {len(cleaned_proxies[:100])} 个节点")
    
    # 验证YAML格式
    try:
        with open(output_path, 'r', encoding='utf-8') as f:
            test_config = yaml.safe_load(f)
        print("  YAML格式验证成功")
    except Exception as e:
        print(f"  YAML格式验证失败: {e}")
    
    return len(cleaned_proxies[:100])

def main():
    """主函数"""
    print("开始生成Clash订阅...")
    
    # 确保目录存在
    input_dir = '输入源'
    output_dir = '订阅链接'
    
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    
    # 清理输出目录
    import glob
    for old_file in glob.glob(os.path.join(output_dir, '*.yaml')):
        try:
            os.remove(old_file)
        except:
            pass
    
    # 查找输入文件
    txt_files = []
    for file in os.listdir(input_dir):
        if file.endswith('.txt'):
            txt_files.append(file)
    
    if not txt_files:
        print(f"没有找到输入文件，请在 '{input_dir}' 中创建.txt文件")
        return
    
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
            
            # 避免请求过快
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
        
        # 生成配置
        if unique_proxies:
            base_name = os.path.splitext(filename)[0]
            generate_clash_config(unique_proxies, base_name)
        else:
            print("  没有有效节点")
    
    print("\n生成完成！")

if __name__ == '__main__':
    main()
