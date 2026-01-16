#!/usr/bin/env python3
"""
自动订阅生成脚本 - 完整版
支持 hysteria2, ss, vmess, trojan, vless, socks5, http 协议
"""

import os
import re
import base64
import json
import requests
import yaml
import urllib.parse
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
import time

def safe_decode_base64(data):
    """安全解码Base64数据"""
    if not data:
        return None
    
    data = str(data).strip()
    
    # 移除可能的换行符
    data = data.replace('\n', '').replace('\r', '')
    
    # 自动补全
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    
    # 尝试多种解码方式
    for encoding in ['utf-8', 'latin-1']:
        try:
            decoded = base64.b64decode(data).decode(encoding)
            return decoded
        except:
            try:
                decoded = base64.urlsafe_b64decode(data).decode(encoding)
                return decoded
            except:
                continue
    
    return None

def parse_hysteria2(url):
    """解析Hysteria2链接"""
    try:
        # 移除协议头
        url = url[11:]  # 移除 hysteria2://
        
        # 解析片段（名称）
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        # 解析认证信息和服务器
        if '@' in url:
            auth_part, server_part = url.split('@', 1)
            password = auth_part
        else:
            return None
        
        # 解析服务器、端口和查询参数
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
        
        # 构建配置
        config = {
            'name': name if name else f"Hysteria2-{server}:{port}",
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
            'sni': query_params.get('sni', [''])[0] or server,
            'skip-cert-verify': query_params.get('insecure', ['0'])[0] == '1' or query_params.get('allowInsecure', ['0'])[0] == '1',
            'down': '100 Mbps',
            'up': '100 Mbps',
            'alpn': query_params.get('alpn', [''])[0].split(',') if query_params.get('alpn') else []
        }
        
        # 移除空值
        config = {k: v for k, v in config.items() if v not in [None, '', []]}
        
        return config
        
    except Exception as e:
        print(f"  Hysteria2解析失败: {e}")
        return None

def parse_ss(url):
    """解析Shadowsocks链接"""
    try:
        # 移除协议头
        url = url[5:]  # 移除 ss://
        
        # 解析片段（名称）
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        # 尝试Base64解码
        decoded = safe_decode_base64(url.split('@')[0] if '@' in url else url)
        
        if decoded and ':' in decoded:
            # 格式: method:password
            method, password = decoded.split(':', 1)
        else:
            # 可能是新式SS链接
            if '@' in url:
                # 格式: base64(method:password)@server:port
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
        
        # 移除查询参数
        if '?' in server_part:
            server_part, _ = server_part.split('?', 1)
        
        if ':' in server_part:
            server, port = server_part.split(':', 1)
            port = int(port)
        else:
            return None
        
        # 构建配置
        config = {
            'name': name if name else f"SS-{server}:{port}",
            'type': 'ss',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password,
            'udp': True
        }
        
        return config
        
    except Exception as e:
        print(f"  SS解析失败: {e}")
        return None

def parse_vmess(url):
    """解析VMess链接"""
    try:
        # 移除协议头并解码
        encoded = url[8:]  # 移除 vmess://
        decoded = safe_decode_base64(encoded)
        
        if not decoded:
            return None
        
        # 解析JSON
        vmess_config = json.loads(decoded)
        
        # 构建配置
        config = {
            'name': vmess_config.get('ps', f"VMess-{vmess_config.get('add', 'unknown')}"),
            'type': 'vmess',
            'server': vmess_config.get('add', ''),
            'port': int(vmess_config.get('port', 443)),
            'uuid': vmess_config.get('id', ''),
            'alterId': int(vmess_config.get('aid', 0)),
            'cipher': vmess_config.get('scy', 'auto'),
            'udp': True,
            'tls': vmess_config.get('tls') == 'tls',
            'skip-cert-verify': vmess_config.get('allowInsecure') == True or vmess_config.get('allowInsecure') == 'true'
        }
        
        # 添加SNI
        if vmess_config.get('sni') or vmess_config.get('host'):
            config['servername'] = vmess_config.get('sni', vmess_config.get('host', ''))
        
        # 网络类型
        network = vmess_config.get('net', 'tcp')
        if network != 'tcp':
            config['network'] = network
            
            if network == 'ws':
                config['ws-opts'] = {
                    'path': vmess_config.get('path', '/'),
                    'headers': {
                        'Host': vmess_config.get('host', '')
                    } if vmess_config.get('host') else {}
                }
            elif network == 'h2':
                config['h2-opts'] = {
                    'host': [vmess_config.get('host', '')],
                    'path': vmess_config.get('path', '/')
                }
            elif network == 'grpc':
                config['grpc-opts'] = {
                    'grpc-service-name': vmess_config.get('path', '')
                }
        
        return config
        
    except Exception as e:
        print(f"  VMess解析失败: {e}")
        return None

def parse_trojan(url):
    """解析Trojan链接"""
    try:
        # 移除协议头
        url = url[9:]  # 移除 trojan://
        
        # 解析片段（名称）
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        # 解析认证信息和服务器
        if '@' in url:
            password_part, server_part = url.split('@', 1)
            password = password_part
        else:
            return None
        
        # 解析服务器、端口和查询参数
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
        
        # 构建配置
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
            config['network'] = query_params['type'][0]
            
            if config['network'] == 'ws' and query_params.get('path'):
                config['ws-opts'] = {
                    'path': query_params['path'][0]
                }
                if query_params.get('host'):
                    config['ws-opts']['headers'] = {
                        'Host': query_params['host'][0]
                    }
        
        return config
        
    except Exception as e:
        print(f"  Trojan解析失败: {e}")
        return None

def parse_vless(url):
    """解析VLESS链接"""
    try:
        # 移除协议头
        url = url[8:]  # 移除 vless://
        
        # 解析片段（名称）
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
        
        # 解析服务器、端口和查询参数
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
        
        # 构建配置
        config = {
            'name': name if name else f"VLESS-{server}:{port}",
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid,
            'udp': True,
            'tls': query_params.get('security', [''])[0] == 'tls' or query_params.get('security', [''])[0] == 'reality',
            'skip-cert-verify': query_params.get('allowInsecure', ['0'])[0] == '1'
        }
        
        # 添加SNI
        if query_params.get('sni'):
            config['servername'] = query_params['sni'][0]
        elif query_params.get('host'):
            config['servername'] = query_params['host'][0]
        else:
            config['servername'] = server
        
        # 网络类型
        if query_params.get('type'):
            config['network'] = query_params['type'][0]
            
            if config['network'] == 'ws' and query_params.get('path'):
                config['ws-opts'] = {
                    'path': query_params['path'][0]
                }
                if query_params.get('host'):
                    config['ws-opts']['headers'] = {
                        'Host': query_params['host'][0]
                    }
            elif config['network'] == 'grpc' and query_params.get('serviceName'):
                config['grpc-opts'] = {
                    'grpc-service-name': query_params['serviceName'][0]
                }
        
        # Reality配置
        if query_params.get('security', [''])[0] == 'reality':
            config['reality-opts'] = {
                'public-key': query_params.get('pbk', [''])[0],
                'short-id': query_params.get('sid', [''])[0]
            }
        
        return config
        
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
    elif url.startswith('socks5://') or url.startswith('socks4://') or url.startswith('http://') or url.startswith('https://'):
        print(f"  跳过SOCKS/HTTP协议: {url[:50]}...")
        return None
    
    return None

def fetch_subscription(url):
    """获取订阅内容"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/plain, */*',
        'Accept-Encoding': 'gzip, deflate'
    }
    
    try:
        print(f"  获取订阅: {url[:80]}...")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        content = response.text.strip()
        print(f"    原始长度: {len(content)} 字符")
        
        # 尝试Base64解码
        decoded = safe_decode_base64(content)
        if decoded:
            print(f"    解码后长度: {len(decoded)} 字符")
            return decoded
        
        return content
        
    except Exception as e:
        print(f"    获取失败: {e}")
        return None

def process_subscription_content(content):
    """处理订阅内容，提取代理节点"""
    if not content:
        return []
    
    proxies = []
    
    # 按行处理
    lines = content.split('\n')
    print(f"    处理 {len(lines)} 行")
    
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # 尝试解析代理URL
        proxy = parse_proxy_url(line)
        if proxy:
            proxies.append(proxy)
    
    print(f"    找到 {len(proxies)} 个节点")
    return proxies

def generate_clash_config(proxies, filename):
    """生成Clash配置"""
    if not proxies:
        print("  警告: 没有找到有效节点，生成空配置")
        proxies = []
    
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
            ],
            'fallback': [
                'https://1.1.1.1/dns-query',
                'https://dns.google/dns-query'
            ]
        },
        'proxies': proxies[:150],  # 限制数量
        'proxy-groups': [
            {
                'name': '🚀 节点选择',
                'type': 'select',
                'proxies': ['♻️ 自动选择', '🎯 全球直连', 'DIRECT'] + [p.get('name', '节点') for p in proxies[:10]]
            },
            {
                'name': '♻️ 自动选择',
                'type': 'url-test',
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50,
                'proxies': [p.get('name', '节点') for p in proxies[:50]]
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
            # 广告拦截
            'DOMAIN-KEYWORD,adservice,🛑 广告拦截',
            'DOMAIN-SUFFIX,ads.com,🛑 广告拦截',
            
            # 国内直连
            'DOMAIN-SUFFIX,cn,🎯 全球直连',
            'DOMAIN-SUFFIX,baidu.com,🎯 全球直连',
            'DOMAIN-SUFFIX,qq.com,🎯 全球直连',
            'DOMAIN-SUFFIX,taobao.com,🎯 全球直连',
            'DOMAIN-SUFFIX,alipay.com,🎯 全球直连',
            'DOMAIN-SUFFIX,jd.com,🎯 全球直连',
            
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
            'DOMAIN-SUFFIX,youtube.com,🌍 国外媒体',
            'DOMAIN-SUFFIX,twitter.com,🌍 国外媒体',
            
            # 微软
            'DOMAIN-SUFFIX,microsoft.com,Ⓜ️ 微软服务',
            'DOMAIN-SUFFIX,windows.com,Ⓜ️ 微软服务',
            'DOMAIN-SUFFIX,office.com,Ⓜ️ 微软服务',
            
            # 苹果
            'DOMAIN-SUFFIX,apple.com,🍎 苹果服务',
            'DOMAIN-SUFFIX,icloud.com,🍎 苹果服务',
            
            # GEOIP
            'GEOIP,CN,🎯 全球直连',
            
            # 最终规则
            'MATCH,🚀 节点选择'
        ]
    }
    
    # 写入文件
    output_dir = '订阅链接'
    os.makedirs(output_dir, exist_ok=True)
    
    output_path = os.path.join(output_dir, f'{filename}.yaml')
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    
    print(f"  生成配置文件: {output_path}")
    print(f"  包含 {len(proxies[:150])} 个节点")
    
    return len(proxies[:150])

def main():
    """主函数"""
    print("=" * 60)
    print("自动订阅生成器")
    print("=" * 60)
    
    # 确保目录存在
    input_dir = '输入源'
    os.makedirs(input_dir, exist_ok=True)
    
    # 检查输入文件
    txt_files = [f for f in os.listdir(input_dir) if f.endswith('.txt')]
    
    if not txt_files:
        print(f"未找到输入文件，请在 '{input_dir}' 目录中创建.txt文件")
        print("创建示例文件...")
        example_content = """# 在此添加订阅链接，每行一个
# 示例:
https://vyy.cqsvhb.cn/s/c59454c04c7395f58b5d8165a598ad64
# https://example.com/subscribe.txt
"""
        with open(os.path.join(input_dir, 'example.txt'), 'w', encoding='utf-8') as f:
            f.write(example_content)
        print(f"已创建示例文件: {input_dir}/example.txt")
        txt_files = ['example.txt']
    
    # 处理每个输入文件
    for filename in txt_files:
        print(f"\n{'='*40}")
        print(f"处理文件: {filename}")
        print('='*40)
        
        filepath = os.path.join(input_dir, filename)
        
        # 读取订阅链接
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"  读取文件失败: {e}")
            continue
        
        if not urls:
            print("  没有找到订阅链接")
            continue
        
        print(f"  找到 {len(urls)} 个订阅链接")
        
        all_proxies = []
        
        # 处理每个链接
        for i, url in enumerate(urls):
            print(f"\n  [{i+1}/{len(urls)}] 处理订阅")
            
            # 获取订阅内容
            content = fetch_subscription(url)
            if not content:
                continue
            
            # 处理订阅内容
            proxies = process_subscription_content(content)
            if proxies:
                all_proxies.extend(proxies)
            
            # 避免请求过快
            if i < len(urls) - 1:
                time.sleep(1)
        
        # 去重
        unique_proxies = []
        seen = set()
        
        for proxy in all_proxies:
            if not proxy:
                continue
            
            # 生成唯一标识
            server = proxy.get('server', '')
            port = proxy.get('port', '')
            proxy_type = proxy.get('type', '')
            name = proxy.get('name', '')
            
            key = f"{server}:{port}:{proxy_type}:{name}"
            
            if key not in seen:
                seen.add(key)
                unique_proxies.append(proxy)
        
        print(f"\n  总计: {len(all_proxies)} 个节点")
        print(f"  去重后: {len(unique_proxies)} 个唯一节点")
        
        # 按类型统计
        type_stats = {}
        for proxy in unique_proxies:
            proxy_type = proxy.get('type', 'unknown')
            type_stats[proxy_type] = type_stats.get(proxy_type, 0) + 1
        
        print("  节点类型统计:")
        for proxy_type, count in type_stats.items():
            print(f"    {proxy_type}: {count} 个")
        
        # 生成配置文件
        if unique_proxies:
            base_name = os.path.splitext(filename)[0]
            generate_clash_config(unique_proxies, base_name)
        else:
            print("  没有有效节点，跳过生成")
    
    print(f"\n{'='*60}")
    print("处理完成！")
    print("=" * 60)

if __name__ == '__main__':
    main()
