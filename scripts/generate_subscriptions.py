#!/usr/bin/env python3
"""
自动订阅生成脚本 - 完整版
支持所有主流代理协议：hysteria2, ss, vmess, trojan, vless, ssr, wireguard, tuic, juicity, reality
"""

import os
import re
import base64
import json
import requests
import yaml
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs, unquote, quote
import time
import hashlib

def decode_base64(data):
    """解码Base64数据，自动补全，支持URL安全的Base64"""
    if not data or not isinstance(data, str):
        return None
    
    data = data.strip()
    if not data:
        return None
    
    # 移除可能的换行符
    data = data.replace('\n', '').replace('\r', '')
    
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    
    try:
        # 先尝试标准Base64
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except:
        try:
            # 再尝试URL安全的Base64
            return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        except:
            # 尝试处理可能的Unicode字符
            try:
                data_bytes = data.encode('utf-8')
                return base64.b64decode(data_bytes).decode('utf-8', errors='ignore')
            except:
                print(f"Base64解码失败: {data[:50]}...")
                return None

def parse_hysteria2(hysteria2_url):
    """解析Hysteria2链接"""
    try:
        # 移除 hysteria2:// 前缀
        url = hysteria2_url[11:]
        
        # 解析URL
        if '#' in url:
            url_part, fragment = url.split('#', 1)
            name = unquote(fragment)  # URL解码
        else:
            url_part = url
            name = ""
        
        # 分离认证信息和服务器
        if '@' in url_part:
            auth_part, server_part = url_part.split('@', 1)
            password = auth_part
        else:
            # 可能没有密码
            server_part = url_part
            password = ""
        
        # 解析服务器和端口
        server = ""
        port = 0
        
        if '?' in server_part:
            server_port_part, query_part = server_part.split('?', 1)
            if ':' in server_port_part:
                server, port_str = server_port_part.split(':', 1)
                try:
                    port = int(port_str)
                except:
                    port = 443
            else:
                server = server_port_part
                port = 443
            
            # 解析查询参数
            query_params = parse_qs(query_part)
        else:
            if ':' in server_part:
                server, port_str = server_part.split(':', 1)
                try:
                    port = int(port_str)
                except:
                    port = 443
            else:
                server = server_part
                port = 443
            query_params = {}
        
        # 构建配置
        config = {
            'name': name if name else f"Hysteria2-{server}:{port}",
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
        }
        
        # 添加可选参数
        if 'sni' in query_params:
            config['sni'] = query_params['sni'][0]
        if 'insecure' in query_params:
            config['skip-cert-verify'] = query_params['insecure'][0] == '1'
        if 'obfs' in query_params:
            config['obfs'] = query_params['obfs'][0]
        if 'obfs-password' in query_params:
            config['obfs-password'] = query_params['obfs-password'][0]
        if 'alpn' in query_params:
            config['alpn'] = [alpn.strip() for alpn in query_params['alpn'][0].split(',')]
        
        # 移除空值
        config = {k: v for k, v in config.items() if v not in [None, '', []]}
        
        return config
        
    except Exception as e:
        print(f"解析Hysteria2链接失败 {hysteria2_url[:50]}: {e}")
        return None

def parse_ss_complex(ss_url):
    """解析复杂格式的SS链接"""
    try:
        # 移除 ss:// 前缀
        url = ss_url[5:]
        
        # 获取名称
        name = ""
        if '#' in url:
            url_part, fragment = url.split('#', 1)
            name = unquote(fragment)
        else:
            url_part = url
        
        # 尝试多种解析方式
        methods = [
            # 方式1: Base64编码的用户信息@服务器:端口
            lambda u: parse_ss_standard(u),
            # 方式2: 2022-blake3格式
            lambda u: parse_ss_2022_blake3(u),
            # 方式3: 简单格式
            lambda u: parse_ss_simple(u, name)
        ]
        
        for method in methods:
            try:
                config = method(url_part)
                if config:
                    if name and 'name' in config:
                        config['name'] = name
                    return config
            except:
                continue
        
        return None
        
    except Exception as e:
        print(f"解析复杂SS链接失败 {ss_url[:50]}: {e}")
        return None

def parse_ss_standard(url_part):
    """解析标准SS链接格式"""
    if '@' not in url_part:
        return None
    
    # 格式: base64(method:password)@server:port
    encoded_info, server_port = url_part.split('@', 1)
    
    # 解码Base64部分
    decoded_info = decode_base64(encoded_info)
    if not decoded_info or ':' not in decoded_info:
        return None
    
    method, password = decoded_info.split(':', 1)
    
    # 解析服务器和端口
    if '?' in server_port:
        server_port_part, _ = server_port.split('?', 1)
    else:
        server_port_part = server_port
    
    if ':' not in server_port_part:
        return None
    
    server, port_str = server_port_part.split(':', 1)
    try:
        port = int(port_str)
    except:
        port = 443
    
    return {
        'name': f"SS-{server}:{port}",
        'type': 'ss',
        'server': server,
        'port': port,
        'cipher': method,
        'password': password,
        'udp': True
    }

def parse_ss_2022_blake3(url_part):
    """解析2022-blake3格式的SS链接"""
    # 示例: 2022-blake3-aes-128-gcm:password@server:port
    if '@' not in url_part:
        return None
    
    auth_part, server_port = url_part.split('@', 1)
    
    if ':' not in auth_part:
        return None
    
    method, password = auth_part.split(':', 1)
    
    # 解析服务器和端口
    if '?' in server_port:
        server_port_part, _ = server_port.split('?', 1)
    else:
        server_port_part = server_port
    
    if ':' not in server_port_part:
        return None
    
    server, port_str = server_port_part.split(':', 1)
    try:
        port = int(port_str)
    except:
        port = 443
    
    return {
        'name': f"SS-{server}:{port}",
        'type': 'ss',
        'server': server,
        'port': port,
        'cipher': method,
        'password': password,
        'udp': True
    }

def parse_ss_simple(url_part, name):
    """解析简单SS链接格式"""
    # 尝试直接解析 server:port:method:password 格式
    parts = url_part.split(':')
    if len(parts) >= 4:
        server = parts[0]
        try:
            port = int(parts[1])
        except:
            port = 443
        method = parts[2]
        password = ':'.join(parts[3:])  # 密码可能包含冒号
        
        return {
            'name': name if name else f"SS-{server}:{port}",
            'type': 'ss',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password,
            'udp': True
        }
    
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
            name = unquote(fragment)
        else:
            url_part = url
            name = ""
            
        if '@' in url_part:
            # 格式: password@server:port
            password_part, server_port = url_part.split('@', 1)
            password = password_part
            
            # 解析服务器和端口
            if '?' in server_port:
                server_port_part, query = server_port.split('?', 1)
                server, port_str = server_port_part.split(':', 1)
                query_params = parse_qs(query)
            else:
                server, port_str = server_port.split(':', 1)
                query_params = {}
            
            try:
                port = int(port_str)
            except:
                port = 443
            
            config = {
                'name': name if name else f"Trojan-{server}:{port}",
                'type': 'trojan',
                'server': server,
                'port': port,
                'password': password,
                'udp': True,
                'sni': query_params.get('sni', [''])[0] or server,
                'skip-cert-verify': query_params.get('insecure', ['0'])[0] == '1'
            }
            
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
        if '#' in url:
            url_part, fragment = url.split('#', 1)
            name = unquote(fragment)
        else:
            url_part = url
            name = ""
        
        # 解析完整的URL
        parsed = urlparse(f'vless://{url_part}')
        
        config = {
            'name': name if name else f"VLESS-{parsed.hostname}:{parsed.port}",
            'type': 'vless',
            'server': parsed.hostname,
            'port': parsed.port,
            'uuid': parsed.username,
            'udp': True,
            'tls': False,  # 默认false
            'skip-cert-verify': False
        }
        
        # 解析查询参数
        if parsed.query:
            params = parse_qs(parsed.query)
            
            # 安全设置
            if 'security' in params:
                security = params['security'][0]
                config['tls'] = security in ['tls', 'xtls', 'reality']
                if security == 'reality':
                    config['type'] = 'reality'
            
            # SNI
            if 'sni' in params:
                config['servername'] = params['sni'][0]
            elif 'host' in params:
                config['servername'] = params['host'][0]
            
            # 跳过证书验证
            if 'insecure' in params:
                config['skip-cert-verify'] = params['insecure'][0] == '1'
            
            # 网络类型
            if 'type' in params:
                network = params['type'][0]
                config['network'] = network
                
                if network == 'ws':
                    config['ws-opts'] = {
                        'path': params.get('path', ['/'])[0]
                    }
                    if 'host' in params:
                        config['ws-opts']['headers'] = {
                            'Host': params['host'][0]
                        }
                elif network == 'grpc':
                    config['grpc-opts'] = {
                        'grpc-service-name': params.get('serviceName', [''])[0]
                    }
            
            # Flow (XTLS)
            if 'flow' in params:
                config['flow'] = params['flow'][0]
        
        return config
    except Exception as e:
        print(f"解析VLESS链接失败 {vless_url[:50]}: {e}")
    return None

def parse_ssr(ssr_url):
    """解析SSR链接"""
    try:
        # 移除 ssr:// 前缀并解码
        encoded = ssr_url[6:]
        decoded = decode_base64(encoded)
        if not decoded:
            return None
        
        # SSR格式: server:port:protocol:method:obfs:password_base64/?params_base64
        parts = decoded.split('/?', 1)
        main_part = parts[0]
        params_part = parts[1] if len(parts) > 1 else ''
        
        main_parts = main_part.split(':')
        if len(main_parts) < 6:
            return None
        
        server = main_parts[0]
        port = int(main_parts[1])
        protocol = main_parts[2]
        method = main_parts[3]
        obfs = main_parts[4]
        
        # 密码是Base64编码的
        password_encoded = main_parts[5]
        password = decode_base64(password_encoded) or password_encoded
        
        # 解析参数
        remarks = ""
        group = ""
        obfsparam = ""
        protoparam = ""
        
        if params_part:
            params = parse_qs(params_part)
            if 'remarks' in params:
                remarks_encoded = params['remarks'][0]
                remarks = decode_base64(remarks_encoded) or remarks_encoded
            if 'group' in params:
                group_encoded = params['group'][0]
                group = decode_base64(group_encoded) or group_encoded
            if 'obfsparam' in params:
                obfsparam_encoded = params['obfsparam'][0]
                obfsparam = decode_base64(obfsparam_encoded) or obfsparam_encoded
            if 'protoparam' in params:
                protoparam_encoded = params['protoparam'][0]
                protoparam = decode_base64(protoparam_encoded) or protoparam_encoded
        
        name = remarks if remarks else f"SSR-{server}:{port}"
        
        # Clash不支持原生SSR，所以转换为SS格式（会丢失一些功能）
        # 只支持简单转换
        return {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password,
            'udp': True
        }
        
    except Exception as e:
        print(f"解析SSR链接失败 {ssr_url[:50]}: {e}")
        return None

def parse_wireguard(wireguard_url):
    """解析WireGuard链接"""
    try:
        # 移除 wireguard:// 前缀
        url = wireguard_url[12:] if wireguard_url.startswith('wireguard://') else wireguard_url
        
        # 解析URL参数
        parsed = urlparse(f'wireguard://{url}')
        if parsed.query:
            params = parse_qs(parsed.query)
        else:
            params = {}
        
        # 基础配置
        config = {
            'name': f"WireGuard-{parsed.hostname or 'wg'}",
            'type': 'wireguard',
            'server': parsed.hostname or '127.0.0.1',
            'port': parsed.port or 51820,
        }
        
        # 添加参数
        if 'private_key' in params:
            config['private-key'] = params['private_key'][0]
        if 'public_key' in params:
            config['public-key'] = params['public_key'][0]
        if 'preshared_key' in params:
            config['preshared-key'] = params['preshared_key'][0]
        if 'address' in params:
            config['address'] = params['address'][0].split(',')
        if 'dns' in params:
            config['dns'] = params['dns'][0].split(',')
        if 'mtu' in params:
            config['mtu'] = int(params['mtu'][0])
        
        return config
        
    except Exception as e:
        print(f"解析WireGuard链接失败 {wireguard_url[:50]}: {e}")
        return None

def parse_tuic(tuic_url):
    """解析TUIC链接"""
    try:
        # 移除 tuic:// 前缀
        url = tuic_url[7:]
        
        if '#' in url:
            url_part, fragment = url.split('#', 1)
            name = unquote(fragment)
        else:
            url_part = url
            name = ""
        
        # 解析
        if '@' in url_part:
            auth_part, server_part = url_part.split('@', 1)
            if ':' in auth_part:
                uuid, password = auth_part.split(':', 1)
            else:
                uuid = auth_part
                password = ""
        else:
            return None
        
        # 解析服务器
        if '?' in server_part:
            server_port_part, query_part = server_part.split('?', 1)
            query_params = parse_qs(query_part)
        else:
            server_port_part = server_part
            query_params = {}
        
        server, port_str = server_port_part.split(':', 1)
        port = int(port_str)
        
        config = {
            'name': name if name else f"TUIC-{server}:{port}",
            'type': 'tuic',
            'server': server,
            'port': port,
            'uuid': uuid,
            'password': password,
        }
        
        # 可选参数
        if 'sni' in query_params:
            config['sni'] = query_params['sni'][0]
        if 'insecure' in query_params:
            config['skip-cert-verify'] = query_params['insecure'][0] == '1'
        if 'alpn' in query_params:
            config['alpn'] = [alpn.strip() for alpn in query_params['alpn'][0].split(',')]
        
        return config
        
    except Exception as e:
        print(f"解析TUIC链接失败 {tuic_url[:50]}: {e}")
        return None

def parse_juicity(juicity_url):
    """解析Juicity链接"""
    try:
        # 移除 juicity:// 前缀
        url = juicity_url[10:]
        
        if '#' in url:
            url_part, fragment = url.split('#', 1)
            name = unquote(fragment)
        else:
            url_part = url
            name = ""
        
        # 类似TUIC的解析
        if '@' in url_part:
            auth_part, server_part = url_part.split('@', 1)
            if ':' in auth_part:
                uuid, password = auth_part.split(':', 1)
            else:
                uuid = auth_part
                password = ""
        else:
            return None
        
        # 解析服务器
        if '?' in server_part:
            server_port_part, query_part = server_part.split('?', 1)
            query_params = parse_qs(query_part)
        else:
            server_port_part = server_part
            query_params = {}
        
        server, port_str = server_port_part.split(':', 1)
        port = int(port_str)
        
        config = {
            'name': name if name else f"Juicity-{server}:{port}",
            'type': 'juicity',
            'server': server,
            'port': port,
            'uuid': uuid,
            'password': password,
        }
        
        # 可选参数
        if 'sni' in query_params:
            config['sni'] = query_params['sni'][0]
        if 'insecure' in query_params:
            config['skip-cert-verify'] = query_params['insecure'][0] == '1'
        
        return config
        
    except Exception as e:
        print(f"解析Juicity链接失败 {juicity_url[:50]}: {e}")
        return None

def parse_proxy(proxy_str):
    """解析单个代理链接"""
    if not isinstance(proxy_str, str) or not proxy_str:
        return None
    
    proxy_str = proxy_str.strip()
    
    # 按协议类型分发
    if proxy_str.startswith('hysteria2://'):
        return parse_hysteria2(proxy_str)
    elif proxy_str.startswith('ss://'):
        return parse_ss_complex(proxy_str)
    elif proxy_str.startswith('vmess://'):
        return parse_vmess(proxy_str)
    elif proxy_str.startswith('trojan://'):
        return parse_trojan(proxy_str)
    elif proxy_str.startswith('vless://'):
        return parse_vless(proxy_str)
    elif proxy_str.startswith('ssr://'):
        return parse_ssr(proxy_str)
    elif proxy_str.startswith('wireguard://') or proxy_str.startswith('wg://'):
        return parse_wireguard(proxy_str)
    elif proxy_str.startswith('tuic://'):
        return parse_tuic(proxy_str)
    elif proxy_str.startswith('juicity://'):
        return parse_juicity(proxy_str)
    elif proxy_str.startswith('reality://'):
        # Reality是VLESS的一种变体
        return parse_vless(proxy_str.replace('reality://', 'vless://'))
    elif len(proxy_str) > 10 and re.match(r'^[A-Za-z0-9+/=_-]+$', proxy_str):
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
                        if isinstance(proxy, list):
                            proxies.extend(proxy)
                        else:
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
        'Accept': 'text/plain, */*; q=0.01',
        'Accept-Encoding': 'gzip, deflate, br'
    }
    
    try:
        print(f"正在获取: {url}")
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        content = response.text.strip()
        print(f"  获取成功，长度: {len(content)} 字符")
        
        # 尝试解码Base64
        decoded = decode_base64(content)
        if decoded:
            print(f"  Base64解码成功，解码后长度: {len(decoded)} 字符")
            # 检查解码后的内容是否包含代理链接
            protocols = ['hysteria2://', 'ss://', 'vmess://', 'trojan://', 'vless://', 'ssr://']
            if any(proto in decoded for proto in protocols):
                return decoded
        
        # 如果解码失败或解码后没有代理链接，返回原始内容
        return content
        
    except Exception as e:
        print(f"获取订阅失败 {url}: {e}")
        return None

def parse_proxies_from_content(content):
    """从内容中解析节点"""
    if not content:
        print("  内容为空")
        return []
    
    proxies = []
    
    # 按行解析
    lines = content.split('\n')
    print(f"  开始解析 {len(lines)} 行内容")
    
    parsed_count = 0
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
                    parsed_count += len(proxy)
                else:
                    proxies.append(proxy)
                    parsed_count += 1
                
                # 显示进度
                if parsed_count % 10 == 0:
                    print(f"  已解析 {parsed_count} 个节点")
        except Exception as e:
            # 显示错误但继续处理
            print(f"  解析行 {i+1} 时出错: {e}")
            # 尝试输出有问题的行以便调试
            print(f"  问题行内容: {line[:100]}...")
            pass
    
    print(f"  解析完成，找到 {len(proxies)} 个节点")
    return proxies

def generate_clash_config(proxies, filename):
    """生成Clash兼容的YAML配置"""
    if not proxies:
        print("  没有有效节点，生成空配置")
        # 生成一个包含测试节点的配置
        proxies = [{
            'name': '测试节点-无可用节点时显示',
            'type': 'ss',
            'server': 'example.com',
            'port': 443,
            'cipher': 'aes-256-gcm',
            'password': 'password',
            'udp': True
        }]
    
    # 过滤掉None值
    proxies = [p for p in proxies if p]
    
    # 为节点添加序号并确保名称唯一
    name_count = {}
    for i, proxy in enumerate(proxies):
        if 'name' not in proxy:
            proxy['name'] = f'节点{i+1:03d}'
        else:
            # 确保名称是字符串且唯一
            original_name = str(proxy['name'])
            if original_name in name_count:
                name_count[original_name] += 1
                proxy['name'] = f"{original_name}-{name_count[original_name]}"
            else:
                name_count[original_name] = 1
                proxy['name'] = original_name
    
    print(f"  准备生成 {len(proxies)} 个节点的配置")
    
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
        'proxies': proxies[:200],  # 限制最多200个节点
        'proxy-groups': [
            {
                'name': '🚀 节点选择',
                'type': 'select',
                'proxies': ['♻️ 自动选择', '🎯 全球直连', 'DIRECT'] + [p['name'] for p in proxies[:15]]
            },
            {
                'name': '♻️ 自动选择',
                'type': 'url-test',
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50,
                'proxies': [p['name'] for p in proxies[:100]]
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
                'name': '🎯 全球直连',
                'type': 'select',
                'proxies': ['DIRECT']
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
            }
        ],
        'rules': [
            # 广告拦截
            'DOMAIN-KEYWORD,ads,REJECT',
            'DOMAIN-SUFFIX,doubleclick.net,REJECT',
            
            # 国内直连
            'DOMAIN-SUFFIX,cn,🎯 全球直连',
            'DOMAIN-SUFFIX,baidu.com,🎯 全球直连',
            'DOMAIN-SUFFIX,qq.com,🎯 全球直连',
            'DOMAIN-SUFFIX,taobao.com,🎯 全球直连',
            'DOMAIN-SUFFIX,jd.com,🎯 全球直连',
            'DOMAIN-SUFFIX,weibo.com,🎯 全球直连',
            'DOMAIN-SUFFIX,zhihu.com,🎯 全球直连',
            
            # Bilibili
            'DOMAIN-SUFFIX,bilibili.com,📺 哔哩哔哩',
            'DOMAIN-SUFFIX,biliapi.com,📺 哔哩哔哩',
            'DOMAIN-SUFFIX,bilivideo.com,📺 哔哩哔哩',
            
            # 国外媒体
            'DOMAIN-SUFFIX,netflix.com,🌍 国外媒体',
            'DOMAIN-SUFFIX,disneyplus.com,🌍 国外媒体',
            'DOMAIN-SUFFIX,hbo.com,🌍 国外媒体',
            'DOMAIN-SUFFIX,youtube.com,🌍 国外媒体',
            'DOMAIN-SUFFIX,twitch.tv,🌍 国外媒体',
            
            # 微软服务
            'DOMAIN-SUFFIX,microsoft.com,Ⓜ️ 微软服务',
            'DOMAIN-SUFFIX,windows.com,Ⓜ️ 微软服务',
            'DOMAIN-SUFFIX,office.com,Ⓜ️ 微软服务',
            
            # 苹果服务
            'DOMAIN-SUFFIX,apple.com,🍎 苹果服务',
            'DOMAIN-SUFFIX,icloud.com,🍎 苹果服务',
            'DOMAIN-SUFFIX,appstore.com,🍎 苹果服务',
            
            # GitHub
            'DOMAIN-SUFFIX,github.com,🚀 节点选择',
            'DOMAIN-SUFFIX,githubusercontent.com,🚀 节点选择',
            
            # Google
            'DOMAIN-SUFFIX,google.com,🚀 节点选择',
            'DOMAIN-SUFFIX,gstatic.com,🚀 节点选择',
            
            # Telegram
            'DOMAIN-SUFFIX,telegram.org,🚀 节点选择',
            'DOMAIN-SUFFIX,t.me,🚀 节点选择',
            
            # Twitter
            'DOMAIN-SUFFIX,twitter.com,🚀 节点选择',
            
            # GEOIP规则
            'GEOIP,CN,🎯 全球直连',
            'GEOIP,PRIVATE,DIRECT',
            
            # 最终规则
            'MATCH,🚀 节点选择'
        ]
    }
    
    # 写入YAML文件
    output_path = os.path.join('订阅链接', f'{filename}.yaml')
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False, width=float("inf"))
    
    print(f"已生成文件: {output_path}，包含 {len(proxies[:200])} 个节点")
    return len(proxies[:200])

def main():
    """主函数"""
    print("=" * 60)
    print("订阅生成器 v2.0 - 支持所有主流协议")
    print("=" * 60)
    
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
        os.makedirs(input_dir, exist_ok=True)
        # 创建示例文件
        with open(os
