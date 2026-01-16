#!/usr/bin/env python3
"""
自动订阅生成脚本 - ACL4SSR增强版
支持从ACL4SSR获取规则配置
生成完全兼容Clash的YAML配置
"""

import os
import re
import base64
import json
import requests
import yaml
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, unquote
import time
import shutil
import urllib.parse

def get_beijing_time():
    """获取东八区北京时间"""
    utc_now = datetime.utcnow()
    beijing_tz = timezone(timedelta(hours=8))
    beijing_time = utc_now.replace(tzinfo=timezone.utc).astimezone(beijing_tz)
    return beijing_time.strftime('%Y-%m-%d %H:%M:%S')

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
            cleaned_list = []
            for item in value:
                cleaned_item = clean_config(item)
                if cleaned_item is not None:
                    cleaned_list.append(cleaned_item)
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

def fetch_remote_content(url, timeout=30):
    """获取远程内容"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/plain, */*',
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.text.strip(), True, None
    except requests.exceptions.Timeout:
        return None, False, "请求超时"
    except requests.exceptions.ConnectionError:
        return None, False, "连接错误"
    except requests.exceptions.HTTPError as e:
        return None, False, f"HTTP错误: {e.response.status_code}"
    except Exception as e:
        return None, False, f"未知错误: {str(e)}"

def fetch_subscription(url, timeout=30):
    """获取订阅内容"""
    content, success, error_msg = fetch_remote_content(url, timeout)
    
    if success and content:
        decoded = safe_decode_base64(content)
        if decoded:
            return decoded, True, None
        return content, True, None
    
    return content, success, error_msg

def get_aclassr_rules():
    """从ACL4SSR获取规则"""
    rule_urls = [
        "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini",
        "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_MultiCountry.ini"
    ]
    
    all_rules = []
    
    for url in rule_urls:
        print(f"  获取ACL4SSR规则: {url}")
        content, success, error_msg = fetch_remote_content(url, timeout=15)
        
        if success and content:
            # 解析INI格式的规则
            rules = parse_aclassr_rules(content)
            if rules:
                all_rules.extend(rules)
                print(f"    获取到 {len(rules)} 条规则")
        else:
            print(f"    获取失败: {error_msg}")
    
    # 如果没有获取到规则，使用默认规则
    if not all_rules:
        print("  使用默认规则")
        all_rules = get_default_rules()
    
    return all_rules

def parse_aclassr_rules(content):
    """解析ACL4SSR规则文件"""
    rules = []
    lines = content.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # 解析规则格式: DOMAIN-SUFFIX,example.com,Proxy
        if ',' in line:
            parts = line.split(',')
            if len(parts) >= 3:
                rule_type = parts[0].strip()
                target = parts[1].strip()
                proxy_group = parts[2].strip()
                
                # 转换代理组名称
                if proxy_group == 'PROXY':
                    proxy_group = '节点选择'
                elif proxy_group == 'DIRECT':
                    proxy_group = 'DIRECT'
                elif proxy_group == 'REJECT':
                    proxy_group = 'REJECT'
                
                rules.append(f"{rule_type},{target},{proxy_group}")
    
    return rules

def get_default_rules():
    """获取默认规则"""
    return [
        # 广告拦截
        'DOMAIN-KEYWORD,adservice,REJECT',
        'DOMAIN-SUFFIX,ads.com,REJECT',
        'DOMAIN-SUFFIX,doubleclick.net,REJECT',
        
        # 国内直连
        'DOMAIN-SUFFIX,cn,DIRECT',
        'DOMAIN-SUFFIX,baidu.com,DIRECT',
        'DOMAIN-SUFFIX,qq.com,DIRECT',
        'DOMAIN-SUFFIX,taobao.com,DIRECT',
        'DOMAIN-SUFFIX,jd.com,DIRECT',
        'DOMAIN-SUFFIX,weibo.com,DIRECT',
        'DOMAIN-SUFFIX,sina.com,DIRECT',
        'DOMAIN-SUFFIX,163.com,DIRECT',
        'DOMAIN-SUFFIX,alibaba.com,DIRECT',
        'DOMAIN-SUFFIX,alipay.com,DIRECT',
        'DOMAIN-SUFFIX,tencent.com,DIRECT',
        'DOMAIN-SUFFIX,bilibili.com,DIRECT',
        'DOMAIN-SUFFIX,zhihu.com,DIRECT',
        
        # GEOIP
        'GEOIP,CN,DIRECT',
        
        # 最终规则
        'MATCH,节点选择'
    ]

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

def generate_clash_config_with_comments(proxies, filename, source_content, success_count, total_count, failed_urls):
    """生成带备注的Clash配置"""
    
    # 获取当前时间
    update_time = get_beijing_time()
    
    # 生成备注
    comments = f"""# ========================================
# Clash 配置文件
# ========================================
# 
# 更新时间（东八区北京时间）: {update_time}
# 输入源文件: {filename}
# 订阅链接获取情况: {success_count}/{total_count}
# 
# 失败的链接:
{failed_urls}
# 
# 输入源文件内容:
{source_content}
# 
# ========================================
# 配置开始
# ========================================
"""
    
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
    
    # 获取ACL4SSR规则
    print("  获取ACL4SSR规则...")
    rules = get_aclassr_rules()
    
    # Clash配置 - 完全兼容格式
    config = {
        'port': 7890,
        'socks-port': 7891,
        'mixed-port': 7893,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        
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
                'https://dns.cloudflare.com/dns-query',
                'https://doh.dns.sb/dns-query'
            ],
            'fallback-filter': {
                'geoip': True,
                'ipcidr': [
                    '240.0.0.0/4'
                ]
            }
        },
        
        'proxies': cleaned_proxies[:150],  # 限制数量
        
        'proxy-groups': [
            {
                'name': '节点选择',
                'type': 'select',
                'proxies': ['自动选择', 'DIRECT']
            },
            {
                'name': '自动选择',
                'type': 'url-test',
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50,
                'proxies': [p.get('name', '节点') for p in cleaned_proxies[:100]]
            }
        ],
        
        'rules': rules
    }
    
    config = clean_config(config)
    
    # 写入文件
    output_dir = '订阅链接'
    os.makedirs(output_dir, exist_ok=True)
    
    output_path = os.path.join(output_dir, f'{filename}.yaml')
    
    with open(output_path, 'w', encoding='utf-8') as f:
        # 写入备注
        f.write(comments)
        # 写入配置，确保YAML格式正确
        yaml.dump(config, f, 
                 allow_unicode=True, 
                 default_flow_style=False, 
                 sort_keys=False,
                 width=float("inf"),
                 explicit_start=False,
                 explicit_end=False,
                 indent=2)
    
    print(f"  生成配置文件: {output_path}")
    print(f"  包含 {len(cleaned_proxies[:150])} 个节点")
    print(f"  包含 {len(rules)} 条规则")
    
    # 验证YAML格式
    try:
        with open(output_path, 'r', encoding='utf-8') as f:
            test_content = f.read()
            # 检查是否包含非法字符
            if '\t' in test_content:
                print("  ⚠️ 警告: YAML文件包含制表符，可能影响解析")
                test_content = test_content.replace('\t', '  ')
                with open(output_path, 'w', encoding='utf-8') as f2:
                    f2.write(test_content)
            
            # 验证YAML语法
            yaml.safe_load(test_content)
        print("  ✅ YAML格式验证成功")
    except yaml.YAMLError as e:
        print(f"  ❌ YAML格式错误: {e}")
        # 尝试修复
        try:
            # 移除可能导致问题的字符
            with open(output_path, 'r', encoding='utf-8') as f:
                content = f.read()
            content = content.replace('\r\n', '\n').replace('\r', '\n')
            content = re.sub(r'\n{3,}', '\n\n', content)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print("  ✅ 已尝试修复YAML格式")
        except:
            print("  ❌ 修复失败")
    
    return len(cleaned_proxies[:150])

def clear_output_directory():
    """清空输出目录"""
    output_dir = '订阅链接'
    
    if os.path.exists(output_dir):
        print(f"清空输出目录: {output_dir}")
        try:
            for filename in os.listdir(output_dir):
                file_path = os.path.join(output_dir, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print(f"删除文件 {file_path} 失败: {e}")
            print("输出目录已清空")
        except Exception as e:
            print(f"清空目录失败: {e}")
    else:
        os.makedirs(output_dir, exist_ok=True)
        print("创建输出目录")

def read_source_file_content(filepath):
    """读取源文件内容并添加#注释"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        commented_lines = []
        for line in lines:
            line = line.rstrip('\n')
            if line.strip():
                commented_lines.append(f"# {line}")
            else:
                commented_lines.append("#")
        
        return "\n".join(commented_lines)
        
    except Exception as e:
        print(f"读取源文件失败: {e}")
        return "# 无法读取源文件内容"

def main():
    """主函数"""
    print("=" * 70)
    print("自动订阅生成器 - ACL4SSR增强版")
    print("=" * 70)
    print(f"开始时间（北京时间）: {get_beijing_time()}")
    
    # 清空输出目录
    clear_output_directory()
    
    input_dir = '输入源'
    os.makedirs(input_dir, exist_ok=True)
    
    # 查找输入文件
    txt_files = [f for f in os.listdir(input_dir) if f.endswith('.txt')]
    
    if not txt_files:
        print(f"\n没有找到输入文件，请在 '{input_dir}' 中创建.txt文件")
        print("创建示例文件...")
        example_content = """# 在此添加订阅链接，每行一个
# 支持ACL4SSR规则
https://vyy.cqsvhb.cn/s/c59454c04c7395f58b5d8165a598ad64
# 更多订阅链接...
"""
        with open(os.path.join(input_dir, 'example.txt'), 'w', encoding='utf-8') as f:
            f.write(example_content)
        print(f"已创建示例文件: {input_dir}/example.txt")
        txt_files = ['example.txt']
    
    # 处理每个文件
    for filename in txt_files:
        print(f"\n" + "=" * 50)
        print(f"处理文件: {filename}")
        print("=" * 50)
        
        filepath = os.path.join(input_dir, filename)
        
        # 读取源文件内容（用于备注）
        source_content = read_source_file_content(filepath)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"  读取失败: {e}")
            continue
        
        if not urls:
            print("  没有订阅链接")
            continue
        
        total_count = len(urls)
        print(f"  找到 {total_count} 个订阅链接")
        
        all_proxies = []
        failed_urls = []
        success_count = 0
        
        # 处理每个链接
        for i, url in enumerate(urls):
            print(f"\n  [{i+1}/{total_count}] 处理链接")
            print(f"    链接: {url[:80]}...")
            
            result = fetch_subscription(url, timeout=15)
            content, success, error_msg = result
            
            if success and content:
                proxies = process_subscription_content(content)
                if proxies:
                    all_proxies.extend(proxies)
                    success_count += 1
                    print(f"    ✅ 成功获取，找到 {len(proxies)} 个节点")
                else:
                    print(f"    ⚠️ 获取成功但未找到有效节点")
                    failed_urls.append(f"# {url} - 无有效节点")
            else:
                error_info = error_msg if error_msg else "未知错误"
                print(f"    ❌ 失败: {error_info}")
                failed_urls.append(f"# {url} - {error_info}")
            
            # 避免请求过快
            if i < total_count - 1:
                time.sleep(1)
        
        # 生成失败链接备注
        failed_comments = "\n".join(failed_urls) if failed_urls else "# 无失败链接"
        
        # 去重
        unique_proxies = []
        seen = set()
        
        for proxy in all_proxies:
            if not proxy:
                continue
            
            key = f"{proxy.get('server', '')}:{proxy.get('port', '')}:{proxy.get('type', '')}:{proxy.get('name', '')}"
            if key not in seen:
                seen.add(key)
                unique_proxies.append(proxy)
        
        # 统计信息
        print(f"\n  {'='*30}")
        print(f"  处理完成统计:")
        print(f"    总链接数: {total_count}")
        print(f"    成功获取: {success_count}")
        print(f"    失败链接: {total_count - success_count}")
        print(f"    原始节点: {len(all_proxies)} 个")
        print(f"    去重节点: {len(unique_proxies)} 个")
        
        # 按类型统计
        type_stats = {}
        for proxy in unique_proxies:
            proxy_type = proxy.get('type', 'unknown')
            type_stats[proxy_type] = type_stats.get(proxy_type, 0) + 1
        
        if type_stats:
            print(f"    节点类型分布:")
            for proxy_type, count in sorted(type_stats.items()):
                print(f"      {proxy_type}: {count} 个")
        else:
            print(f"    无有效节点")
        
        # 生成配置
        if unique_proxies:
            base_name = os.path.splitext(filename)[0]
            node_count = generate_clash_config_with_comments(
                unique_proxies, 
                base_name, 
                source_content,
                success_count,
                total_count,
                failed_comments
            )
            print(f"\n    ✅ 配置文件生成成功，包含 {node_count} 个节点")
        else:
            print("\n    ⚠️ 没有有效节点，生成空配置")
            # 生成一个空配置，但仍然包含备注
            empty_proxies = []
            base_name = os.path.splitext(filename)[0]
            generate_clash_config_with_comments(
                empty_proxies,
                base_name,
                source_content,
                success_count,
                total_count,
                failed_comments
            )
    
    print(f"\n" + "=" * 70)
    print(f"生成完成！")
    print(f"完成时间（北京时间）: {get_beijing_time()}")
    print("=" * 70)

if __name__ == '__main__':
    main()
