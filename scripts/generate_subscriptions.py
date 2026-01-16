#!/usr/bin/env python3
"""
自动订阅生成脚本
从输入源文件夹读取.txt文件中的链接，合并节点并生成ACL4SSR格式的YAML文件
"""

import os
import re
import requests
import yaml
from datetime import datetime
from urllib.parse import urlparse
import time

def read_links_from_file(file_path):
    """从文本文件读取链接"""
    links = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # 跳过空行和注释
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
        return response.text
    except Exception as e:
        print(f"获取订阅失败 {url}: {e}")
        return None

def parse_proxies_from_content(content):
    """从内容中解析节点"""
    proxies = []
    
    # 解析各种格式的节点
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # SS/SSR格式
        if line.startswith('ss://') or line.startswith('ssr://'):
            proxies.append(line)
        # VMess格式
        elif line.startswith('vmess://'):
            proxies.append(line)
        # Trojan格式
        elif line.startswith('trojan://'):
            proxies.append(line)
        # VLESS格式
        elif line.startswith('vless://'):
            proxies.append(line)
        # Base64编码的节点
        elif re.match(r'^[A-Za-z0-9+/=]+$', line):
            proxies.append(line)
    
    return proxies

def generate_acl4ssr_yaml(proxies, filename):
    """生成ACL4SSR格式的YAML文件"""
    config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': True,
        'mode': 'Rule',
        'log-level': 'info',
        'external-controller': '0.0.0.0:9090',
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
        'proxies': [],
        'proxy-groups': [
            {
                'name': '🚀 节点选择',
                'type': 'select',
                'proxies': ['♻️ 自动选择', '🎯 全球直连']
            },
            {
                'name': '♻️ 自动选择',
                'type': 'url-test',
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50,
                'proxies': []
            },
            {
                'name': '📺 哔哩哔哩',
                'type': 'select',
                'proxies': ['🚀 节点选择', '♻️ 自动选择', '🎯 全球直连']
            },
            {
                'name': '🌍 国外媒体',
                'type': 'select',
                'proxies': ['🚀 节点选择', '♻️ 自动选择', '🎯 全球直连']
            },
            {
                'name': 'Ⓜ️ 微软服务',
                'type': 'select',
                'proxies': ['🚀 节点选择', '🎯 全球直直连']
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
            'DOMAIN-SUFFIX,ads.com,REJECT',
            'DOMAIN-KEYWORD,adservice,REJECT',
            'DOMAIN-SUFFIX,bilibili.com,📺 哔哩哔哩',
            'DOMAIN-SUFFIX,bilibili.tv,📺 哔哩哔哩',
            'DOMAIN-SUFFIX,netflix.com,🌍 国外媒体',
            'DOMAIN-SUFFIX,disneyplus.com,🌍 国外媒体',
            'DOMAIN-SUFFIX,microsoft.com,Ⓜ️ 微软服务',
            'DOMAIN-SUFFIX,apple.com,🍎 苹果服务',
            'GEOIP,CN,🎯 全球直连',
            'MATCH,🚀 节点选择'
        ]
    }
    
    # 添加代理到配置
    for i, proxy in enumerate(proxies[:100]):  # 限制最多100个节点
        proxy_name = f"节点{i+1:03d}"
        
        # 尝试解析代理类型
        if proxy.startswith('ss://'):
            config['proxies'].append({
                'name': proxy_name,
                'type': 'ss',
                'server': 'server.address',  # 需要实际解析
                'port': 443,
                'cipher': 'aes-256-gcm',
                'password': 'password'
            })
        elif proxy.startswith('vmess://'):
            config['proxies'].append({
                'name': proxy_name,
                'type': 'vmess',
                'server': 'server.address',
                'port': 443,
                'uuid': 'uuid',
                'alterId': 0,
                'cipher': 'auto',
                'tls': True
            })
        else:
            # 添加为原始字符串
            config['proxies'].append(proxy)
        
        # 添加到自动选择组
        config['proxy-groups'][1]['proxies'].append(proxy_name)
    
    # 写入YAML文件
    output_path = os.path.join('订阅链接', f'{filename}.yaml')
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False)
    
    print(f"已生成文件: {output_path}，包含 {len(proxies)} 个节点")
    return len(proxies)

def main():
    """主函数"""
    print("开始生成订阅...")
    
    # 确保输出目录存在
    os.makedirs('订阅链接', exist_ok=True)
    
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
            for link in links:
                print(f"  获取链接: {link}")
                content = fetch_subscription_content(link)
                if content:
                    proxies = parse_proxies_from_content(content)
                    all_proxies.extend(proxies)
                    print(f"    找到 {len(proxies)} 个节点")
                    time.sleep(1)  # 避免请求过快
            
            # 去重
            unique_proxies = list(dict.fromkeys(all_proxies))
            
            # 生成YAML文件
            if unique_proxies:
                base_name = os.path.splitext(filename)[0]
                count = generate_acl4ssr_yaml(unique_proxies, base_name)
                print(f"  总计: {count} 个唯一节点")
            else:
                print(f"  未找到有效节点")
    
    print("订阅生成完成！")

if __name__ == '__main__':
    main()
