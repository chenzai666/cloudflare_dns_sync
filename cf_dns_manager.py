#!/usr/bin/env python3
"""
增强版 Cloudflare DNS 管理器 (支持主域名解析和TTL自定义)
功能：
1. 新增前缀DNS记录
2. 删除指定前缀的记录
3. 修改指定前缀的记录
4. 同步所有记录到DDNS记录IP
5. 支持主域名解析 (@)
6. 支持自定义TTL值（包括 "auto"）
7. 修复了Windows上的日志文件创建问题
"""
import argparse
import json
import logging
import os
import requests
import sys
from pathlib import Path
from datetime import datetime
# 全局配置目录
CFG_DIR = Path.home() / ".cf_dns_manager"
CFG_FILE = CFG_DIR / "config.json"
LOG_FILE = CFG_DIR / "cf_dns_manager.log"  # 日志文件路径
# 设置日志
def setup_logger():
    """配置日志系统"""
    # 确保配置目录存在
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger("CF_DNS_Manager")
    logger.setLevel(logging.INFO)
    
    # 移除所有已存在的处理器
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # 文件处理器（配置文件同目录）
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        '%(asctime)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    return logger
# 初始化日志
logger = setup_logger()
def load_config():
    """加载配置文件"""
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"配置目录: {CFG_DIR}")
  
    if CFG_FILE.exists():
        try:
            with open(CFG_FILE, 'r') as f:
                config = json.load(f)
                # 验证必要配置
                if not config.get("API_TOKEN") or not config.get("ZONE_ID"):
                    logger.error("配置文件中缺少API_TOKEN或ZONE_ID")
                    sys.exit(1)
                # 设置默认TTL如果不存在
                if "DEFAULT_TTL" not in config:
                    config["DEFAULT_TTL"] = "auto"  # 默认为自动
                    
                # 记录配置加载信息
                logger.info(f"已加载配置文件: {CFG_FILE}")
                logger.info(f"基础域名: {config.get('BASE_DOMAIN', '未设置')}")
                logger.info(f"DDNS记录: {config.get('DDNS_RECORD', '未设置')}")
                logger.info(f"默认TTL: {config.get('DEFAULT_TTL', 'auto')}")
                return config
        except Exception as e:
            logger.error(f"配置文件损坏: {e}")
            logger.exception("配置文件解析错误详细信息:")
            sys.exit(1)
  
    
    # 创建默认配置
    config = {
        "API_TOKEN": "",
        "ZONE_ID": "",
        "BASE_DOMAIN": "example.com",
        "DDNS_RECORD": "ddns.example.com",
        "DEFAULT_TTL": "auto"  # 默认为自动
    }
    
    with open(CFG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    
    logger.info(f"已创建默认配置文件: {CFG_FILE}")
    logger.info("请编辑配置文件设置API Token、Zone ID和基础域名")
    sys.exit(1)

def cf_api_request(method, endpoint, data=None):
    """发送Cloudflare API请求"""
    url = f"https://api.cloudflare.com/client/v4/zones/{config['ZONE_ID']}/{endpoint}"
    headers = {
        "Authorization": f"Bearer {config['API_TOKEN']}",
        "Content-Type": "application/json"
    }
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data)
        elif method == "PUT":
            response = requests.put(url, headers=headers, json=data)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
            
        response.raise_for_status()
        return response.json()
                
    except requests.exceptions.RequestException as e:
        error_msg = str(e)
        try:
            error_resp = e.response.json()
            if "errors" in error_resp:
                errors = ', '.join([err["message"] for err in error_resp["errors"]])
                error_msg = f"{e} | {errors}"
        except:
            pass
            
        logger.error(f"API请求失败: {error_msg}")
        return {"success": False, "errors": [{"message": error_msg}]}

def get_dns_record(record_name, record_type=None):
    """获取DNS记录"""
    endpoint = f"dns_records?name={record_name}"
    if record_type:
        endpoint += f"&type={record_type}"
    
    result = cf_api_request("GET", endpoint)
    
    if not result.get("success"):
        error = result.get("errors", [{}])[0].get("message", "Unknown error")
        logger.error(f"获取DNS记录失败: {error}")
        return None
    
    records = result.get("result", [])
    return records[0] if records else None

def get_public_ip(ipv6=False):
    """获取公网IP地址"""
    try:
        if ipv6:
            return requests.get('https://api64.ipify.org').text
        return requests.get('https://api.ipify.org').text
    except:
        logger.error("无法获取公网IP")
        return None

def sync_dns_records():
    """同步所有DNS记录到DDNS记录IP"""
    logger.info("开始同步DNS记录...")
    
    # 获取DDNS记录IP
    ddns_record = config.get("DDNS_RECORD", "ddns.example.com")
    record = get_dns_record(ddns_record)
    
    if not record:
        logger.error(f"未找到DDNS记录: {ddns_record}")
        return False
    
    ddns_ip = record["content"]
    record_type = record["type"]
    
    logger.info(f"DDNS记录IP: {ddns_ip} ({record_type})")
    
    # 获取所有记录
    endpoint = "dns_records?per_page=100"
    result = cf_api_request("GET", endpoint)
    
    if not result.get("success"):
        error = result.get("errors", [{}])[0].get("message", "Unknown error")
        logger.error(f"获取DNS记录失败: {error}")
        return False
    
    records = result.get("result", [])
    
    # 过滤需要更新的记录
    update_records = [
        r for r in records 
        if r["type"] == record_type 
        and r["name"] != ddns_record
        and r["content"] != ddns_ip
        and not r["proxied"]
    ]
    
    if not update_records:
        logger.info("没有需要更新的记录")
        return True
    
    logger.info(f"找到 {len(update_records)} 条需要更新的记录")
    
    # 更新记录
    updated_count = 0
    for record in update_records:
        update_data = {
            "type": record["type"],
            "name": record["name"],
            "content": ddns_ip,
            "ttl": record["ttl"],
            "proxied": record["proxied"]
        }
        
        result = cf_api_request("PUT", f"dns_records/{record['id']}", update_data)
        
        if result.get("success"):
            ttl_display = "auto" if record["ttl"] == 1 else record["ttl"]
            logger.info(f"更新成功: {record['name']} -> {ddns_ip} (TTL: {ttl_display})")
            updated_count += 1
        else:
            error = result.get("errors", [{}])[0].get("message", "Unknown error")
            logger.error(f"更新失败: {record['name']} - {error}")
    
    logger.info(f"同步完成! 更新了 {updated_count}/{len(update_records)} 条记录")
    return updated_count > 0

def build_full_name(prefix):
    """构建完整域名，支持主域名（@）"""
    if prefix == "@":
        return config['BASE_DOMAIN']
    return f"{prefix}.{config['BASE_DOMAIN']}"

def normalize_ttl(ttl):
    """规范化TTL值：处理 'auto' 和整数"""
    if ttl == "auto" or ttl is None:
        return 1  # Cloudflare 中 "auto" 对应值为1
    try:
        return int(ttl)
    except ValueError:
        logger.error(f"无效的TTL值: {ttl}")
        return None

def format_ttl(ttl):
    """格式化TTL值用于显示"""
    if ttl == 1:
        return "auto"
    return ttl

def add_prefix_record(prefix, ip=None, record_type="A", ttl=None, proxied=False):
    """添加前缀DNS记录"""
    full_name = build_full_name(prefix)
    
    # 检查记录是否已存在
    existing_record = get_dns_record(full_name, record_type)
    if existing_record:
        logger.error(f"记录已存在: {full_name} ({record_type})")
        return False
    
    # 自动获取IP（如果未提供）
    if not ip:
        logger.info("未提供IP地址，将使用公网IP")
        ip = get_public_ip(record_type == "AAAA")
        if not ip:
            return False
    
    # 规范化TTL值
    normalized_ttl = normalize_ttl(ttl or config.get("DEFAULT_TTL", "auto"))
    if normalized_ttl is None:
        return False
    
    # 创建记录
    record_data = {
        "type": record_type,
        "name": full_name,
        "content": ip,
        "ttl": normalized_ttl,
        "proxied": proxied
    }
    
    result = cf_api_request("POST", "dns_records", record_data)
    
    if result.get("success"):
        record_id = result["result"]["id"]
        ttl_display = format_ttl(normalized_ttl)
        logger.info(f"记录创建成功! ID: {record_id}")
        logger.info(f"名称: {full_name}, IP: {ip}, TTL: {ttl_display}, 代理: {'是' if proxied else '否'}")
        return True
    else:
        error = result.get("errors", [{}])[0].get("message", "Unknown error")
        logger.error(f"创建失败: {error}")
        return False

def delete_prefix_record(prefix, record_type=None):
    """删除指定前缀的DNS记录"""
    full_name = build_full_name(prefix)
    
    # 查找记录
    record = get_dns_record(full_name, record_type)
    
    if not record:
        logger.error(f"未找到记录: {full_name} {f'({record_type})' if record_type else ''}")
        return False
    
    # 执行删除
    result = cf_api_request("DELETE", f"dns_records/{record['id']}")
    
    if result.get("success"):
        logger.info(f"记录删除成功: {full_name} ({record['type']})")
        return True
    else:
        error = result.get("errors", [{}])[0].get("message", "Unknown error")
        logger.error(f"删除失败: {error}")
        return False

def update_prefix_record(prefix, new_ip=None, record_type=None, new_ttl=None, new_proxied=None):
    """修改指定前缀的DNS记录"""
    full_name = build_full_name(prefix)
    
    # 查找记录
    record = get_dns_record(full_name, record_type)
    
    if not record:
        logger.error(f"未找到记录: {full_name} {f'({record_type})' if record_type else ''}")
        return False
    
    # 规范化TTL值
    normalized_new_ttl = None
    if new_ttl is not None:
        normalized_new_ttl = normalize_ttl(new_ttl)
        if normalized_new_ttl is None:
            return False
    
    # 如果没有提供任何更新参数
    if new_ip is None and normalized_new_ttl is None and new_proxied is None:
        logger.warning("没有提供更新参数（IP/TTL/Proxy状态）")
        return False
    
    # 准备更新数据
    update_data = {
        "type": record["type"],
        "name": record["name"],
        "content": new_ip if new_ip is not None else record["content"],
        "ttl": normalized_new_ttl if normalized_new_ttl is not None else record["ttl"],
        "proxied": new_proxied if new_proxied is not None else record["proxied"]
    }
    
    # 检查是否需要更新
    if (update_data["content"] == record["content"] and 
        update_data["ttl"] == record["ttl"] and 
        update_data["proxied"] == record["proxied"]):
        logger.info("记录内容未更改，无需更新")
        return True
    
    # 显示更新信息
    logger.info("更新记录详情:")
    if new_ip is not None:
        logger.info(f"  IP: {record['content']} → {update_data['content']}")
    if normalized_new_ttl is not None:
        old_ttl_display = format_ttl(record["ttl"])
        new_ttl_display = format_ttl(update_data["ttl"])
        logger.info(f"  TTL: {old_ttl_display} → {new_ttl_display}")
    if new_proxied is not None:
        logger.info(f"  代理: {'是' if record['proxied'] else '否'} → {'是' if update_data['proxied'] else '否'}")
    
    # 执行更新
    result = cf_api_request("PUT", f"dns_records/{record['id']}", update_data)
    
    if result.get("success"):
        logger.info(f"记录更新成功: {full_name}")
        return True
    else:
        error = result.get("errors", [{}])[0].get("message", "Unknown error")
        logger.error(f"更新失败: {error}")
        return False

if __name__ == "__main__":
    # 加载配置
    config = load_config()
    
    # 命令行参数解析
    parser = argparse.ArgumentParser(description='Cloudflare DNS记录管理器')
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # sync命令
    sync_parser = subparsers.add_parser('sync', help='同步所有记录到DDNS记录IP')
    
    # add命令
    add_parser = subparsers.add_parser('add', help='添加DNS记录')
    add_parser.add_argument('prefix', help='记录前缀 (使用@表示主域名)')
    add_parser.add_argument('--ip', help='IP地址')
    add_parser.add_argument('--type', choices=['A', 'AAAA', 'CNAME'], default='A', help='记录类型 (默认: A)')
    add_parser.add_argument('--ttl', help=f'TTL值 (整数秒或"auto"，默认: {config.get("DEFAULT_TTL", "auto")})')
    add_parser.add_argument('--proxied', action='store_true', help='启用Cloudflare代理')
    
    # delete命令
    del_parser = subparsers.add_parser('delete', help='删除DNS记录')
    del_parser.add_argument('prefix', help='记录前缀 (使用@表示主域名)')
    del_parser.add_argument('--type', choices=['A', 'AAAA', 'CNAME'], help='记录类型')
    
    # update命令
    update_parser = subparsers.add_parser('update', help='更新DNS记录')
    update_parser.add_argument('prefix', help='记录前缀 (使用@表示主域名)')
    update_parser.add_argument('--ip', help='新的IP地址')
    update_parser.add_argument('--type', choices=['A', 'AAAA', 'CNAME'], help='记录类型')
    update_parser.add_argument('--ttl', help='新的TTL值 (整数秒或"auto")')
    update_parser.add_argument('--proxied', action='store_true', help='启用Cloudflare代理')
    update_parser.add_argument('--no-proxied', action='store_true', help='禁用Cloudflare代理')
    
    # 解析参数
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # 执行命令
    if args.command == 'sync':
        success = sync_dns_records()
        sys.exit(0 if success else 1)
    
    elif args.command == 'add':
        success = add_prefix_record(
            args.prefix,
            args.ip,
            args.type,
            args.ttl,  # 传递None时使用默认TTL
            args.proxied
        )
        sys.exit(0 if success else 1)
    
    elif args.command == 'delete':
        success = delete_prefix_record(args.prefix, args.type)
        sys.exit(0 if success else 1)
    
    elif args.command == 'update':
        proxied = None
        if args.proxied and args.no_proxied:
            logger.error("不能同时设置 --proxied 和 --no-proxied")
            sys.exit(1)
        elif args.proxied:
            proxied = True
        elif args.no_proxied:
            proxied = False
            
        success = update_prefix_record(
            args.prefix,
            args.ip,
            args.type,
            args.ttl,
            proxied
        )
        sys.exit(0 if success else 1)


