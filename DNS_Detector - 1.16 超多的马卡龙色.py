import sys
import threading
import subprocess
import socket
import dns.resolver
import concurrent.futures
import time
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QLineEdit, QPushButton, QTreeWidget, QTreeWidgetItem, QHeaderView,
    QProgressBar, QMessageBox, QComboBox, QMenu, QTextEdit, QDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QAction, QColor
from PyQt6.QtGui import QTextCursor
from PyQt6.QtGui import QIcon

class ProjectInfo:
    """项目信息元数据（集中管理所有项目相关信息）"""
    VERSION = "1.15.0"
    BUILD_DATE = "2025-05-15"
    AUTHOR = "杜玛"
    LICENSE = "MIT"
    COPYRIGHT = "© 永久 杜玛"
    URL = "https://github.com/duma520"
    MAINTAINER_EMAIL = "不提供"
    NAME = "DNS服务器检测工具"
    DESCRIPTION = "一款用于检测DNS服务器响应速度和可靠性的工具"

    @classmethod
    def get_metadata(cls) -> dict:
        """获取主要元数据字典"""
        return {
            'version': cls.VERSION,
            'author': cls.AUTHOR,
            'license': cls.LICENSE,
            'url': cls.URL
        }

    @classmethod
    def get_header(cls) -> str:
        """生成标准化的项目头信息"""
        return f"{cls.NAME} {cls.VERSION} | {cls.LICENSE} License | {cls.URL}"



# 增强版全球DNS服务器列表（共200+个）
DNS_SERVERS = [
    # 中国大陆DNS (40个)
    '114.114.114.114', '114.114.115.115', '223.5.5.5', '223.6.6.6',
    '119.29.29.29', '182.254.116.116', '101.226.4.6', '218.30.118.6',
    '123.125.81.6', '140.207.198.6', '180.76.76.76', '101.198.192.33',
    '101.198.198.198', '112.124.47.27', '114.215.126.16', '119.147.53.99',
    '106.120.178.94', '210.2.4.8', '210.21.196.6', '221.5.203.98',
    '221.6.4.66', '221.6.156.178', '221.7.92.98', '221.7.128.68',
    '221.7.136.68', '221.11.1.67', '221.11.1.68', '221.12.1.227',
    '221.12.33.227', '221.13.28.228', '221.13.28.234', '221.13.65.34',
    '221.131.143.69', '221.199.13.72', '221.199.16.130', '222.172.200.68',
    '222.186.30.112', '222.216.254.162', '222.246.129.80', '61.139.2.69',
    # 国际公共DNS (60个)
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112',
    '208.67.222.222', '208.67.220.220', '64.6.64.6', '64.6.65.6',
    '84.200.69.80', '84.200.70.40', '8.26.56.26', '8.20.247.20',
    '185.228.168.9', '185.228.169.9', '156.154.70.1', '156.154.71.1',
    '198.101.242.72', '23.253.163.53', '176.103.130.130', '176.103.130.131',
    '45.32.36.36', '45.32.72.72', '5.2.75.75', '5.2.75.76',
    '193.183.98.66', '194.187.251.67', '195.46.39.39', '195.46.39.40',
    '37.235.1.174', '37.235.1.177', '89.233.43.71', '91.239.100.100',
    '74.82.42.42', '109.69.8.51', '216.146.35.35', '216.146.36.36',
    '199.85.126.10', '199.85.127.10', '198.54.117.10', '198.54.117.11',
    '205.171.3.65', '205.171.2.65', '216.87.84.211', '216.87.84.212',
    '216.87.106.229', '216.87.106.230', '208.76.50.50', '208.76.51.51',
    '103.247.36.36', '103.247.37.37', '202.83.95.227', '202.83.95.229',
    '203.112.2.4', '203.112.2.5', '202.14.67.4', '202.14.67.14',
    '203.80.96.10', '203.80.96.9', '202.45.84.58', '202.45.84.59',
    # 教育网/科研DNS (20个)
    '202.112.20.131', '202.112.20.132', '202.112.0.44', '202.112.0.46',
    '202.112.0.35', '202.112.0.36', '202.112.0.55', '202.112.0.56',
    '210.28.0.10', '210.28.0.11', '210.28.128.10', '210.28.128.11',
    '210.28.129.10', '210.28.129.11', '210.28.130.10', '210.28.130.11',
    '210.28.131.10', '210.28.131.11', '210.28.132.10', '210.28.132.11',
    # 亚洲其他地区DNS (40个)
    '203.80.96.10', '203.80.96.9',  # 香港
    '202.181.202.140', '202.181.224.2',  # 澳门
    '168.95.1.1', '168.95.192.1',  # 台湾
    '203.145.0.1', '203.145.0.2',  # 台湾
    '202.39.152.12', '202.39.152.11',  # 日本
    '202.12.27.33', '202.12.29.33',  # 日本
    '210.114.1.21', '210.114.1.22',  # 韩国
    '164.124.101.2', '203.248.252.2',  # 韩国
    '103.196.38.38', '103.196.38.39',  # 新加坡
    '165.21.83.88', '165.21.100.88',  # 新加坡
    '202.47.117.77', '202.47.117.78',  # 泰国
    '203.113.5.30', '203.113.5.31',  # 越南
    '202.86.249.20', '202.86.249.21',  # 马来西亚
    '202.158.40.1', '202.158.40.2',  # 菲律宾
    '202.56.250.5', '202.56.250.6',  # 印度
    '203.94.227.70', '203.94.227.71',  # 印度
    '202.83.121.10', '202.83.121.11',  # 巴基斯坦
    '202.165.96.1', '202.165.96.2',  # 孟加拉
    # 欧美地区DNS (40个)
    '8.26.56.26', '8.20.247.20',  # Comodo
    '195.46.39.39', '195.46.39.40',  # SafeDNS
    '81.218.119.11', '209.88.198.133',  # GreenTeam
    '89.233.43.71', '91.239.100.100',  # censurfridns
    '77.109.148.136', '77.109.148.137',  # Freetz
    '94.247.43.254', '94.247.43.253',  # DNS.WATCH
    '176.103.130.130', '176.103.130.131',  # AdGuard
    '84.200.69.80', '84.200.70.40',  # DNS.WATCH
    '208.76.50.50', '208.76.51.51',  # SmartViper
    '199.85.126.10', '199.85.127.10',  # Norton
    '198.153.192.1', '198.153.194.1',  # OpenDNS
    '216.146.35.35', '216.146.36.36',  # Dyn
    '37.235.1.174', '37.235.1.177',  # FreeDNS
    '156.154.70.1', '156.154.71.1',  # Neustar
    '45.32.36.36', '45.32.72.72',  # Fourth Estate
    '5.2.75.75', '5.2.75.76',  # Computerblue
    '193.183.98.66', '194.187.251.67'  # DNS0
]

DNS_DESCRIPTIONS = {
    # ============= 中国大陆DNS (40个) =============
    '114.114.114.114': '114DNS (国内用户推荐, 电信联通移动多线接入)',
    '114.114.115.115': '114DNS 备用服务器 (国内)',
    '223.5.5.5': '阿里公共DNS (阿里巴巴提供, 国内多线BGP)',
    '223.6.6.6': '阿里公共DNS 备用节点',
    '119.29.29.29': 'DNSPod DNS+ (腾讯云旗下, 国内多线)',
    '182.254.116.116': 'DNSPod 企业版DNS',
    '101.226.4.6': '中国电信骨干DNS (上海)',
    '218.30.118.6': '中国电信骨干DNS (西安)',
    '123.125.81.6': '百度公共DNS (北京联通)',
    '140.207.198.6': '中国联通骨干DNS (北京)',
    '180.76.76.76': '百度公共DNS (全球Anycast)',
    '101.198.192.33': '清华大学TUNA DNS',
    '101.198.198.198': '清华大学TUNA DNS 备用',
    '112.124.47.27': 'OneDNS (安全DNS, 拦截恶意网站)',
    '114.215.126.16': 'CNNIC SDNS (中国互联网络信息中心)',
    '119.147.53.99': '新网DNS (国内多线)',
    '106.120.178.94': '方正宽带DNS',
    '210.2.4.8': '中国互联网应急中心DNS (CNCERT)',
    '210.21.196.6': '中国教育网DNS (广州)',
    '221.5.203.98': '广东电信DNS',
    '221.6.4.66': '江苏电信DNS (南京)',
    '221.6.156.178': '江苏电信DNS 备用',
    '221.7.92.98': '广西电信DNS (南宁)',
    '221.7.128.68': '云南电信DNS (昆明)',
    '221.7.136.68': '云南电信DNS 备用',
    '221.11.1.67': '陕西电信DNS (西安)',
    '221.11.1.68': '陕西电信DNS 备用',
    '221.12.1.227': '浙江电信DNS (杭州)',
    '221.12.33.227': '浙江电信DNS 备用',
    '221.13.28.228': '内蒙古联通DNS (呼和浩特)',
    '221.13.28.234': '内蒙古联通DNS 备用',
    '221.13.65.34': '山西联通DNS (太原)',
    '221.131.143.69': '海南移动DNS',
    '221.199.13.72': '内蒙古移动DNS',
    '221.199.16.130': '黑龙江移动DNS',
    '222.172.200.68': '云南移动DNS',
    '222.186.30.112': '江苏移动DNS',
    '222.216.254.162': '广西移动DNS',
    '222.246.129.80': '湖南电信DNS',
    '61.139.2.69': '四川电信DNS (成都)',

    # ============= 国际公共DNS (60个) =============
    '8.8.8.8': 'Google Public DNS (全球Anycast, 最常用公共DNS)',
    '8.8.4.4': 'Google Public DNS 备用节点',
    '1.1.1.1': 'Cloudflare DNS (全球最快, 隐私保护)',
    '1.0.0.1': 'Cloudflare DNS 备用节点',
    '9.9.9.9': 'Quad9 DNS (恶意网站拦截, IBM支持)',
    '149.112.112.112': 'Quad9 无过滤DNS',
    '208.67.222.222': 'OpenDNS (思科旗下, 家庭防护)',
    '208.67.220.220': 'OpenDNS 备用节点',
    '64.6.64.6': 'Verisign Public DNS (稳定可靠)',
    '64.6.65.6': 'Verisign Public DNS 备用',
    '84.200.69.80': 'DNS.WATCH (德国, 无日志)',
    '84.200.70.40': 'DNS.WATCH 备用节点',
    '8.26.56.26': 'Comodo Secure DNS (恶意软件防护)',
    '8.20.247.20': 'Comodo Secure DNS 备用',
    '185.228.168.9': 'CleanBrowsing (家庭过滤)',
    '185.228.169.9': 'CleanBrowsing 备用',
    '156.154.70.1': 'Neustar DNS (企业级安全)',
    '156.154.71.1': 'Neustar DNS 备用',
    '198.101.242.72': 'Alternate DNS (广告拦截)',
    '23.253.163.53': 'Alternate DNS 备用',
    '176.103.130.130': 'AdGuard DNS (广告拦截)',
    '176.103.130.131': 'AdGuard DNS 备用',
    '45.32.36.36': 'Fourth Estate DNS (非营利组织)',
    '45.32.72.72': 'Fourth Estate DNS 备用',
    '5.2.75.75': 'Computerblue DNS (荷兰)',
    '5.2.75.76': 'Computerblue DNS 备用',
    '193.183.98.66': 'DNS0 (瑞士, 隐私保护)',
    '194.187.251.67': 'DNS0 备用节点',
    '195.46.39.39': 'SafeDNS (俄罗斯, 内容过滤)',
    '195.46.39.40': 'SafeDNS 备用',
    '37.235.1.174': 'FreeDNS (欧洲, 无过滤)',
    '37.235.1.177': 'FreeDNS 备用',
    '89.233.43.71': 'UncensoredDNS (丹麦, 无审查)',
    '91.239.100.100': 'UncensoredDNS 备用',
    '74.82.42.42': 'Hurricane Electric DNS (美国)',
    '109.69.8.51': ' puntCAT DNS (西班牙加泰罗尼亚)',
    '216.146.35.35': 'Dyn DNS (美国)',
    '216.146.36.36': 'Dyn DNS 备用',
    '199.85.126.10': 'Norton ConnectSafe (赛门铁克安全DNS)',
    '199.85.127.10': 'Norton ConnectSafe 备用',
    '198.54.117.10': 'GreenTeamDNS (环保组织支持)',
    '198.54.117.11': 'GreenTeamDNS 备用',
    '205.171.3.65': 'AT&T DNS (美国)',
    '205.171.2.65': 'AT&T DNS 备用',
    '216.87.84.211': 'XO Communications DNS',
    '216.87.84.212': 'XO Communications 备用',
    '216.87.106.229': 'XO Communications DNS (西部)',
    '216.87.106.230': 'XO Communications 备用',
    '208.76.50.50': 'SmartViper DNS (美国)',
    '208.76.51.51': 'SmartViper DNS 备用',
    '103.247.36.36': 'DNSforAsian (亚洲优化)',
    '103.247.37.37': 'DNSforAsian 备用',
    '202.83.95.227': 'NTT Communications DNS (日本)',
    '202.83.95.229': 'NTT Communications 备用',
    '203.112.2.4': 'IIJ DNS (日本)',
    '203.112.2.5': 'IIJ DNS 备用',
    '202.14.67.4': 'APNIC DNS (亚太互联网络信息中心)',
    '202.14.67.14': 'APNIC DNS 备用',
    '203.80.96.10': 'HKNet DNS (香港)',
    '203.80.96.9': 'HKNet DNS 备用',
    '202.45.84.58': 'Telstra DNS (澳大利亚)',
    '202.45.84.59': 'Telstra DNS 备用',

    # ============= 教育网/科研DNS (20个) =============
    '202.112.20.131': '中国教育网DNS (北京主节点)',
    '202.112.20.132': '中国教育网DNS 备用',
    '202.112.0.44': '清华大学校园网DNS',
    '202.112.0.46': '清华大学校园网DNS 备用',
    '202.112.0.35': '北京大学校园网DNS',
    '202.112.0.36': '北京大学校园网DNS 备用',
    '202.112.0.55': '中国科技大学校园网DNS',
    '202.112.0.56': '中国科技大学校园网DNS 备用',
    '210.28.0.10': '浙江大学校园网DNS',
    '210.28.0.11': '浙江大学校园网DNS 备用',
    '210.28.128.10': '复旦大学校园网DNS',
    '210.28.128.11': '复旦大学校园网DNS 备用',
    '210.28.129.10': '上海交通大学校园网DNS',
    '210.28.129.11': '上海交通大学校园网DNS 备用',
    '210.28.130.10': '南京大学校园网DNS',
    '210.28.130.11': '南京大学校园网DNS 备用',
    '210.28.131.10': '武汉大学校园网DNS',
    '210.28.131.11': '武汉大学校园网DNS 备用',
    '210.28.132.10': '中山大学校园网DNS',
    '210.28.132.11': '中山大学校园网DNS 备用',

    # ============= 亚洲其他地区DNS (40个) =============
    '203.80.96.10': 'HKNet DNS (香港)',
    '203.80.96.9': 'HKNet DNS 备用',
    '202.181.202.140': 'CTM DNS (澳门电信)',
    '202.181.224.2': 'CTM DNS 备用',
    '168.95.1.1': 'HiNet DNS (台湾中华电信)',
    '168.95.192.1': 'HiNet DNS 备用',
    '203.145.0.1': 'TFN DNS (台湾大哥大)',
    '203.145.0.2': 'TFN DNS 备用',
    '202.39.152.12': 'So-net DNS (日本)',
    '202.39.152.11': 'So-net DNS 备用',
    '202.12.27.33': 'WIDE DNS (日本)',
    '202.12.29.33': 'WIDE DNS 备用',
    '210.114.1.21': 'KT DNS (韩国电信)',
    '210.114.1.22': 'KT DNS 备用',
    '164.124.101.2': 'SK Broadband DNS (韩国)',
    '203.248.252.2': 'SK Broadband DNS 备用',
    '103.196.38.38': 'Singtel DNS (新加坡电信)',
    '103.196.38.39': 'Singtel DNS 备用',
    '165.21.83.88': 'StarHub DNS (新加坡)',
    '165.21.100.88': 'StarHub DNS 备用',
    '202.47.117.77': 'TOT DNS (泰国)',
    '202.47.117.78': 'TOT DNS 备用',
    '203.113.5.30': 'VNPT DNS (越南)',
    '203.113.5.31': 'VNPT DNS 备用',
    '202.86.249.20': 'TM DNS (马来西亚)',
    '202.86.249.21': 'TM DNS 备用',
    '202.158.40.1': 'PLDT DNS (菲律宾)',
    '202.158.40.2': 'PLDT DNS 备用',
    '202.56.250.5': 'BSNL DNS (印度)',
    '202.56.250.6': 'BSNL DNS 备用',
    '203.94.227.70': 'MTNL DNS (印度孟买)',
    '203.94.227.71': 'MTNL DNS 备用',
    '202.83.121.10': 'PTCL DNS (巴基斯坦)',
    '202.83.121.11': 'PTCL DNS 备用',
    '202.165.96.1': 'BTCL DNS (孟加拉)',
    '202.165.96.2': 'BTCL DNS 备用',

    # ============= 欧美地区DNS (40个) =============
    '8.26.56.26': 'Comodo Secure DNS (美国)',
    '8.20.247.20': 'Comodo Secure DNS 备用',
    '195.46.39.39': 'SafeDNS (俄罗斯)',
    '195.46.39.40': 'SafeDNS 备用',
    '81.218.119.11': 'GreenTeamDNS (欧洲)',
    '209.88.198.133': 'GreenTeamDNS 备用',
    '89.233.43.71': 'UncensoredDNS (丹麦)',
    '91.239.100.100': 'UncensoredDNS 备用',
    '77.109.148.136': 'Freetz DS (德国)',
    '77.109.148.137': 'Freetz DS 备用',
    '94.247.43.254': 'DNS.WATCH (德国)',
    '94.247.43.253': 'DNS.WATCH 备用',
    '176.103.130.130': 'AdGuard DNS (俄罗斯)',
    '176.103.130.131': 'AdGuard DNS 备用',
    '84.200.69.80': 'DNS.WATCH (德国)',
    '84.200.70.40': 'DNS.WATCH 备用',
    '208.76.50.50': 'SmartViper DNS (美国)',
    '208.76.51.51': 'SmartViper DNS 备用',
    '199.85.126.10': 'Norton ConnectSafe (美国)',
    '199.85.127.10': 'Norton ConnectSafe 备用',
    '198.153.192.1': 'OpenDNS FamilyShield (美国)',
    '198.153.194.1': 'OpenDNS FamilyShield 备用',
    '216.146.35.35': 'Dyn DNS (美国)',
    '216.146.36.36': 'Dyn DNS 备用',
    '37.235.1.174': 'FreeDNS (欧洲)',
    '37.235.1.177': 'FreeDNS 备用',
    '156.154.70.1': 'Neustar DNS (美国)',
    '156.154.71.1': 'Neustar DNS 备用',
    '45.32.36.36': 'Fourth Estate DNS (美国)',
    '45.32.72.72': 'Fourth Estate DNS 备用',
    '5.2.75.75': 'Computerblue DNS (荷兰)',
    '5.2.75.76': 'Computerblue DNS 备用',
    '193.183.98.66': 'DNS0 (瑞士)',
    '194.187.251.67': 'DNS0 备用'
}



class PingThread(QThread):
    update_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(str, float, int)  # 统计信息: 平均延迟, 丢包率

    def __init__(self, ip):
        super().__init__()
        self.ip = ip
        self._is_running = True

    def run(self):
        try:
            latencies = []
            lost_count = 0
            
            self.update_signal.emit(f"开始Ping测试 {self.ip}...\n")
            
            for i in range(4):
                if not self._is_running:
                    break
                
                try:
                    # 显示当前ping次数
                    self.update_signal.emit(f"第 {i+1} 次Ping: ")
                    
                    # Windows系统使用ping -n，Linux/Mac使用ping -c
                    command = ["ping", "-n", "1", self.ip] if os.name == 'nt' else ["ping", "-c", "1", self.ip]
                    process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
                        text=True,
                        encoding='gbk' if os.name == 'nt' else 'utf-8',
                        shell=False  # 明确设置shell=False
                    )
                    output, _ = process.communicate(timeout=5)  # 增加5秒超时
                    
                    # 显示完整的ping输出
                    self.update_signal.emit(f"\n{output}\n")
                    
                    if "time=" in output or "时间=" in output:
                        # 提取延迟时间
                        time_str = output.split("time=")[1].split(" ")[0] if "time=" in output else output.split("时间=")[1].split("ms")[0]
                        latency = float(time_str)
                        latencies.append(latency)
                        self.update_signal.emit(f"第 {i+1} 次: 延迟 {latency:.2f}ms\n")
                    else:
                        lost_count += 1
                        self.update_signal.emit(f"第 {i+1} 次: 请求超时\n")
                except subprocess.TimeoutExpired:
                    process.kill()
                    output, _ = process.communicate()
                    lost_count += 1
                    self.update_signal.emit(f"第 {i+1} 次: 超时\n")
                except Exception as e:
                    self.update_signal.emit(f"第 {i+1} 次: 错误 - {str(e)}\n")
                    lost_count += 1
            
            # 计算统计信息
            avg_latency = sum(latencies)/len(latencies) if latencies else 0
            loss_rate = (lost_count / 4) * 100
            
            self.update_signal.emit(f"\n=== 统计 ===\n平均延迟: {avg_latency:.2f}ms\n丢包率: {loss_rate:.1f}%\n")
            self.finished_signal.emit("Ping测试完成", avg_latency, loss_rate)
            
        except Exception as e:
            self.update_signal.emit(f"\n发生严重错误: {str(e)}\n")
            self.finished_signal.emit("Ping测试失败", 0, 100)


    def stop(self):
        self._is_running = False

class PingDialog(QDialog):
    def __init__(self, ip, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Ping测试 - {ip}")
        self.setFixedSize(400, 300)
        
        self.ping_thread = PingThread(ip)
        
        self.init_ui()
        self.start_ping()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # 结果显示区域
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(4)
        layout.addWidget(self.progress_bar)
        
        # 状态标签
        self.status_label = QLabel("准备Ping测试...")
        layout.addWidget(self.status_label)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        
        self.copy_button = QPushButton("复制结果")
        self.copy_button.clicked.connect(self.copy_results)
        button_layout.addWidget(self.copy_button)
        
        self.close_button = QPushButton("关闭窗口")
        self.close_button.clicked.connect(self.close)
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
        # 连接信号
        self.ping_thread.update_signal.connect(self.update_output)
        self.ping_thread.finished_signal.connect(self.on_ping_finished)
        
    def start_ping(self):
        self.ping_thread.start()
        
    def update_output(self, text):
        self.result_text.moveCursor(QTextCursor.MoveOperation.End)
        self.result_text.insertPlainText(text)
        self.progress_bar.setValue(self.progress_bar.value() + 1)
        
    def on_ping_finished(self, status, avg_latency, loss_rate):
        self.status_label.setText(status)
        self.copy_button.setEnabled(True)
        self.close_button.setEnabled(True)
        
    def copy_results(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.result_text.toPlainText())
        self.status_label.setText("结果已复制到剪贴板")
        
    def closeEvent(self, event):
        self.ping_thread.stop()
        self.ping_thread.wait()
        super().closeEvent(event)

class DNSDetector(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{ProjectInfo.NAME} {ProjectInfo.VERSION} {ProjectInfo.BUILD_DATE}")
        self.setWindowIcon(QIcon('icon.ico'))
        self.setFixedSize(700, 700)
        
        # 初始化AI模型
        self.model = None
        self.load_or_train_model()
        self.history = []
        
        # 创建主界面
        self.init_ui()
        
    def load_or_train_model(self):
        """加载或训练AI模型"""
        model_file = "dns_model.pkl"
        if os.path.exists(model_file):
            try:
                self.model = joblib.load(model_file)
            except:
                self.train_model()
                joblib.dump(self.model, model_file)
        else:
            self.train_model()
            joblib.dump(self.model, model_file)
    
    def train_model(self):
        """训练AI模型来预测DNS可靠性"""
        # 模拟一些训练数据 (在实际应用中应该使用真实数据)
        np.random.seed(42)
        X = np.array([
            [np.random.uniform(1, 100), np.random.randint(0, 2), np.random.uniform(0, 1), np.random.randint(0, 3), np.random.randint(0, 5)]
            for _ in range(200)
        ])
        y = np.array([1 if x[0] < 50 and x[1] == 1 else 0 for x in X])
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
        
        self.model = RandomForestClassifier(n_estimators=100)
        self.model.fit(X_train, y_train)
        
        # 打印模型准确率
        accuracy = self.model.score(X_test, y_test)
        print(f"模型训练完成，测试集准确率: {accuracy:.2f}")
    
    def init_ui(self):
        """初始化用户界面"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # 控制面板
        control_layout = QHBoxLayout()
        
        # 检测域名
        self.domain_label = QLabel("检测域名:")
        self.domain_entry = QLineEdit("www.baidu.com")
        control_layout.addWidget(self.domain_label)
        control_layout.addWidget(self.domain_entry)
        
        # 开始检测按钮
        self.detect_button = QPushButton("开始检测")
        self.detect_button.clicked.connect(self.start_detection)
        control_layout.addWidget(self.detect_button)
        
        # 导出结果按钮
        self.export_button = QPushButton("导出结果")
        self.export_button.clicked.connect(self.export_results)
        control_layout.addWidget(self.export_button)
        
        main_layout.addLayout(control_layout)
        
        # 第二行控制面板
        control_layout2 = QHBoxLayout()
        
        # DNS分组选择
        self.group_label = QLabel("DNS分组:")
        self.group_combo = QComboBox()
        self.group_combo.addItems(["全部", "国内DNS", "国际DNS", "教育网DNS", "其他DNS"])
        control_layout2.addWidget(self.group_label)
        control_layout2.addWidget(self.group_combo)
        
        # 自定义DNS
        self.custom_dns_label = QLabel("自定义DNS:")
        self.custom_dns_entry = QLineEdit()
        self.custom_dns_entry.setPlaceholderText("输入IP地址")
        self.add_dns_button = QPushButton("添加")
        self.add_dns_button.clicked.connect(self.add_custom_dns)
        control_layout2.addWidget(self.custom_dns_label)
        control_layout2.addWidget(self.custom_dns_entry)
        control_layout2.addWidget(self.add_dns_button)
        
        main_layout.addLayout(control_layout2)
        
        # 第三行控制面板
        control_layout3 = QHBoxLayout()
        
        # 排序按钮
        self.sort_time_button = QPushButton("按响应时间排序")
        self.sort_time_button.clicked.connect(lambda: self.sort_results("time"))
        control_layout3.addWidget(self.sort_time_button)
        
        self.sort_status_button = QPushButton("按状态排序")
        self.sort_status_button.clicked.connect(lambda: self.sort_results("status"))
        control_layout3.addWidget(self.sort_status_button)
        
        self.sort_reliability_button = QPushButton("按可靠性排序")
        self.sort_reliability_button.clicked.connect(lambda: self.sort_results("reliability"))
        control_layout3.addWidget(self.sort_reliability_button)
        
        # 一键测速按钮
        self.fastest_button = QPushButton("一键测速(前10)")
        self.fastest_button.clicked.connect(self.auto_select_fastest)
        control_layout3.addWidget(self.fastest_button)
        
        # 历史记录按钮
        self.history_button = QPushButton("历史记录")
        self.history_button.clicked.connect(self.show_history)
        control_layout3.addWidget(self.history_button)
        
        main_layout.addLayout(control_layout3)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        main_layout.addWidget(self.progress_bar)
        
        # 结果表格
        self.tree = QTreeWidget()
        self.tree.setColumnCount(5)  # 从4改为5，增加一列
        self.tree.setHeaderLabels(["DNS服务器", "响应时间(ms)", "状态", "可靠性预测", "DNS介绍"])  # 添加新列

        # 设置列宽策略（优化后的版本）
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)  # 第一列可交互调整
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # 第二列根据内容
        self.tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # 第三列根据内容
        self.tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # 第四列根据内容
        self.tree.header().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)  # 第五列（介绍列）自动拉伸
        
        # 设置初始列宽（可选）
        self.tree.setColumnWidth(0, 150)  # DNS服务器列
        self.tree.setColumnWidth(1, 100)  # 响应时间列
        self.tree.setColumnWidth(2, 80)   # 状态列
        self.tree.setColumnWidth(3, 100)  # 可靠性列

        self.tree.header().sectionClicked.connect(self.on_header_clicked)
        
        self.tree.setSortingEnabled(True)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        main_layout.addWidget(self.tree)

        # 统计信息
        stats_layout = QHBoxLayout()
        
        self.total_label = QLabel("总数: 0")
        self.success_label = QLabel("成功: 0")
        self.avg_time_label = QLabel("平均响应: 0ms")
        
        stats_layout.addWidget(self.total_label)
        stats_layout.addWidget(self.success_label)
        stats_layout.addWidget(self.avg_time_label)
        
        main_layout.addLayout(stats_layout)
        
        # 状态栏
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")
        
        # 创建右键菜单
        self.create_context_menu()
    
    def create_context_menu(self):
        """创建右键上下文菜单"""
        self.context_menu = QMenu(self)
        
        # 复制IP动作
        self.copy_action = QAction("复制IP", self)
        self.copy_action.triggered.connect(self.copy_ip)
        self.context_menu.addAction(self.copy_action)
        
        # Ping测试动作
        self.ping_action = QAction("Ping测试", self)
        self.ping_action.triggered.connect(self.ping_test)
        self.context_menu.addAction(self.ping_action)
    
    def show_context_menu(self, position):
        """显示右键上下文菜单"""
        item = self.tree.itemAt(position)
        if item:
            self.context_menu.exec(self.tree.viewport().mapToGlobal(position))
    
    def copy_ip(self):
        """复制选中的IP地址"""
        selected_items = self.tree.selectedItems()
        if selected_items:
            ip = selected_items[0].text(0)
            clipboard = QApplication.clipboard()
            clipboard.setText(ip)
            self.status_bar.showMessage(f"已复制: {ip}", 3000)
    
    def ping_test(self):
        """执行Ping测试"""
        selected_items = self.tree.selectedItems()
        if selected_items:
            ip = selected_items[0].text(0)
            ping_dialog = PingDialog(ip, self)
            ping_dialog.exec()
    
    def start_detection(self):
        """开始检测DNS服务器"""
        domain = self.domain_entry.text().strip()
        if not domain:
            QMessageBox.critical(self, "错误", "请输入要检测的域名")
            return
        
        # 获取选择的分组
        selected_group = self.group_combo.currentText()
        filtered_dns = DNS_SERVERS
        if selected_group != "全部":
            group_mapping = {
                "国内DNS": DNS_SERVERS[:40],
                "国际DNS": DNS_SERVERS[40:100],
                "教育网DNS": DNS_SERVERS[100:120],
                "其他DNS": DNS_SERVERS[120:]
            }
            filtered_dns = group_mapping.get(selected_group, DNS_SERVERS)
            self.status_bar.showMessage(f"正在检测【{selected_group}】分组 ({len(filtered_dns)}个DNS)...")
        else:
            self.status_bar.showMessage(f"正在检测全部DNS服务器 ({len(DNS_SERVERS)}个)...")
        
        # 清空之前的结果
        self.tree.clear()
        
        # 更新进度条
        self.progress_bar.setMaximum(len(filtered_dns))
        self.progress_bar.setValue(0)
        
        # 使用多线程检测DNS
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for dns in filtered_dns:
                futures.append(executor.submit(self.check_dns, dns, domain))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    self.update_tree(result)
                    self.progress_bar.setValue(self.progress_bar.value() + 1)
                    QApplication.processEvents()  # 刷新界面
                except Exception as e:
                    print(f"检测出错: {e}")
        
        # 检测完成后自动排序并设置颜色
        self.apply_sorted_macaron_scheme()
        self.status_bar.showMessage(f"检测完成，共检测了{len(filtered_dns)}个DNS服务器", 5000)
    
    def check_dns(self, dns_server, domain):
        """检测单个DNS服务器"""
        # IP格式验证
        try:
            socket.inet_aton(dns_server)
        except socket.error:
            return {
                "dns": dns_server,
                "time": "无效IP",
                "status": "失败",
                "reliability": "未知",
                "description": "无效IP地址"  # 新增描述字段
            }

        # 获取DNS描述信息
        description = DNS_DESCRIPTIONS.get(dns_server, "未知DNS服务商")  # 新增
        
        time.sleep(0.05)
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        resolver.timeout = 2
        resolver.lifetime = 2
        
        start_time = time.time()
        status = "失败"
        response_time = 0
        
        try:
            answer = resolver.resolve(domain, 'A')
            response_time = (time.time() - start_time) * 1000  # 转换为毫秒
            status = "成功"
            
            # 使用AI预测可靠性
            features = np.array([[response_time, 1, 0, 0, 0]])  # 示例特征
            reliability = "高" if self.model.predict(features)[0] == 1 else "低"
        except Exception as e:
            reliability = "未知"
        
        return {
            "dns": dns_server,
            "time": response_time if isinstance(response_time, (int, float)) else float('inf'),  # 确保是数值
            "status": status,
            "reliability": reliability,
            "description": description
        }

    
    def update_tree(self, result):
        """更新结果到树状表格"""
        item = QTreeWidgetItem(self.tree)
        item.setText(0, result["dns"])

        # 显示格式化后的时间
        if isinstance(result["time"], str) and result["time"] == "超时":
            time_text = "超时"
            time_value = float('inf')
        else:
            try:
                time_value = float(result["time"])
                time_text = f"{time_value:.2f}"
            except (ValueError, TypeError):
                time_text = "超时"
                time_value = float('inf')

        item.setText(1, time_text)

        # 确保存储的是数值类型
        item.setData(1, Qt.ItemDataRole.UserRole, time_value)

        item.setText(2, result["status"])
        item.setText(3, result["reliability"])
        item.setText(4, result["description"])
        
        # 存储原始数值用于排序（关键修改）
        # time_value = float('inf') if result["time"] == "超时" else result["time"]
        # item.setData(1, Qt.ItemDataRole.UserRole, time_value)  # 确保存储的是数值
        
        # 根据状态设置颜色
        if result["status"] == "成功":
            item.setForeground(2, QColor(0, 128, 0))  # 绿色
        else:
            item.setForeground(2, QColor(255, 0, 0))  # 红色
            
        # 根据可靠性设置颜色
        if result["reliability"] == "高":
            item.setForeground(3, QColor(0, 128, 0))  # 绿色
        elif result["reliability"] == "中":
            item.setForeground(3, QColor(255, 165, 0))  # 橙色
        elif result["reliability"] == "低":
            item.setForeground(3, QColor(255, 0, 0))  # 红色
            
        self.update_stats()
    
    def sort_results(self, sort_by):
        """根据指定字段排序结果"""
        if self.tree.topLevelItemCount() == 0:
            return
        
        # print(f"\n[DEBUG] 排序开始 - 按 {sort_by} 排序")
        
        # 完全禁用内置排序
        self.tree.setSortingEnabled(False)
        
        # 获取所有项目
        items = [self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount())]

        # 定义排序键函数
        def get_key(item):
            if sort_by == "time":
                # 直接从UserRole获取数值
                time_val = item.data(1, Qt.ItemDataRole.UserRole)
                # 确保返回的是可比较的数值
                return float(time_val) if isinstance(time_val, (int, float)) else float('inf')
            elif sort_by == "status":
                return item.text(2)  # "成功"排在前面
            elif sort_by == "reliability":
                reliability_map = {"高": 0, "中": 1, "低": 2, "未知": 3}
                return reliability_map.get(item.text(3), 3)
            return 0
        
        # 确定排序方向
        reverse_order = (sort_by == "reliability")  # 只有可靠性需要降序
        
        # 执行排序
        items.sort(key=get_key, reverse=reverse_order)
        
        # 清除并重新添加排序后的项目
        root = self.tree.invisibleRootItem()
        for item in items:
            root.removeChild(item)
            root.addChild(item)
        
        # 如果是按时间排序，应用新的颜色方案
        if sort_by == "time":
            # self.apply_sorted_macaron_scheme()
            # print("\n[DEBUG] 排序后检查:")
            for i, item in enumerate(items[:10]):  # 只打印前10项
                time_text = item.text(1)
                time_data = item.data(1, Qt.ItemDataRole.UserRole)
                # print(f"[DEBUG] 排序后项目 {i+1}: 显示文本='{time_text}', 存储数据={time_data}")





    
    def update_stats(self):
        """更新统计信息"""
        total = self.tree.topLevelItemCount()
        success = 0
        total_time = 0.0
        valid_times = 0
        
        for i in range(total):
            item = self.tree.topLevelItem(i)
            if item.text(2) == "成功":
                success += 1
            try:
                time_val = float(item.text(1))
                total_time += time_val
                valid_times += 1
            except:
                pass
        
        avg_time = total_time / valid_times if valid_times > 0 else 0
        
        self.total_label.setText(f"总数: {total}")
        self.success_label.setText(f"成功: {success}")
        self.avg_time_label.setText(f"平均响应: {avg_time:.2f}ms")
    
    def export_results(self):
        """导出检测结果到CSV文件"""
        try:
            data = []
            for i in range(self.tree.topLevelItemCount()):
                item = self.tree.topLevelItem(i)
                data.append({
                    "DNS服务器": item.text(0),
                    "响应时间(ms)": item.text(1),
                    "状态": item.text(2),
                    "AI可靠性预测": item.text(3),
                    "DNS介绍": item.text(4)
                })
            
            if not data:
                QMessageBox.warning(self, "警告", "没有可导出的数据")
                return
            
            df = pd.DataFrame(data)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"dns_results_{timestamp}.csv"
            df.to_csv(filename, index=False, encoding="utf_8_sig")
            
            QMessageBox.information(self, "成功", f"结果已导出到 {filename}")
            
            # 保存历史记录
            self.history.append({
                "time": timestamp,
                "domain": self.domain_entry.text(),
                "count": len(data)
            })
        except Exception as e:
            QMessageBox.critical(self, "错误", f"导出失败: {e}")
    
    def auto_select_fastest(self):
        """自动选择响应最快的10个DNS服务器"""
        if self.tree.topLevelItemCount() == 0:
            QMessageBox.warning(self, "提示", "请先执行检测")
            return
        
        # 收集有效项目
        valid_items = []
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            time_val = item.data(1, Qt.ItemDataRole.UserRole)
            if time_val != float('inf'):
                valid_items.append((time_val, item))
        
        if not valid_items:
            QMessageBox.warning(self, "提示", "没有有效的响应时间数据")
            return
        
        # 按响应时间排序
        valid_items.sort(key=lambda x: x[0])
        
        # 重置所有背景色
        for i in range(self.tree.topLevelItemCount()):
            self.tree.topLevelItem(i).setBackground(0, QColor(255, 255, 255))
        
        # 标记最快的10个
        for _, item in valid_items[:10]:
            item.setBackground(0, QColor(144, 238, 144))  # 浅绿色
        
        QMessageBox.information(self, "完成", "已标记响应最快的10个DNS服务器")




    
    def add_custom_dns(self):
        """添加自定义DNS到检测列表"""
        custom_dns = self.custom_dns_entry.text().strip()
        if not custom_dns:
            QMessageBox.warning(self, "警告", "请输入DNS服务器IP地址")
            return
        
        # 简单的IP地址验证
        try:
            socket.inet_aton(custom_dns)
        except socket.error:
            QMessageBox.warning(self, "警告", "请输入有效的IP地址")
            return
        
        if custom_dns not in DNS_SERVERS:
            DNS_SERVERS.append(custom_dns)
            self.custom_dns_entry.clear()
            QMessageBox.information(self, "成功", f"已添加DNS: {custom_dns}")
        else:
            QMessageBox.warning(self, "提示", "该DNS已存在于列表中")
    
    def show_history(self):
        """显示历史记录窗口"""
        if not self.history:
            QMessageBox.information(self, "提示", "暂无历史记录")
            return
        
        history_dialog = QDialog(self)
        history_dialog.setWindowTitle("检测历史记录")
        history_dialog.setFixedSize(400, 300)
        
        layout = QVBoxLayout()
        
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        
        for record in self.history:
            text_edit.append(f"时间: {record['time']}")
            text_edit.append(f"域名: {record['domain']}")
            text_edit.append(f"检测数量: {record['count']}\n")
        
        layout.addWidget(text_edit)
        
        close_button = QPushButton("关闭")
        close_button.clicked.connect(history_dialog.close)
        layout.addWidget(close_button)
        
        history_dialog.setLayout(layout)
        history_dialog.exec()

    def on_header_clicked(self, logical_index):
        """处理表头点击事件"""
        if logical_index == 1:  # 响应时间列的索引
            print("\n[DEBUG] 表头点击 - 响应时间列")
            self.sort_results("time")
        elif logical_index == 2:  # 状态列
            self.sort_results("status")
        elif logical_index == 3:  # 可靠性列
            self.sort_results("reliability")

    def get_color_scheme(self, value, min_val, max_val):
        """根据值在最小最大值之间的位置计算背景色和文字颜色"""
        if max_val == min_val:
            ratio = 0.5
        else:
            ratio = (value - min_val) / (max_val - min_val)
        
        # 从绿色(快)到红色(慢)的渐变
        red = int(255 * ratio)
        green = int(255 * (1 - ratio))
        blue = 0
        
        # 计算亮度 (0~1)
        brightness = (0.299 * red + 0.587 * green + 0.114 * blue) / 255
        
        # 根据亮度决定文字颜色
        text_color = QColor(0, 0, 0) if brightness > 0.5 else QColor(255, 255, 255)
        
        return QColor(red, green, blue), text_color

    def apply_color_scheme(self):
        """应用马卡龙色系方案"""
        if self.tree.topLevelItemCount() == 0:
            return

        # 马卡龙色系配色方案 (柔和的粉彩色)
        macaron_colors = [
            QColor(255, 209, 220),  # 粉红
            QColor(207, 246, 216),  # 薄荷绿
            QColor(255, 247, 193),  # 淡黄
            QColor(214, 232, 255),  # 淡蓝
            QColor(255, 219, 207),  # 杏色
            QColor(230, 220, 255),  # 淡紫
            QColor(220, 255, 247),  # 浅青
            QColor(255, 227, 227)   # 浅珊瑚
        ]

        # 先按响应时间排序
        self.sort_results("time")

        # 应用马卡龙色系
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            
            # 循环使用马卡龙色系
            bg_color = macaron_colors[i % len(macaron_colors)]
            
            # 根据背景色亮度自动选择文字颜色
            brightness = (bg_color.red() * 299 + bg_color.green() * 587 + bg_color.blue() * 114) / 1000
            text_color = QColor(80, 80, 80) if brightness > 180 else QColor(240, 240, 240)
            
            # 设置所有列的背景色和文字颜色
            for col in range(self.tree.columnCount()):
                item.setBackground(col, bg_color)
                item.setForeground(col, text_color)


    def apply_sorted_macaron_scheme(self):
        """应用基于响应时间排序的马卡龙渐变色系方案"""
        if self.tree.topLevelItemCount() == 0:
            return

        # 完整的马卡龙渐变色系 (从快到慢)
        macaron_gradient = [
            # 粉色系（24色）
            # 基础粉
            QColor(255, 209, 220),  # 马卡龙粉 (Macaron Pink)
            QColor(255, 220, 230),  # 樱花粉 (Sakura Pink)
            QColor(255, 200, 230),  # 泡泡糖粉 (Bubblegum)
            QColor(255, 215, 225),  # 草莓奶霜 (Strawberry Cream)

            # 浅粉变体
            QColor(255, 225, 235),  # 棉花糖 (Marshmallow)
            QColor(255, 230, 240),  # 糖霜粉 (Frosting)
            QColor(255, 235, 245),  # 天使粉 (Angel Pink)
            QColor(255, 240, 250),  # 珍珠粉 (Pearl Pink)

            # 深粉变体（保持柔和）
            QColor(255, 190, 215),  # 玫瑰糖 (Rose Candy)
            QColor(255, 185, 210),  # 芍药粉 (Peony Pink)
            QColor(255, 180, 205),  # 蜜桃粉 (Peach Blossom)
            QColor(255, 175, 200),  # 西瓜粉 (Watermelon)

            # 冷调粉
            QColor(245, 210, 230),  # 灰粉 (Dusty Pink)
            QColor(240, 200, 220),  # 薰衣草粉 (Lavender Pink)
            QColor(235, 220, 235),  # 紫粉 (Orchid Pink)
            QColor(250, 215, 240),  # 香槟粉 (Champagne Pink)

            # 暖调粉
            QColor(255, 210, 200),  # 珊瑚粉 (Coral Pink)
            QColor(255, 205, 195),  # 西柚粉 (Grapefruit)
            QColor(255, 200, 190),  # 蜜粉 (Honey Pink)
            QColor(255, 220, 210),  # 奶油粉 (Buttercream Pink)

            # 特殊粉
            QColor(255, 218, 223),  # 芭蕾粉 (Ballet Slipper)
            QColor(255, 228, 225),  # 贝壳粉 (Seashell Pink)
            QColor(255, 238, 227),  # 香草粉 (Vanilla Pink)
            QColor(255, 248, 229),  # 缎面粉 (Satin Pink)

            # 蓝色系（22色）
            # 基础蓝
            QColor(214, 232, 255),  # 淡蓝 (Powder Blue)
            QColor(230, 240, 255),  # 天蓝 (Sky Blue)
            QColor(200, 230, 255),  # 冰蓝 (Ice Blue)
            QColor(220, 230, 250),  # 雾蓝 (Misty Blue)

            # 浅蓝变体
            QColor(210, 220, 255),  # 矢车菊蓝 (Cornflower)
            QColor(180, 220, 255),  # 湖蓝 (Lake Blue)
            QColor(225, 235, 255),  # 婴儿蓝 (Baby Blue)
            QColor(190, 230, 255),  # 冰川蓝 (Glacier)

            # 深蓝变体
            QColor(170, 210, 255),  # 知更鸟蓝 (Robin's Egg)
            QColor(160, 200, 250),  # 浅海军蓝 (Pastel Navy)
            QColor(150, 190, 245),  # 灰蓝 (Slate Blue)
            QColor(200, 215, 255),  # 睡莲蓝 (Water Lily)

            # 绿调蓝
            QColor(185, 240, 255),  # 浅水蓝 (Aqua Blue)
            QColor(175, 230, 250),  # 绿松石蓝 (Turquoise)
            QColor(165, 220, 245),  # 碧蓝 (Cerulean)
            QColor(220, 245, 255),  # 冰河蓝 (Frost Blue)

            # 紫调蓝
            QColor(215, 225, 255),  # 紫苑蓝 (Aster Blue)
            QColor(205, 215, 250),  # 薰衣草蓝 (Lavender Blue)
            QColor(195, 205, 245),  # 紫灰蓝 (Periwinkle)
            QColor(230, 235, 255),  # 月光蓝 (Moonlight Blue)

            # 特殊蓝
            QColor(240, 248, 255),  # 蕾丝蓝 (Lace Blue)
            QColor(220, 240, 255),  # 雪花蓝 (Snow Blue)

            # 绿色系（20色）
            # 基础绿
            QColor(207, 246, 216),  # 薄荷绿 (Mint Green)
            QColor(220, 245, 220),  # 嫩绿 (Pastel Green)
            QColor(210, 255, 210),  # 苹果绿 (Apple Green)
            QColor(200, 255, 200),  # 荧光薄荷 (Neon Mint)

            # 浅绿变体
            QColor(230, 255, 230),  # 青柠绿 (Lime Green)
            QColor(240, 255, 220),  # 蜜瓜绿 (Honeydew)
            QColor(220, 255, 240),  # 冰薄荷 (Frost Mint)
            QColor(230, 250, 230),  # 豌豆绿 (Pea Green)

            # 黄调绿
            QColor(215, 255, 200),  # 柠檬草 (Lemongrass)
            QColor(205, 255, 190),  # 酸橙绿 (Lime)
            QColor(225, 255, 210),  # 香芹绿 (Parsley)
            QColor(235, 255, 220),  # 开心果绿 (Pistachio)

            # 蓝调绿
            QColor(190, 255, 220),  # 海沫绿 (Sea Foam)
            QColor(180, 250, 210),  # 翡翠冰 (Jade Ice)
            QColor(170, 240, 200),  # 绿松石绿 (Turquoise Green)
            QColor(200, 245, 230),  # 水绿 (Aqua Green)

            # 特殊绿
            QColor(245, 255, 230),  # 月光绿 (Moonlight Green)
            QColor(250, 255, 240),  # 乳白绿 (Cream Green)
            QColor(210, 240, 220),  # 灰绿 (Sage Green)
            QColor(220, 235, 225),  # 苔藓绿 (Moss Green)

            # 紫色系（18色）
            # 基础紫
            QColor(230, 220, 255),  # 淡紫 (Lavender)
            QColor(245, 220, 245),  # 薰衣草 (Lilac)
            QColor(240, 230, 255),  # 淡丁香 (Lilac Mist)
            QColor(250, 220, 255),  # 紫藤 (Wisteria)

            # 浅紫变体
            QColor(220, 210, 255),  # 灰紫 (Dusty Purple)
            QColor(255, 220, 255),  # 粉紫 (Pink Lavender)
            QColor(235, 225, 255),  # 香芋紫 (Taro Purple)
            QColor(225, 215, 250),  # 紫水晶 (Amethyst)

            # 蓝调紫
            QColor(210, 200, 255),  # 蓝紫 (Blue Violet)
            QColor(200, 190, 250),  # 紫罗兰 (Violet)
            QColor(190, 180, 245),  # 深薰衣草 (Deep Lavender)
            QColor(230, 220, 245),  # 雾紫 (Misty Purple)

            # 粉调紫
            QColor(255, 210, 255),  # 紫粉 (Orchid)
            QColor(255, 200, 250),  # 亮紫 (Bright Lilac)
            QColor(255, 190, 245),  # 糖果紫 (Candy Purple)
            QColor(255, 230, 255),  # 极光紫 (Aurora Purple)

            # 特殊紫
            QColor(240, 235, 255),  # 珍珠紫 (Pearl Purple)
            QColor(245, 240, 255),  # 白紫 (White Lavender)

            # 橙色/黄色系（22色）
            # 基础黄
            QColor(255, 247, 193),  # 淡黄 (Lemon Cream)
            QColor(255, 240, 200),  # 奶油黄 (Butter Yellow)
            QColor(255, 235, 205),  # 杏仁奶油 (Almond Cream)
            QColor(255, 230, 210),  # 桃橙 (Peach Orange)

            # 浅黄变体
            QColor(255, 225, 180),  # 香槟黄 (Champagne)
            QColor(255, 245, 215),  # 香草奶油 (Vanilla Cream)
            QColor(255, 250, 220),  # 月光黄 (Moonlight Yellow)
            QColor(255, 255, 200),  # 荧光黄 (Neon Yellow)

            # 橙调黄
            QColor(255, 220, 180),  # 杏黄 (Apricot Yellow)
            QColor(255, 215, 175),  # 琥珀黄 (Amber)
            QColor(255, 210, 170),  # 蜂蜜黄 (Honey Yellow)
            QColor(255, 205, 165),  # 姜黄 (Ginger)

            # 粉调黄
            QColor(255, 230, 200),  # 奶油杏 (Cream Apricot)
            QColor(255, 225, 195),  # 桃奶黄 (Peach Cream)
            QColor(255, 220, 190),  # 珊瑚黄 (Coral Yellow)
            QColor(255, 215, 185),  # 日落黄 (Sunset Yellow)

            # 特殊黄
            QColor(255, 240, 190),  # 玉米黄 (Corn Yellow)
            QColor(255, 235, 195),  # 金丝雀黄 (Canary Yellow)
            QColor(255, 230, 220),  # 沙黄 (Sand Yellow)
            QColor(255, 225, 210),  # 香槟金 (Champagne Gold)
            QColor(255, 220, 200),  # 裸黄 (Nude Yellow)
            QColor(255, 215, 205),  # 玫瑰金 (Rose Gold)

            # 混合色 & 特殊色（57色）
            # 粉蓝渐变系（12色）
            QColor(255, 220, 247),  # 粉紫渐变 (Pink-Purple Gradient)
            QColor(250, 225, 245),  # 棉花糖渐变 (Marshmallow Gradient)
            QColor(245, 230, 243),  # 薰衣草雾 (Lavender Mist)
            QColor(220, 255, 247),  # 薄荷青 (Mint Cyan)
            QColor(215, 250, 240),  # 海玻璃绿 (Seaglass Green)
            QColor(210, 245, 233),  # 冰湖渐变 (Ice Lake Gradient)
            QColor(230, 240, 255),  # 天蓝雾 (Sky Blue Mist)
            QColor(225, 235, 250),  # 云朵蓝 (Cloud Blue)
            QColor(255, 240, 230),  # 香草杏 (Vanilla Apricot)
            QColor(255, 235, 220),  # 日落奶油 (Sunset Cream)
            QColor(255, 230, 210),  # 桃色晨光 (Peach Dawn)
            QColor(255, 225, 200),  # 珊瑚雾 (Coral Mist)

            # 低饱和度彩虹色（18色）
            # 红-橙-黄系
            QColor(255, 220, 220),  # 浅樱花红 (Pale Cherry Blossom)
            QColor(255, 225, 210),  # 蜜桃红 (Peachy Red)
            QColor(255, 230, 200),  # 杏橙色 (Apricot Orange)
            QColor(255, 235, 190),  # 香槟橙 (Champagne Orange)
            QColor(255, 240, 180),  # 奶油黄橙 (Butter Yellow-Orange)
            QColor(255, 245, 170),  # 柠檬雾 (Lemon Mist)

            # 绿-青系
            QColor(220, 255, 220),  # 薄雾绿 (Misty Green)
            QColor(210, 255, 230),  # 苹果薄荷 (Apple Mint)
            QColor(200, 255, 240),  # 冰薄荷蓝 (Ice Mint Blue)
            QColor(190, 255, 250),  # 极光青 (Aurora Cyan)

            # 蓝-紫系
            QColor(180, 230, 255),  # 冰晶蓝 (Ice Crystal Blue)
            QColor(190, 220, 255),  # 淡钴蓝 (Pale Cobalt)
            QColor(200, 210, 255),  # 紫雾蓝 (Purple Mist Blue)
            QColor(210, 200, 255),  # 灰紫罗兰 (Gray Violet)
            QColor(220, 190, 255),  # 薰衣草灰 (Lavender Gray)
            QColor(230, 180, 255),  # 粉紫极光 (Pink-Purple Aurora)

            # 红-紫系
            QColor(255, 190, 255),  # 粉紫霓虹 (Pink-Purple Neon)
            QColor(255, 200, 240),  # 玫瑰紫雾 (Rose Purple Mist)

            # 中性调和色（15色）
            # 灰白色系
            QColor(240, 240, 240),  # 珍珠灰 (Pearl Gray)
            QColor(230, 230, 230),  # 雾灰 (Misty Gray)
            QColor(220, 220, 220),  # 丝绸灰 (Silk Gray)
            QColor(250, 250, 250),  # 天使白 (Angel White)
            QColor(245, 245, 245),  # 乳白云 (Cream Cloud)

            # 暖调中性色
            QColor(255, 240, 230),  # 香草沙 (Vanilla Sand)
            QColor(255, 235, 225),  # 杏仁灰 (Almond Gray)
            QColor(255, 230, 220),  # 玫瑰石英 (Rose Quartz)
            QColor(255, 225, 215),  # 裸粉灰 (Nude Pink Gray)

            # 冷调中性色
            QColor(230, 235, 240),  # 冰川灰 (Glacier Gray)
            QColor(225, 230, 235),  # 钢雾灰 (Steel Mist)
            QColor(220, 225, 230),  # 蓝灰 (Blue Gray)
            QColor(235, 230, 235),  # 紫灰 (Lilac Gray)
            QColor(240, 230, 240),  # 粉灰 (Pink Gray)
            QColor(245, 230, 245),  # 薰衣草雾灰 (Lavender Fog)

            # 特殊光影色（12色）
            # 珠光效果
            QColor(255, 248, 240),  # 珍珠母 (Mother of Pearl)
            QColor(255, 250, 230),  # 月光缎 (Moonlight Satin)
            QColor(240, 255, 250),  # 冰晶闪光 (Ice Sparkle)
            QColor(230, 255, 240),  # 极光纱 (Aurora Veil)

            # 透明叠加色
            QColor(255, 230, 230, 150),  # 半透明樱花粉 (Translucent Sakura)
            QColor(230, 240, 255, 150),  # 半透明天蓝 (Translucent Sky Blue)
            QColor(220, 255, 220, 150),  # 半透明薄荷 (Translucent Mint)

            # 金属质感
            QColor(255, 245, 200),  # 香槟金 (Champagne Gold)
            QColor(250, 240, 210),  # 玫瑰金 (Rose Gold)
            QColor(240, 240, 220),  # 铂金灰 (Platinum Gray)
            QColor(255, 240, 220),  # 蜜糖金 (Honey Gold)
            QColor(230, 230, 240),  # 银雾 (Silver Mist)
        ]

        # 先按响应时间排序
        self.sort_results("time")

        # 获取有效响应时间范围
        valid_items = []
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            time_val = item.data(1, Qt.ItemDataRole.UserRole)
            if time_val != float('inf'):
                valid_items.append(time_val)
        
        if not valid_items:
            return

        min_time = min(valid_items)
        max_time = max(valid_items)
        time_range = max_time - min_time if max_time != min_time else 1

        # 应用渐变颜色
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            time_val = item.data(1, Qt.ItemDataRole.UserRole)
            
            if time_val == float('inf'):
                # 超时项目使用灰色
                bg_color = QColor(220, 220, 220)
            else:
                # 计算颜色位置
                ratio = (time_val - min_time) / time_range
                color_idx = min(int(ratio * (len(macaron_gradient) - 1)), len(macaron_gradient) - 1)
                bg_color = macaron_gradient[color_idx]
            
            # 设置所有列的背景色
            for col in range(self.tree.columnCount()):
                item.setBackground(col, bg_color)



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DNSDetector()
    window.show()
    sys.exit(app.exec())




