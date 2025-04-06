import threading
import subprocess
import socket
import dns.resolver
import concurrent.futures
import time
from tkinter import *
from tkinter import ttk, messagebox
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os

# 全局DNS服务器列表 (共100个常见DNS)
DNS_SERVERS = [
    # 国内DNS
    '114.114.114.114', '114.114.115.115', '223.5.5.5', '223.6.6.6', 
    '119.29.29.29', '182.254.116.116', '101.226.4.6', '218.30.118.6',
    '123.125.81.6', '140.207.198.6', '180.76.76.76', '101.198.192.33',
    '101.198.198.198', '112.124.47.27', '114.215.126.16', '119.147.53.99',
    
    # 国际DNS
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112',
    '208.67.222.222', '208.67.220.220', '64.6.64.6', '64.6.65.6', '84.200.69.80',
    '84.200.70.40', '8.26.56.26', '8.20.247.20', '185.228.168.9', '185.228.169.9',
    '156.154.70.1', '156.154.71.1', '198.101.242.72', '23.253.163.53',
    
    # 其他地区DNS
    '202.14.67.4', '202.14.67.14', '203.80.96.10', '203.80.96.9', '203.112.2.4',
    '203.112.2.5', '202.45.84.58', '202.45.84.59', '202.83.95.227', '202.83.95.229',
    '202.14.67.4', '202.14.67.14', '203.80.96.10', '203.80.96.9', '203.112.2.4',
    '203.112.2.5', '202.45.84.58', '202.45.84.59', '202.83.95.227', '202.83.95.229',
    
    # 教育网DNS
    '202.112.20.131', '202.112.20.132', '202.112.0.44', '202.112.0.46',
    '202.112.0.35', '202.112.0.36', '202.112.0.55', '202.112.0.56',
    
    # 其他知名DNS
    '199.85.126.10', '199.85.127.10', '216.146.35.35', '216.146.36.36',
    '37.235.1.174', '37.235.1.177', '89.233.43.71', '91.239.100.100',
    '74.82.42.42', '109.69.8.51', '156.154.70.1', '156.154.71.1',
    '198.101.242.72', '23.253.163.53', '176.103.130.130', '176.103.130.131',
    '45.32.36.36', '45.32.72.72', '5.2.75.75', '5.2.75.76',
    '193.183.98.66', '194.187.251.67', '195.46.39.39', '195.46.39.40'
]

class DNSDetector:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS服务器检测工具 v1.3.0")
        self.root.geometry("1100x600")
        
        # 初始化AI模型
        self.model = None
        self.load_or_train_model()
        self.history = []  # 初始化历史记录
        
        # 创建GUI组件
        self.create_widgets()
        
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
        # X = np.random.rand(100, 5)  # 5个特征：响应时间、成功率、地理位置、类型、历史记录
        # y = np.random.randint(0, 2, 100)  # 0=不可靠, 1=可靠
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
    
    def create_widgets(self):
        """创建GUI界面"""
        # 顶部控制面板
        control_frame = Frame(self.root, padx=10, pady=10)
        control_frame.pack(fill=X)

        Label(control_frame, text="检测域名:").grid(row=0, column=0, sticky=W)
        self.domain_entry = Entry(control_frame, width=40)
        self.domain_entry.grid(row=0, column=1, padx=5)
        self.domain_entry.insert(0, "www.baidu.com")  # 默认检测域名
        
        Button(control_frame, text="开始检测", command=self.start_detection).grid(row=0, column=2, padx=5)
        Button(control_frame, text="导出结果", command=self.export_results).grid(row=0, column=3, padx=5)

        # 一键测速按钮（第97行后插入）
        Button(control_frame, text="一键测速", command=self.auto_select_fastest).grid(row=0, column=7, padx=5)
        Button(control_frame, text="历史记录", command=self.show_history).grid(row=0, column=8, padx=5)


        # 添加分组选择下拉框（在第97行后插入）
        Label(control_frame, text="DNS分组:").grid(row=1, column=0, sticky=W)
        self.group_var = StringVar()
        self.group_var.set("全部")  # 默认显示全部
        group_options = ["全部", "国内DNS", "国际DNS", "教育网DNS", "其他DNS"]
        OptionMenu(control_frame, self.group_var, *group_options).grid(row=1, column=1, padx=5, sticky=W)

        # 自定义DNS输入（105行后插入）
        Label(control_frame, text="自定义DNS:").grid(row=1, column=2, sticky=W)
        self.custom_dns_entry = Entry(control_frame, width=25)
        self.custom_dns_entry.grid(row=1, column=3, padx=5)
        Button(control_frame, text="+添加", command=self.add_custom_dns).grid(row=1, column=4)



        # 新增的排序按钮（在这下面添加）
        Button(control_frame, text="按响应时间排序", command=lambda: self.sort_results("time")).grid(row=0, column=4, padx=5)
        Button(control_frame, text="按状态排序", command=lambda: self.sort_results("status")).grid(row=0, column=5, padx=5)
        Button(control_frame, text="按可靠性排序", command=lambda: self.sort_results("reliability")).grid(row=0, column=6, padx=5)
        
        # 添加进度条（在第110行前插入）
        self.progress = ttk.Progressbar(self.root, orient=HORIZONTAL, length=200, mode='determinate')
        self.progress.pack(fill=X, padx=10, pady=5)


        # 结果显示区域
        result_frame = Frame(self.root)
        result_frame.pack(fill=BOTH, expand=True, padx=10, pady=(0,10))
        
        # 树状表格显示结果
        self.tree = ttk.Treeview(result_frame, columns=("DNS", "响应时间", "状态", "可靠性预测"), show="headings")
        
        # 设置列宽和标题
        self.tree.column("DNS", width=200, anchor="center")
        self.tree.column("响应时间", width=100, anchor="center")
        self.tree.column("状态", width=100, anchor="center")
        self.tree.column("可靠性预测", width=150, anchor="center")
        
        self.tree.heading("DNS", text="DNS服务器")
        self.tree.heading("响应时间", text="响应时间(ms)")
        self.tree.heading("状态", text="状态")
        self.tree.heading("可靠性预测", text="AI可靠性预测")
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)

        # 统计面板
        stats_frame = Frame(self.root, bd=1, relief=GROOVE)
        stats_frame.pack(fill=X, padx=10, pady=5)

        self.stats_vars = {
            "total": StringVar(value="总数: 0"),
            "success": StringVar(value="成功: 0"), 
            "avg_time": StringVar(value="平均响应: 0ms")
        }

        Label(stats_frame, textvariable=self.stats_vars["total"]).pack(side=LEFT, padx=10)
        Label(stats_frame, textvariable=self.stats_vars["success"]).pack(side=LEFT, padx=10)
        Label(stats_frame, textvariable=self.stats_vars["avg_time"]).pack(side=LEFT, padx=10)


        # 右键菜单（第135行后插入）
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.context_menu = Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="复制IP", command=self.copy_ip)
        self.context_menu.add_command(label="Ping测试", command=self.ping_test)  # 135行后插入


        
        # 底部状态栏
        self.status_var = StringVar()
        self.status_var.set("就绪")
        status_bar = Label(self.root, textvariable=self.status_var, bd=1, relief=SUNKEN, anchor=W)
        status_bar.pack(side=BOTTOM, fill=X)
    
    def start_detection(self):
        """开始检测DNS服务器"""
        # 获取选择的分组（移动到方法开头）
        selected_group = self.group_var.get()
        filtered_dns = DNS_SERVERS
        if selected_group != "全部":
            group_mapping = {
                "国内DNS": DNS_SERVERS[:16],
                "国际DNS": DNS_SERVERS[16:32],
                "教育网DNS": DNS_SERVERS[32:40],
                "其他DNS": DNS_SERVERS[40:]
            }
            filtered_dns = group_mapping.get(selected_group, DNS_SERVERS)
            self.status_var.set(f"正在检测【{selected_group}】分组 ({len(filtered_dns)}个DNS)...")
        else:
            self.status_var.set(f"正在检测全部DNS服务器 ({len(DNS_SERVERS)}个)...")

        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("错误", "请输入要检测的域名")
            return
        
        # 清空之前的结果
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # 更新进度条
        self.progress["maximum"] = len(filtered_dns)
        self.progress["value"] = 0

        self.status_var.set("正在检测DNS服务器...")
        self.root.update()
        
        # 使用多线程检测DNS
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for dns in filtered_dns:
                futures.append(executor.submit(self.check_dns, dns, domain))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    self.update_tree(result)
                    self.progress["value"] += 1  # 每次检测完成进度+1（在第150行后插入）
                    self.root.update()  # 刷新界面

                except Exception as e:
                    print(f"检测出错: {e}")
        
        self.status_var.set(f"检测完成，共检测了{len(filtered_dns)}个DNS服务器")
    
    def check_dns(self, dns_server, domain):
        """检测单个DNS服务器"""
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
            "time": f"{response_time:.2f}" if response_time > 0 else "超时",
            "status": status,
            "reliability": reliability
        }
    
    def update_tree(self, result):
        """更新结果到树状表格"""
        self.tree.insert("", "end", values=(
            result["dns"],
            result["time"],
            result["status"],
            result["reliability"]
        ))
        self.update_stats()

    def sort_results(self, sort_by):
        """根据指定字段排序结果"""
        if not self.tree.get_children():
            return  # 没有数据时不排序
        
        # 获取所有数据
        items = [(self.tree.item(item, "values"), item) for item in self.tree.get_children()]
        
        # 定义排序键函数
        def get_key(item):
            values = item[0]
            if sort_by == "time":
                try:
                    return float(values[1]) if values[1] != "超时" else float('inf')
                except:
                    return float('inf')
            elif sort_by == "status":
                return values[2]  # 状态
            elif sort_by == "reliability":
                return values[3]  # 可靠性
            return 0
        
        # 排序数据
        items.sort(key=get_key)
        
        # 重新插入排序后的数据
        for index, (values, item) in enumerate(items):
            self.tree.move(item, "", index)


    def export_results(self):
        """导出检测结果到CSV文件"""
        try:
            data = []
            for item in self.tree.get_children():
                values = self.tree.item(item, "values")
                data.append({
                    "DNS服务器": values[0],
                    "响应时间(ms)": values[1],
                    "状态": values[2],
                    "AI可靠性预测": values[3]
                })
            
            if not data:
                messagebox.showwarning("警告", "没有可导出的数据")
                return
            
            df = pd.DataFrame(data)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"dns_results_{timestamp}.csv"
            df.to_csv(filename, index=False, encoding="utf_8_sig")
            
            messagebox.showinfo("成功", f"结果已导出到 {filename}")
            # 保存历史记录（第220行后插入）
            self.history.append({
                "time": timestamp,
                "domain": self.domain_entry.get(),
                "count": len(data)
            })

        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")

    def auto_select_fastest(self):
        """自动选择响应最快的3个DNS服务器"""
        if not self.tree.get_children():
            messagebox.showwarning("提示", "请先执行检测")
            return
        
        items = [(float(self.tree.item(item, "values")[1]), item) 
                for item in self.tree.get_children() 
                if self.tree.item(item, "values")[1] != "超时"]
        items.sort(key=lambda x: x[0])
        
        for i, (_, item) in enumerate(items[:3]):
            self.tree.item(item, tags=("fastest",))
            self.tree.tag_configure("fastest", background="lightgreen")
        
        messagebox.showinfo("完成", f"已标记响应最快的3个DNS服务器")

    def show_history(self):
        """显示历史记录窗口"""
        history_window = Toplevel(self.root)
        history_window.title("检测历史记录")
        
        text = Text(history_window, wrap=WORD)
        text.pack(fill=BOTH, expand=True)
        
        for record in self.history:
            text.insert(END, f"时间: {record['time']}\n域名: {record['domain']}\n检测数量: {record['count']}\n\n")
        
        Button(history_window, text="关闭", command=history_window.destroy).pack(pady=5)

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.context_menu.post(event.x_root, event.y_root)

    def copy_ip(self):
        selected = self.tree.selection()
        if selected:
            ip = self.tree.item(selected[0], "values")[0]
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)
            self.status_var.set(f"已复制: {ip}")

    def update_stats(self):
        """更新统计信息"""
        items = [self.tree.item(item, "values") for item in self.tree.get_children()]
        success_count = sum(1 for item in items if item[2] == "成功")
        avg_time = np.mean([float(item[1]) for item in items if item[1] != "超时"])
        
        self.stats_vars["total"].set(f"总数: {len(items)}")
        self.stats_vars["success"].set(f"成功: {success_count}")
        self.stats_vars["avg_time"].set(f"平均响应: {avg_time:.2f}ms")

    def add_custom_dns(self):
        """添加自定义DNS到检测列表"""
        custom_dns = self.custom_dns_entry.get().strip()
        if custom_dns and custom_dns not in DNS_SERVERS:
            DNS_SERVERS.append(custom_dns)
            self.custom_dns_entry.delete(0, END)
            messagebox.showinfo("成功", f"已添加DNS: {custom_dns}")

    def ping_test(self):
        """对选中的DNS执行带进度显示的Ping测试"""
        selected = self.tree.selection()
        if not selected:
            return
        
        ip = self.tree.item(selected[0], "values")[0]
        
        # 创建Ping测试窗口
        ping_window = Toplevel(self.root)
        ping_window.title(f"Ping测试 - {ip}")
        ping_window.geometry("400x300")
        
        # 结果显示区域
        result_text = Text(ping_window, wrap=WORD)
        result_text.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # 进度条
        progress = ttk.Progressbar(ping_window, orient=HORIZONTAL, length=300, mode='determinate')
        progress.pack(pady=5)
        progress["maximum"] = 4  # 4次ping测试
        
        # 状态标签
        status_var = StringVar(value="准备Ping测试...")
        Label(ping_window, textvariable=status_var).pack()
        
        # 执行Ping测试
        def do_ping():
            try:
                result_text.delete(1.0, END)
                process = subprocess.Popen(
                    ["ping", "-n", "4", ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='gbk'  # Windows系统使用gbk编码
                )
                
                count = 0
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        result_text.insert(END, output)
                        result_text.see(END)
                        if "字节=32" in output:  # 检测到有效响应
                            count += 1
                            progress["value"] = count
                            status_var.set(f"已完成 {count}/4 次测试")
                        ping_window.update()
                
                if process.returncode == 0:
                    status_var.set("Ping测试完成！")
                else:
                    status_var.set("Ping测试失败")
                    
            except Exception as e:
                result_text.insert(END, f"错误: {str(e)}")
                status_var.set("Ping测试异常")
        
        # 在新线程中执行Ping
        threading.Thread(target=do_ping, daemon=True).start()



if __name__ == "__main__":
    root = Tk()
    app = DNSDetector(root)
    root.mainloop()
