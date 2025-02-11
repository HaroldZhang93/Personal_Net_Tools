import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import subprocess
import socket
import netifaces
import psutil
import sys

class NetworkConfig:
    def __init__(self, name, interface, ip, subnet, gateway, dns):
        self.name = name
        self.interface = interface
        self.ip = ip
        self.subnet = subnet
        self.gateway = gateway
        self.dns = dns

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("网络配置管理器")
        self.geometry("800x600")
        
        # 创建主框架
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # 创建左侧配置列表框架
        self.left_frame = ttk.LabelFrame(self.main_frame, text="已保存的配置")
        self.left_frame.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.Y)
        
        # 配置列表
        self.config_listbox = tk.Listbox(self.left_frame, width=30)
        self.config_listbox.pack(padx=5, pady=5, fill=tk.Y)
        self.config_listbox.bind('<<ListboxSelect>>', self.load_selected_config)
        
        # 创建右侧配置编辑框架
        self.right_frame = ttk.LabelFrame(self.main_frame, text="网络配置")
        self.right_frame.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.BOTH, expand=True)
        
        # 网卡选择
        ttk.Label(self.right_frame, text="网卡:").grid(row=0, column=0, padx=5, pady=5)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(self.right_frame, textvariable=self.interface_var, width=50)
        self.interface_combo['values'] = self.get_network_interfaces()
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        
        # 添加网卡信息显示
        self.interface_info = ttk.Label(self.right_frame, text="", wraplength=400)
        self.interface_info.grid(row=0, column=2, padx=5, pady=5, sticky='w')
        
        # 绑定网卡选择事件
        self.interface_combo.bind('<<ComboboxSelected>>', self.on_interface_selected)
        
        # IP地址
        ttk.Label(self.right_frame, text="IP地址:").grid(row=1, column=0, padx=5, pady=5)
        self.ip_var = tk.StringVar()
        self.ip_entry = ttk.Entry(self.right_frame, textvariable=self.ip_var)
        self.ip_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # 子网掩码
        ttk.Label(self.right_frame, text="子网掩码:").grid(row=2, column=0, padx=5, pady=5)
        self.subnet_var = tk.StringVar()
        self.subnet_entry = ttk.Entry(self.right_frame, textvariable=self.subnet_var)
        self.subnet_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # 网关
        ttk.Label(self.right_frame, text="网关:").grid(row=3, column=0, padx=5, pady=5)
        self.gateway_var = tk.StringVar()
        self.gateway_entry = ttk.Entry(self.right_frame, textvariable=self.gateway_var)
        self.gateway_entry.grid(row=3, column=1, padx=5, pady=5)
        
        # DNS
        ttk.Label(self.right_frame, text="DNS:").grid(row=4, column=0, padx=5, pady=5)
        self.dns_var = tk.StringVar()
        self.dns_entry = ttk.Entry(self.right_frame, textvariable=self.dns_var)
        self.dns_entry.grid(row=4, column=1, padx=5, pady=5)
        
        # 配置名称
        ttk.Label(self.right_frame, text="配置名称:").grid(row=5, column=0, padx=5, pady=5)
        self.config_name_var = tk.StringVar()
        self.config_name_entry = ttk.Entry(self.right_frame, textvariable=self.config_name_var)
        self.config_name_entry.grid(row=5, column=1, padx=5, pady=5)
        
        # 按钮框架
        self.button_frame = ttk.Frame(self.right_frame)
        self.button_frame.grid(row=6, column=0, columnspan=2, pady=20)
        
        # 按钮
        ttk.Button(self.button_frame, text="应用配置", command=self.apply_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.button_frame, text="保存配置", command=self.save_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.button_frame, text="删除配置", command=self.delete_config).pack(side=tk.LEFT, padx=5)
        
        # 加载已保存的配置
        self.load_saved_configs()
    
    def get_network_interfaces(self):
        """获取系统网络接口列表，包含更详细的信息"""
        interfaces = []
        
        # 获取所有网络接口
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        
        for interface_name, addrs in net_if_addrs.items():
            # 跳过回环接口
            if interface_name.startswith('lo') or interface_name.startswith('Loop'):
                continue
                
            # 获取接口状态
            if interface_name in net_if_stats:
                stats = net_if_stats[interface_name]
                if not stats.isup:
                    continue  # 跳过未启用的接口
            
            # 获取IPv4地址信息
            ipv4_info = ""
            mac_address = ""
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    ipv4_info = f"({addr.address})"
                elif addr.family == psutil.AF_LINK:  # MAC地址
                    mac_address = f"[{addr.address}]"
            
            # 组合显示信息，使用特殊分隔符
            display_name = f"{interface_name}|||{mac_address}|||{ipv4_info}"
            interfaces.append((interface_name, display_name))
        
        # 返回排序后的接口列表
        return [item[1] for item in sorted(interfaces, key=lambda x: x[0])]
    
    def on_interface_selected(self, event):
        """当选择网卡时更新显示详细信息"""
        selected = self.interface_combo.get()
        interface_name = selected.split('|||')[0]  # 使用特殊分隔符获取接口名称
        
        try:
            # 获取接口详细信息
            addrs = psutil.net_if_addrs()[interface_name]
            stats = psutil.net_if_stats()[interface_name]
            
            info = []
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    info.append(f"IPv4: {addr.address}")
                    info.append(f"子网掩码: {addr.netmask}")
                elif addr.family == socket.AF_INET6:
                    info.append(f"IPv6: {addr.address}")
                elif addr.family == psutil.AF_LINK:
                    info.append(f"MAC: {addr.address}")
            
            info.append(f"速度: {stats.speed}Mb/s" if stats.speed > 0 else "速度: 未知")
            info.append(f"状态: {'启用' if stats.isup else '禁用'}")
            
            # 更新信息显示
            self.interface_info.config(text="\n".join(info))
            
            # 自动填充当前IP地址和子网掩码
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    self.ip_var.set(addr.address)
                    self.subnet_var.set(addr.netmask)
                    break
            
        except Exception as e:
            self.interface_info.config(text=f"获取接口信息失败: {str(e)}")
    
    def get_config_path(self):
        """获取配置文件路径"""
        if getattr(sys, 'frozen', False):
            # 如果是打包后的exe
            application_path = os.path.dirname(sys.executable)
        else:
            # 如果是直接运行的py文件
            application_path = os.path.dirname(os.path.abspath(__file__))
        
        return os.path.join(application_path, 'network_configs.json')
    
    def load_saved_configs(self):
        """加载保存的配置文件"""
        try:
            config_path = self.get_config_path()
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    configs = json.load(f)
                    for config in configs:
                        self.config_listbox.insert(tk.END, config['name'])
        except Exception as e:
            messagebox.showerror("错误", f"加载配置文件失败: {str(e)}")
    
    def save_config(self):
        """保存当前配置"""
        name = self.config_name_var.get()
        if not name:
            messagebox.showerror("错误", "请输入配置名称")
            return
            
        config = {
            'name': name,
            'interface': self.interface_var.get().split('|||')[0],
            'ip': self.ip_var.get(),
            'subnet': self.subnet_var.get(),
            'gateway': self.gateway_var.get(),
            'dns': self.dns_var.get()
        }
        
        configs = []
        config_path = self.get_config_path()
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                configs = json.load(f)
        
        # 检查是否存在同名配置
        for i, existing_config in enumerate(configs):
            if existing_config['name'] == name:
                configs[i] = config
                break
        else:
            configs.append(config)
        
        with open(config_path, 'w') as f:
            json.dump(configs, f, indent=4)
        
        self.config_listbox.delete(0, tk.END)
        for config in configs:
            self.config_listbox.insert(tk.END, config['name'])
        
        messagebox.showinfo("成功", "配置已保存")
    
    def load_selected_config(self, event):
        """加载选中的配置"""
        selection = self.config_listbox.curselection()
        if not selection:
            return
            
        config_path = self.get_config_path()
        with open(config_path, 'r') as f:
            configs = json.load(f)
            
        selected_config = configs[selection[0]]
        self.config_name_var.set(selected_config['name'])
        self.interface_var.set(selected_config['interface'])
        self.ip_var.set(selected_config['ip'])
        self.subnet_var.set(selected_config['subnet'])
        self.gateway_var.set(selected_config['gateway'])
        self.dns_var.set(selected_config['dns'])
    
    def delete_config(self):
        """删除选中的配置"""
        selection = self.config_listbox.curselection()
        if not selection:
            messagebox.showwarning("警告", "请先选择要删除的配置")
            return
            
        if messagebox.askyesno("确认", "确定要删除选中的配置吗？"):
            config_path = self.get_config_path()
            with open(config_path, 'r') as f:
                configs = json.load(f)
            
            del configs[selection[0]]
            
            with open(config_path, 'w') as f:
                json.dump(configs, f, indent=4)
            
            self.config_listbox.delete(selection)
    
    def apply_config(self):
        """应用网络配置"""
        try:
            selected_interface = self.interface_var.get()
            # 使用特殊分隔符获取接口名称
            interface = selected_interface.split('|||')[0]
            
            # 获取Windows中实际的网卡显示名称
            try:
                # 使用完整的网卡名称，不需要再次查找
                if not interface:
                    messagebox.showerror("错误", "请选择网卡")
                    return
                    
            except Exception as e:
                messagebox.showerror("错误", f"获取网卡信息失败: {str(e)}")
                return
            
            ip = self.ip_var.get()
            subnet = self.subnet_var.get()
            gateway = self.gateway_var.get()
            dns = self.dns_var.get()
            
            # 验证输入
            if not all([interface, ip, subnet, gateway, dns]):
                messagebox.showerror("错误", "请填写所有网络配置信息")
                return
            
            # Windows系统下的网络配置命令
            if os.name == 'nt':
                try:
                    # 设置IP地址和子网掩码
                    ip_cmd = f'netsh interface ip set address name="{interface}" source=static addr={ip} mask={subnet} gateway={gateway}'
                    subprocess.run(ip_cmd, shell=True, check=True)
                    
                    # 设置DNS
                    dns_cmd = f'netsh interface ip set dns name="{interface}" source=static addr={dns}'
                    subprocess.run(dns_cmd, shell=True, check=True)
                    
                    messagebox.showinfo("成功", "网络配置已应用")
                    
                except subprocess.CalledProcessError as e:
                    if e.returncode == 5:
                        messagebox.showerror("错误", "访问被拒绝。请以管理员身份运行程序！")
                    else:
                        messagebox.showerror("错误", f"应用配置失败: {str(e)}\n请检查网络参数是否正确。")
                    return
            
            # Linux系统下的网络配置命令
            else:
                try:
                    # 需要root权限
                    commands = [
                        f'ip addr flush dev {interface}',  # 清除现有配置
                        f'ip addr add {ip}/{subnet} dev {interface}',
                        f'ip route add default via {gateway}',
                    ]
                    
                    for cmd in commands:
                        subprocess.run(['sudo'] + cmd.split(), check=True)
                    
                    # 设置DNS
                    with open('/etc/resolv.conf', 'w') as f:
                        f.write(f'nameserver {dns}\n')
                    
                    messagebox.showinfo("成功", "网络配置已应用")
                    
                except subprocess.CalledProcessError as e:
                    messagebox.showerror("错误", f"应用配置失败: {str(e)}\n请确保有足够的权限。")
                    return
                except Exception as e:
                    messagebox.showerror("错误", f"应用配置失败: {str(e)}")
                    return
            
        except Exception as e:
            messagebox.showerror("错误", f"应用配置失败: {str(e)}")

if __name__ == "__main__":
    app = Application()
    app.mainloop() 