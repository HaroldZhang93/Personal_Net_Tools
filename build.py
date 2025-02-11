import PyInstaller.__main__
import sys
import os

# 确保在正确的目录下
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

# 打包参数
params = [
    'main.py',  # 主程序文件
    '--name=NetworkConfigManager',  # 生成的exe名称
    '--noconsole',  # 不显示控制台窗口
    '--onefile',  # 打包成单个文件
    '--clean',  # 清理临时文件
    '--add-data=network_configs.json;.',  # 添加配置文件（如果存在）
    # '--icon=icon.ico',  # 如果有图标文件，取消注释这行
    '--uac-admin',  # 请求管理员权限
    '--hidden-import=psutil',
    '--hidden-import=netifaces',
]

# 执行打包命令
PyInstaller.__main__.run(params) 