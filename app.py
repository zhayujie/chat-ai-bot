# encoding:utf-8

import os
import signal
import sys
import time
import subprocess

from channel import channel_factory
from common import const
from config import load_config
from plugins import *
import threading
from CoW_web import Home

def sigterm_handler_wrap(_signo):
    old_handler = signal.getsignal(_signo)

    def func(_signo, _stack_frame):
        logger.info("signal {} received, exiting...".format(_signo))
        conf().save_user_datas()
        if callable(old_handler):  #  check old_handler
            return old_handler(_signo, _stack_frame)
        sys.exit(0)

    signal.signal(_signo, func)


def start_channel(channel_name: str):
    channel = channel_factory.create_channel(channel_name)
    if channel_name in ["wx", "wxy", "terminal", "wechatmp","web", "wechatmp_service", "wechatcom_app", "wework",
                        const.FEISHU, const.DINGTALK]:
        PluginManager().load_plugins()

    if conf().get("use_linkai"):
        try:
            from common import linkai_client
            threading.Thread(target=linkai_client.start, args=(channel,)).start()
        except Exception as e:
            pass
    channel.startup()


def run():
    try:
        # load config
        load_config()
        # ctrl + c
        sigterm_handler_wrap(signal.SIGINT)
        # kill signal
        sigterm_handler_wrap(signal.SIGTERM)

        # create channel
        channel_name = conf().get("channel_type", "wx")

        if "--cmd" in sys.argv:
            channel_name = "terminal"

        if channel_name == "wxy":
            os.environ["WECHATY_LOG"] = "warn"

        start_channel(channel_name)

        while True:
            time.sleep(1)
    except Exception as e:
        logger.error("App startup failed!")
        logger.exception(e)


def start_web_interface():
    """启动Web界面"""
    try:
        # 获取当前脚本所在的目录
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # 使用subprocess启动streamlit,并设置PYTHONPATH
        process = subprocess.Popen(
            ["streamlit", "run", "CoW_web/Home.py"],
            # 直接显示输出到控制台
            stdout=None,
            stderr=None,
            env={
                **os.environ,
                "PYTHONPATH": current_dir  # 添加当前目录到PYTHONPATH
            },
            cwd=current_dir  # 设置工作目录为当前目录
        )
        return process
    except Exception as e:
        logger.error(f"Failed to start web interface: {e}")
        return None


if __name__ == "__main__":
    # 启动web界面
    web_process = start_web_interface()
    
    # 运行后端服务
    try:
        run()
    finally:
        # 确保在主程序退出时关闭web界面
        if web_process:
            web_process.terminate()
