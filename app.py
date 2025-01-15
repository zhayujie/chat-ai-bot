# encoding:utf-8

import os
import signal
import sys
import time

from channel import channel_factory
from common import const
from config import load_config
from plugins import *
import threading


def sigterm_handler_wrap(_signo):
    old_handler = signal.getsignal(_signo)

    def func(_signo, _stack_frame):
        logger.info("signal {} received, exiting...".format(_signo))
        conf().save_user_datas()
        if callable(old_handler):  #  check old_handler
            return old_handler(_signo, _stack_frame)
        stop_event.set()
        sys.exit(0)

    signal.signal(_signo, func)


def start_channel(channel_name: str):
    channel = channel_factory.create_channel(channel_name)

    if conf().get("use_linkai"):
        try:
            from common import linkai_client
            threading.Thread(target=linkai_client.start, args=(channel,)).start()
        except Exception as e:
            pass
    channel.startup()


stop_event = threading.Event()
def run():
    try:
        # load config
        load_config()
        # ctrl + c
        sigterm_handler_wrap(signal.SIGINT)
        # kill signal
        sigterm_handler_wrap(signal.SIGTERM)

        PluginManager().load_plugins()
        
        channel_name = "terminal" if "--cmd" in sys.argv else conf().get("channel_type", "wx")
        channel_names = conf().get("channel_types", [])
        if channel_name not in channel_names:
            channel_names.append(channel_name)
        channel_names=list(set(channel_names))

        for name in channel_names:
            if name == "wxy":
                os.environ["WECHATY_LOG"] = "warn"
            threading.Thread(target=start_channel, args=(name,)).start()
      
        stop_event.wait()
    except Exception as e:
        logger.error("App startup failed!")
        logger.exception(e)


if __name__ == "__main__":
    run()
