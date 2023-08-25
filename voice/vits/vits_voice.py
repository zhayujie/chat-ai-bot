"""
VITS是一个可以通过输入语音数据集训练以克隆声线的AI文本转语音模型，
加入对VITS的支持能够以用户自己喜欢的角色的声线来说话，增添趣味性。
需要自行搭建vits-simple-api服务器：https://github.com/Artrajz/vits-simple-api
"""
import json
import os
import time

import requests

from bridge.reply import Reply, ReplyType
from common.log import logger
from common.tmp_dir import TmpDir
from voice.voice import Voice

"""
server_url : 服务器url，如http://127.0.0.1:23456
api_key : 若服务器配置了API Key，在此填入
speaker_id : 说话人ID，由所使用的模型决定
format : 默认音频格式 可选wav,ogg,silk
lang : 语言，支持auto、zh、ja,ko,en  
length : 调节语音长度，相当于调节语速，该数值越大语速越慢。
noise : 噪声
noisew : 噪声偏差
max : 分段阈值，按标点符号分段，加起来大于max时为一段文本。max<=0表示不分段。
timeout: 响应超时时间，根据vits-simple-api服务器性能不同配置合理的超时时间。    
"""


class VITSVoice(Voice):
    def __init__(self):
        try:
            curdir = os.path.dirname(__file__)
            config_path = os.path.join(curdir, "config.json")
            vconf = None
            if not os.path.exists(config_path):  # 如果没有配置文件，创建本地配置文件
                vconf = { "server_url": "https://api.artrajz.cn/py", "api_key": "api_key",
                        "speaker_id": 0, "format": "wav", "lang": "auto", "length": 1.0, "noise": 0.667,
                        "noisew": 0.8, "max": 50, "timeout": 60}
                with open(config_path, "w") as fw:
                    json.dump(vconf, fw, indent=4)
            else:
                with open(config_path, "r") as fr:
                    vconf = json.load(fr)

            self.server_url = vconf["server_url"]
            self.api_key = vconf["api_key"]
            self.speaker_id = vconf["speaker_id"]
            self.format = vconf["format"]
            self.lang = vconf["lang"]
            self.length = vconf["length"]
            self.noise = vconf["noise"]
            self.noisew = vconf["noisew"]
            self.max = vconf["max"]
            self.timeout = vconf["timeout"]
        except Exception as e:
            logger.warn("VITSVoice init failed: %s, ignore " % e)

    def textToVoice(self, text):
        try:
            data = {
                "text": text,
                "id": self.speaker_id,
                "format": self.format,
                "lang": self.lang,
                "length": self.length,
                "noise": self.noise,
                "noisew": self.noisew,
                "max": self.max
            }
            headers = {"X-API-KEY": self.api_key}
            url = f"{self.server_url}/voice"
            result = requests.post(url=url, data=data, headers=headers, timeout=self.timeout)
            result.raise_for_status()
            # Avoid the same filename under multithreading
            fileName = TmpDir().path() + "reply-" + str(int(time.time())) + "-" + str(hash(text) & 0x7FFFFFFF) + "." + self.format
            with open(fileName, "wb") as f:
                f.write(result.content)
            logger.info("[VITS] textToVoice text={} voice file name={}".format(text, fileName))
            reply = Reply(ReplyType.VOICE, fileName)
        except Exception as err:
            logger.error("[VITS] textToVoice error={}".format(err.__str__()))
            reply = Reply(ReplyType.ERROR, "抱歉，语音合成失败")
        finally:
            return reply
