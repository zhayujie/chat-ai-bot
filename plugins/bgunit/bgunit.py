# encoding:utf-8
import json
import os
import uuid
from uuid import getnode as get_mac

import requests

import plugins
from bridge.context import ContextType
from bridge.reply import Reply, ReplyType
from common.log import logger
from plugins import *

"""利用百度UNIT实现智能对话
    如果命中意图，返回意图对应的回复，否则返回继续交付给下个插件处理
    品高专用
"""


@plugins.register(
    name="BGunit",
    desire_priority=0,
    hidden=True,
    desc="Baidu unit bot system",
    version="0.1",
    author="jackson",
)
class BGunit(Plugin):
    def __init__(self):
        super().__init__()
        try:
            conf = super().load_config()
            if not conf:
                raise Exception("config.json not found")
            self.service_id = conf["service_id"]
            self.api_key = conf["api_key"]
            self.secret_key = conf["secret_key"]
            self.access_token = self.get_token()
            self.handlers[Event.ON_HANDLE_CONTEXT] = self.on_handle_context
            logger.info("[BGunit] inited")
        except Exception as e:
            logger.warn("[BGunit] init failed, ignore ")
            raise e

    def on_handle_context(self, e_context: EventContext):
        if e_context["context"].type != ContextType.TEXT:
            return

        content = e_context["context"].content
        logger.debug("[BGunit] on_handle_context. content: %s" % content)
        parsed = self.getUnit2(content)
        intent = self.getIntent(parsed)
        if intent:  # 找到意图
            logger.debug("[BGunit] Baidu_AI Intent= %s", intent)
            reply = Reply()
            reply.type = ReplyType.TEXT
            slotstring=''
            slots=self.getSlots(parsed, intent)
            if slots.__len__()>0:
                slotstring=slots[0]['normalized_word']
            reply.content = self.getSay(parsed)+":"+intent+ "-" + slotstring
            e_context["reply"] = reply
            e_context.action = EventAction.BREAK_PASS  # 事件结束，并跳过处理context的默认逻辑
        else:
            e_context.action = EventAction.CONTINUE  # 事件继续，交付给下个插件或默认逻辑

    def get_help_text(self, **kwargs):
        help_text = "本插件返回对话中意图和词槽，这些技能由您的百度智能对话UNIT决定\n"
        return help_text

    def get_token(self):
        """获取访问百度UUNIT 的access_token
        #param api_key: UNIT apk_key
        #param secret_key: UNIT secret_key
        Returns:
            string: access_token
        """
        url = "https://aip.baidubce.com/oauth/2.0/token?client_id={}&client_secret={}&grant_type=client_credentials".format(self.api_key, self.secret_key)
        payload = ""
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        response = requests.request("POST", url, headers=headers, data=payload)

        # print(response.text)
        return response.json()["access_token"]

    def getUnit(self, query):
        """
        NLU 解析version 3.0
        :param query: 用户的指令字符串
        :returns: UNIT 解析结果。如果解析失败，返回 None
        """

        url = "https://aip.baidubce.com/rpc/2.0/unit/service/v3/chat?access_token=" + self.access_token
        request = {
            "query": query,
            "user_id": str(get_mac())[:32],
            "terminal_id": "88888",
        }
        body = {
            "log_id": str(uuid.uuid1()),
            "version": "3.0",
            "service_id": self.service_id,
            "session_id": str(uuid.uuid1()),
            "request": request,
        }
        try:
            headers = {"Content-Type": "application/json"}
            response = requests.post(url, json=body, headers=headers)
            return json.loads(response.text)
        except Exception:
            return None

    def getUnit2(self, query):
        """
        NLU 解析 version 2.0

        :param query: 用户的指令字符串
        :returns: UNIT 解析结果。如果解析失败，返回 None
        """
        url = "https://aip.baidubce.com/rpc/2.0/unit/service/chat?access_token=" + self.access_token
        request = {"query": query, "user_id": str(get_mac())[:32]}
        body = {
            "log_id": str(uuid.uuid1()),
            "version": "2.0",
            "service_id": self.service_id,
            "session_id": str(uuid.uuid1()),
            "request": request,
        }
        try:
            headers = {"Content-Type": "application/json"}
            response = requests.post(url, json=body, headers=headers)
            return json.loads(response.text)
        except Exception:
            return None

    def getIntent(self, parsed):
        """
        提取意图

        :param parsed: UNIT 解析结果
        :returns: 意图数组
        """
        if parsed and "result" in parsed and "response_list" in parsed["result"]:
            try:
                return parsed["result"]["response_list"][0]["schema"]["intent"]
            except Exception as e:
                logger.warning(e)
                return ""
        else:
            return ""

    def hasIntent(self, parsed, intent):
        """
        判断是否包含某个意图

        :param parsed: UNIT 解析结果
        :param intent: 意图的名称
        :returns: True: 包含; False: 不包含
        """
        if parsed and "result" in parsed and "response_list" in parsed["result"]:
            response_list = parsed["result"]["response_list"]
            for response in response_list:
                if "schema" in response and "intent" in response["schema"] and response["schema"]["intent"] == intent:
                    return True
            return False
        else:
            return False

    def getSlots(self, parsed, intent=""):
        """
            提取某个意图的所有词槽

            :param parsed: UNIT 解析结果
            :param intent: 意图的名称
            :returns: 词槽列表。你可以通过 name 属性筛选词槽，
        再通过 normalized_word 属性取出相应的值
        """
        if parsed and "result" in parsed and "response_list" in parsed["result"]:
            response_list = parsed["result"]["response_list"]
            if intent == "":
                try:
                    return parsed["result"]["response_list"][0]["schema"]["slots"]
                except Exception as e:
                    logger.warning(e)
                    return []
            for response in response_list:
                if "schema" in response and "intent" in response["schema"] and "slots" in response["schema"] and response["schema"]["intent"] == intent:
                    return response["schema"]["slots"]
            return []
        else:
            return []

    def getSlotWords(self, parsed, intent, name):
        """
        找出命中某个词槽的内容

        :param parsed: UNIT 解析结果
        :param intent: 意图的名称
        :param name: 词槽名
        :returns: 命中该词槽的值的列表。
        """
        slots = self.getSlots(parsed, intent)
        words = []
        for slot in slots:
            if slot["name"] == name:
                words.append(slot["normalized_word"])
        return words

    def getSayByConfidence(self, parsed):
        """
        提取 UNIT 置信度最高的回复文本

        :param parsed: UNIT 解析结果
        :returns: UNIT 的回复文本
        """
        if parsed and "result" in parsed and "response_list" in parsed["result"]:
            response_list = parsed["result"]["response_list"]
            answer = {}
            for response in response_list:
                if (
                    "schema" in response
                    and "intent_confidence" in response["schema"]
                    and (not answer or response["schema"]["intent_confidence"] > answer["schema"]["intent_confidence"])
                ):
                    answer = response
            return answer["action_list"][0]["say"]
        else:
            return ""

    def getSay(self, parsed, intent=""):
        """
        提取 UNIT 的回复文本

        :param parsed: UNIT 解析结果
        :param intent: 意图的名称
        :returns: UNIT 的回复文本
        """
        if parsed and "result" in parsed and "response_list" in parsed["result"]:
            response_list = parsed["result"]["response_list"]
            if intent == "":
                try:
                    return response_list[0]["action_list"][0]["say"]
                except Exception as e:
                    logger.warning(e)
                    return ""
            for response in response_list:
                if "schema" in response and "intent" in response["schema"] and response["schema"]["intent"] == intent:
                    try:
                        return response["action_list"][0]["say"]
                    except Exception as e:
                        logger.warning(e)
                        return ""
            return ""
        else:
            return ""
