from bot.bot import Bot
from bridge.context import ContextType, Context
from bridge.reply import Reply, ReplyType
from common.log import logger
from config import conf
from cozepy import Coze, TokenAuth
from typing import Optional, List
import logging


class CozeBot(Bot):
    def __init__(self):
        # 调用父类的初始化方法
        super().__init__()
        # 从配置文件获取 token 和 bot_id
        self.token = conf().get("coze_token")
        self.bot_id = conf().get("coze_bot_id")
        # 存储用户ID和会话ID的映射关系
        self.user_conversation_map = {}

        # 初始化 Coze 客户端
        self.coze = Coze(
            auth=TokenAuth(token=self.token),
            base_url="https://api.coze.cn"
        )

    def create_conversation(self, user_id: str = None) -> Optional[str]:
        """创建新会话
        :param user_id: 用户ID
        :return: 会话ID，如果创建失败则返回None
        """
        try:
            conversation = self.coze.conversations.create()
            conversation_id = conversation.id
            # 如果提供了user_id，建立映射关系
            if user_id:
                self.user_conversation_map[user_id] = conversation_id             
            return conversation_id
        except Exception as e:
            logger.error(f"创建会话失败: {str(e)}")
            return None

    def reply(self, query, context: Context = None) -> Reply:
        """发送消息并获取回复
        :param query: 查询内容
        :param context: 上下文
        :return: 回复对象
        """
        # 检查上下文类型是否为文本，如果不是，则记录警告并返回空文本回复。
        if context.type != ContextType.TEXT:
            logger.warn(f"[coze] Unsupported message type, type={context.type}")
            return Reply(ReplyType.TEXT, None)
        
        # 从context中获取user_id
        user_id = context["receiver"]
        
        # 获取或创建会话ID
        conversation_id = None
        if user_id and user_id in self.user_conversation_map:
            conversation_id = self.user_conversation_map[user_id]

        if not conversation_id:
            conversation_id = self.create_conversation(user_id)
            
        if conversation_id is None:
            logger.error("创建会话失败")
            return Reply(ReplyType.TEXT, None)
        
        try:
            # 创建用户消息
            message = self.coze.conversations.messages.create(
                conversation_id=conversation_id,
                content=query,
                role="user",
                content_type="text"
            )

            # 获取机器人回复
            chat = self.coze.chat.create_and_poll(
                conversation_id=message.conversation_id,
                bot_id=self.bot_id,
                user_id=context["receiver"],
                additional_messages=[message],
                auto_save_history=True
            )
            for msg in chat.messages:
                if msg.type.value == 'answer':
                    reply = msg.content
                    break
            if not reply:
                logger.error("回复内容为空")
                return Reply(ReplyType.TEXT, None)
                
            # 发送回复消息
            return Reply(ReplyType.TEXT, reply)
            
        except Exception as e:
            logger.error(f"发送回复消息时出错: {str(e)}")
            return Reply(ReplyType.TEXT, None)
        


