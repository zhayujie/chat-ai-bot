from wechatpy.enterprise import WeChatClient

from bridge.context import ContextType
from channel.chat_message import ChatMessage
from common.log import logger
from common.tmp_dir import TmpDir


class WechatComAppMessage(ChatMessage):
    def __init__(self, msg, client: WeChatClient, is_group=False, kf_msg=None):
        super().__init__(msg)
        self.is_group = is_group
        self.client = client
        self.create_time = msg.time

        if kf_msg:
            self.msg_id = kf_msg['msgid']
            self.msgtype = kf_msg['msgtype']
            self.from_user_id = kf_msg['external_userid']
            self.to_user_id = kf_msg['open_kfid']
        else:
            self.msg_id = msg.id
            self.msgtype = msg.type
            self.from_user_id = msg.source
            self.to_user_id = msg.target
            self.other_user_id = msg.source

        if self.msgtype == "text":
            self.ctype = ContextType.TEXT
            self.content = kf_msg['text']['content'] if kf_msg else msg.content
        elif self.msgtype == "voice":
            self.ctype = ContextType.VOICE
            logger.debug(f"[wechatcom] voice message: {msg}")
            self.media_id = kf_msg['voice']['media_id'] if kf_msg else msg.media_id
            media_format = ".mp3" if kf_msg else msg.format

            self.content = TmpDir().path() +  self.media_id + media_format  # content直接存临时目录路径
            self._prepare_fn = self.download_media
        elif msg.type == "image":
            self.ctype = ContextType.IMAGE
            logger.debug(f"[wechatcom] image message: {msg}")
            self.media_id = kf_msg['image']['media_id'] if kf_msg else msg.media_id
            media_format = ".jpg" if kf_msg else ".png"

            self.content = TmpDir().path() +  self.media_id + media_format  # content直接存临时目录路径
            self._prepare_fn = self.download_media
        else:
            raise NotImplementedError("Unsupported message type: Type:{} ".format(msg.type))

    def download_media(self):
        # 如果响应状态码是200，则将响应内容写入本地文件
        response = self.client.media.download(self.media_id)
        if response.status_code == 200:
            with open(self.content, "wb") as f:
                f.write(response.content)
        else:
            logger.info(f"[wechatcom] Failed to download voice file, {response.content}")