"""
Optimized Google Gemini Bot
"""
# encoding:utf-8

import time
from bot.bot import Bot
import google.generativeai as genai
from bot.session_manager import SessionManager
from bridge.context import ContextType, Context
from bridge.reply import Reply, ReplyType
from common.log import logger
from config import conf
from bot.chatgpt.chat_gpt_session import ChatGPTSession
from google.generativeai.types import HarmCategory, HarmBlockThreshold


class GoogleGeminiBot(Bot):
    def __init__(self):
        super().__init__()
        self.api_key = conf().get("gemini_api_key")
        self.sessions = SessionManager(ChatGPTSession, model=conf().get("model") or "gpt-3.5-turbo")
        self.model = conf().get("model") or "gemini-pro"
        if self.model == "gemini":
            self.model = "gemini-pro"

    def reply(self, query, context: Context = None) -> Reply:
        try:
            session_id = context["session_id"]
            session = self.sessions.session_query(query, session_id)
            genai.configure(api_key=self.api_key)
            gemini_messages = self._prepare_messages(query, context, session.messages)
            
            # 添加安全设置
            safety_settings = {
                HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
            }

            # 生成回复
            response = genai.GenerativeModel(self.model).generate_content(
                gemini_messages,
                safety_settings=safety_settings
            )

            if response.candidates and response.candidates[0].content:
                reply_text = response.candidates[0].content.parts[0].text
                logger.info(f"[Gemini] reply={reply_text}")
                self.sessions.session_reply(reply_text, session_id)
                return Reply(ReplyType.TEXT, reply_text)
            else:
                self._log_safety_ratings(response)
                error_message = "No valid response generated due to safety constraints."
                logger.warning(error_message)
                self.sessions.session_reply(error_message, session_id)
                return Reply(ReplyType.ERROR, error_message)

        except Exception as e:
            logger.error(f"[Gemini] Error generating response: {str(e)}", exc_info=True)
            error_message = "Failed to invoke [Gemini] API!"
            self.sessions.session_reply(error_message, session_id)
            return Reply(ReplyType.ERROR, error_message)

    def _prepare_messages(self, query, context, messages):
        """Prepare messages based on context type."""
        if context.type == ContextType.TEXT:
            return self._convert_to_gemini_messages(self.filter_messages(messages))
        elif context.type in {ContextType.IMAGE, ContextType.AUDIO, ContextType.VIDEO}:
            media_file = self._upload_and_process_file(context)
            return [media_file, "\n\n", query]
        else:
            raise ValueError(f"Unsupported input type: {context.type}")

    def _upload_and_process_file(self, context):
        """Handle media file upload and processing."""
        media_file = genai.upload_file(context.content)
        if context.type == ContextType.VIDEO:
            while media_file.state.name == "PROCESSING":
                logger.info(f"Video file {media_file.name} is processing...")
                time.sleep(5)
                media_file = genai.get_file(media_file.name)
        logger.info(f"Media file {media_file.name} uploaded successfully.")
        return media_file

    def _log_safety_ratings(self, response):
        """Log safety ratings if no valid response is generated."""
        if hasattr(response, 'candidates') and response.candidates:
            for rating in response.candidates[0].safety_ratings:
                logger.warning(f"Safety rating: {rating.category} - {rating.probability}")

    def _convert_to_gemini_messages(self, messages):
        if isinstance(messages, str):
            return [{"role": "user", "parts": [{"text": messages}]}]
        res = []
        for msg in messages:
            role = {"user": "user", "assistant": "model", "system": "user"}.get(msg.get("role"))
            if role:
                res.append({"role": role, "parts": [{"text": msg.get("content")}]})
        return res

    @staticmethod
    def filter_messages(messages: list):
        res, turn = [], "user"
        for message in reversed(messages or []):
            role = message.get("role")
            if role == "system":
                res.insert(0, message)
                continue
            if role != turn:
                continue
            res.insert(0, message)
            turn = "assistant" if turn == "user" else "user"
        return res