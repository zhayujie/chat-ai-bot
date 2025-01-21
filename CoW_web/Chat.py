import streamlit as st
from CoW_web.config_manager import ConfigManager

def show_chat_info():
    # 创建配置管理器实例
    config_manager = ConfigManager()
    
    st.title("聊天配置")

    # 1, 个人聊天配置
    st.subheader("个人聊天配置")
    
    with st.form("private_chat_config"):
        # 触发配置
        st.markdown("##### 触发配置")
        col1, col2 = st.columns(2)
        with col1:
            single_chat_prefix = st.text_input(
                "触发前缀",
                value="bot,@bot",
                help="私聊时文本需要包含该前缀才能触发机器人回复，多个前缀用逗号分隔"
            )
        with col2:
            single_chat_reply_prefix = st.text_input(
                "回复前缀",
                value="[bot] ",
                help="私聊时自动回复的前缀，用于区分真人"
            )
        
        single_chat_reply_suffix = st.text_input(
            "回复后缀",
            value="",
            help="私聊时自动回复的后缀，\\n可以换行"
        )

        # 会话配置
        st.markdown("##### 会话配置")
        col1, col2 = st.columns(2)
        with col1:
            expires_in_seconds = st.number_input(
                "会话过期时间(秒)",
                min_value=60,
                max_value=7200,
                value=3600,
                help="无操作会话的过期时间"
            )
        with col2:
            conversation_max_tokens = st.number_input(
                "最大上下文字符数",
                min_value=100,
                max_value=4000,
                value=1000,
                help="支持上下文记忆的最多字符数"
            )
            
        # 人格配置
        st.markdown("##### 人格配置")
        character_desc = st.text_area(
            "人格描述",
            value="你是ChatGPT, 一个由OpenAI训练的大型语言模型, 你旨在回答并解决人们的任何问题，并且可以使用多种语言与人交流。",
            help="配置机器人的人格特征"
        )

        # 语音配置
        st.markdown("##### 语音配置")
        col1, col2 = st.columns(2)
        with col1:
            speech_recognition = st.checkbox(
                "开启语音识别",
                value=False,
                help="是否开启语音识别"
            )
        with col2:
            voice_reply_voice = st.checkbox(
                "语音回复语音",
                value=False,
                help="是否使用语音回复语音"
            )

        # 高级配置
        with st.expander("高级配置"):
            col1, col2 = st.columns(2)
            with col1:
                rate_limit_chatgpt = st.number_input(
                    "ChatGPT调用频率限制",
                    min_value=1,
                    max_value=100,
                    value=20,
                    help="每分钟最多调用次数"
                )
            with col2:
                rate_limit_dalle = st.number_input(
                    "DALL-E调用频率限制",
                    min_value=1,
                    max_value=100,
                    value=50
                )
            
            # 图片生成配置
            st.markdown("##### 图片生成配置")
            col1, col2 = st.columns(2)
            with col1:
                text_to_image = st.selectbox(
                    "图片生成模型",
                    options=["dall-e-2", "dall-e-3"],
                    help="用于生成图片的模型"
                )
            with col2:
                image_create_prefix = st.text_input(
                    "图片生成触发词",
                    value="画,看,找",
                    help="触发图片生成的前缀词，多个用逗号分隔"
                )
            
            image_create_size = st.selectbox(
                "图片生成尺寸",
                options=["256x256", "512x512", "1024x1024"],
                help="生成图片的尺寸(dall-e-3默认为1024x1024)"
            )

        if st.form_submit_button("保存配置", use_container_width=True):
            # 收集个人聊天配置
            private_config = {
                "single_chat_prefix": single_chat_prefix.split(","),
                "single_chat_reply_prefix": single_chat_reply_prefix,
                "single_chat_reply_suffix": single_chat_reply_suffix,
                "expires_in_seconds": expires_in_seconds,
                "conversation_max_tokens": conversation_max_tokens,
                "character_desc": character_desc,
                "speech_recognition": speech_recognition,
                "voice_reply_voice": voice_reply_voice,
                "rate_limit_chatgpt": rate_limit_chatgpt,
                "rate_limit_dalle": rate_limit_dalle,
                "text_to_image": text_to_image,
                "image_create_prefix": image_create_prefix.split(","),
                "image_create_size": image_create_size
            }
            
            # 保存配置
            if config_manager.save_config(private_config):
                st.success("个人聊天配置已保存")
            else:
                st.error("保存配置失败")

    # 2, 群聊配置
    st.subheader("群聊配置")
    
    with st.form("group_chat_config"):
        # 触发配置
        st.markdown("##### 触发配置")
        col1, col2 = st.columns(2)
        with col1:
            group_chat_prefix = st.text_input(
                "触发前缀",
                value="@bot",
                help="群聊时包含该前缀则会触发机器人回复"
            )
        with col2:
            group_chat_keyword = st.text_input(
                "关键词触发",
                value="",
                help="群聊时包含该关键词则会触发机器人回复"
            )
        
        col1, col2 = st.columns(2)
        with col1:
            group_chat_reply_prefix = st.text_input(
                "回复前缀",
                value="",
                help="群聊时自动回复的前缀"
            )
        with col2:
            group_chat_reply_suffix = st.text_input(
                "回复后缀",
                value="",
                help="群聊时自动回复的后缀，\\n可以换行"
            )
        
        # 群组配置
        st.markdown("##### 群组配置")
        col1, col2 = st.columns(2)
        with col1:
            group_name_white_list = st.text_input(
                "群聊白名单",
                value="ChatGPT测试群,ChatGPT测试群2",
                help="开启自动回复的群名称列表，多个用逗号分隔"
            )
        with col2:
            group_name_keyword_white_list = st.text_input(
                "群聊白名单关键词",
                value="",
                help="开启自动回复的群名称关键词列表"
            )
        
        group_chat_in_one_session = st.text_input(
            "共享会话的群组",
            value="ChatGPT测试群",
            help="支持会话上下文共享的群名称"
        )

        # 功能配置
        st.markdown("##### 功能配置")
        col1, col2, col3 = st.columns(3)
        with col1:
            no_need_at = st.checkbox(
                "无需@触发",
                value=False,
                help="群聊回复时是否不需要艾特"
            )
        with col2:
            group_at_off = st.checkbox(
                "关闭@触发",
                value=False,
                help="是否关闭群聊时@bot的触发"
            )
        with col3:
            group_speech_recognition = st.checkbox(
                "开启语音识别",
                value=False,
                help="是否开启群组语音识别"
            )

        # 高级配置
        with st.expander("高级配置"):
            col1, col2 = st.columns(2)
            with col1:
                group_welcome_msg = st.text_input(
                    "新人欢迎语",
                    value="",
                    help="配置新人进群固定欢迎语，不配置则使用随机风格欢迎"
                )
            with col2:
                nick_name_black_list = st.text_input(
                    "用户昵称黑名单",
                    value="",
                    help="用户昵称黑名单，多个用逗号分隔"
                )
            
            col1, col2 = st.columns(2)
            with col1:
                max_media_send_count = st.number_input(
                    "单次最大发送媒体数",
                    min_value=1,
                    max_value=10,
                    value=3,
                    help="单次最大发送媒体资源的个数"
                )
            with col2:
                media_send_interval = st.number_input(
                    "发送媒体间隔(秒)",
                    min_value=1,
                    max_value=10,
                    value=1,
                    help="发送图片的时间间隔"
                )
            
            group_chat_exit_group = st.checkbox(
                "允许退群",
                value=False,
                help="是否允许机器人退出群聊"
            )

        if st.form_submit_button("保存配置", use_container_width=True):
            # 收集群聊配置
            group_config = {
                "group_chat_prefix": [group_chat_prefix],
                "group_chat_keyword": group_chat_keyword.split(",") if group_chat_keyword else [],
                "group_chat_reply_prefix": group_chat_reply_prefix,
                "group_chat_reply_suffix": group_chat_reply_suffix,
                "group_name_white_list": group_name_white_list.split(","),
                "group_name_keyword_white_list": group_name_keyword_white_list.split(",") if group_name_keyword_white_list else [],
                "group_chat_in_one_session": [group_chat_in_one_session] if group_chat_in_one_session else [],
                "no_need_at": no_need_at,
                "group_at_off": group_at_off,
                "group_speech_recognition": group_speech_recognition,
                "group_welcome_msg": group_welcome_msg,
                "nick_name_black_list": nick_name_black_list.split(",") if nick_name_black_list else [],
                "max_media_send_count": max_media_send_count,
                "media_send_interval": media_send_interval,
                "group_chat_exit_group": group_chat_exit_group
            }
            
            # 保存配置
            if config_manager.save_config(group_config):
                st.success("群聊配置已保存")
            else:
                st.error("保存配置失败")

def main():
    show_chat_info()

if __name__ == "__main__":
    main()

