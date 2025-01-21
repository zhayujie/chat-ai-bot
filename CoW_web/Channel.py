import streamlit as st

from CoW_web.cinfig_info import channels
from common import const
from CoW_web.config_manager import ConfigManager

def config_manage():
    st.title("配置管理")

    # 创建配置管理器实例
    config_manager = ConfigManager()

    # 1,选择渠道
    selected_channel = st.selectbox(
        "选择渠道",
        options=list(channels.keys()),
        format_func=lambda x: channels[x]["name"]
    )
    
    if selected_channel:
        st.subheader(f"配置 {channels[selected_channel]['name']}")
        
        # 渠道配置表单
        with st.form("channel_config"):
            # 动态显示配置项
            config_values = {}
            for key, field in channels[selected_channel]["config"].items():
                if field["type"] == "text":
                    config_values[key] = st.text_input(
                        field["label"],
                        value=field["default"],
                        key=f"{selected_channel}_{key}"
                    )
                elif field["type"] == "password":
                    config_values[key] = st.text_input(
                        field["label"],
                        value=field["default"],
                        type="password",
                        key=f"{selected_channel}_{key}"
                    )
                elif field["type"] == "number":
                    config_values[key] = st.number_input(
                        field["label"],
                        value=field["default"],
                        key=f"{selected_channel}_{key}"
                    )
                elif field["type"] == "checkbox":
                    config_values[key] = st.checkbox(
                        field["label"],
                        value=field["default"],
                        key=f"{selected_channel}_{key}"
                    )
            
            if st.form_submit_button("保存配置", use_container_width=True):
                # 收集渠道配置
                channel_config = {
                    "channel_type": selected_channel,
                }
                
                # 添加所有配置项的值
                for key in channels[selected_channel]["config"]:
                    channel_config[key] = config_values[key]
                
                # 保存配置
                if config_manager.save_config(channel_config):
                    st.success("渠道配置已保存")
                else:
                    st.error("保存配置失败")

        # 2, 配置模型
        st.divider()
        st.subheader("模型配置")
        
        # 模型分类
        model_categories = {
            "OpenAI模型": [
                const.GPT35, const.GPT35_0125, const.GPT35_1106,
                const.GPT4, const.GPT4_32k, const.GPT4_TURBO,
                const.GPT_4o, const.GPT_4o_MINI
            ],
            "Claude模型": [
                const.CLAUDE_3_OPUS, const.CLAUDE_3_SONNET, const.CLAUDE_3_HAIKU
            ],
            "国内模型": [
                const.WEN_XIN, const.WEN_XIN_4,  # 百度文心
                const.GLM_4, const.GLM_4_PLUS, const.GLM_4_flash,  # 智谱GLM
                const.QWEN_TURBO, const.QWEN_PLUS, const.QWEN_MAX,  # 阿里通义千问
                const.XUNFEI  # 讯飞星火
            ],
            "其他模型": [
                const.GEMINI_PRO, const.GEMINI_15_PRO,  # Google Gemini
                const.MOONSHOT,  # Moonshot
                const.MiniMax, # MiniMax
                const.COZE, # Coze
            ]
        }

        # 选择模型类别和具体模型
        model_category = st.selectbox(
            "选择模型类别",
            options=list(model_categories.keys())
        )
        
        selected_model = st.selectbox(
            "选择具体模型",
            options=model_categories[model_category],
            format_func=lambda x: x.replace("-", " ").title()
        )

        # 模型配置表单
        with st.form("model_config"):
            # 基础配置
            st.subheader("基础配置")
            temperature = st.slider("Temperature (创造性)", 0.0, 2.0, 0.7)
            max_tokens = st.number_input("最大Token数", 100, 4000, 2000)
            
            # API配置
            st.subheader("API配置")
            
            # 根据不同模型显示不同的配置项
            if selected_model in model_categories["OpenAI模型"]:
                api_key = st.text_input("OpenAI API Key", type="password")
                api_base = st.text_input("API Base URL", value="https://api.openai.com/v1")
            elif selected_model in model_categories["Claude模型"]:
                api_key = st.text_input("Claude API Key", type="password")
            elif selected_model == const.WEN_XIN or selected_model == const.WEN_XIN_4:
                api_key = st.text_input("百度 API Key", type="password")
                secret_key = st.text_input("百度 Secret Key", type="password")
            elif selected_model.startswith("glm"):
                api_key = st.text_input("智谱 API Key", type="password")
            elif selected_model.startswith("qwen"):
                api_key = st.text_input("阿里 API Key", type="password")
            elif selected_model == const.XUNFEI:
                app_id = st.text_input("讯飞 APPID")
                api_secret = st.text_input("讯飞 API Secret", type="password")
            elif selected_model.startswith("gemini"):
                api_key = st.text_input("Google API Key", type="password")
            elif selected_model == const.MOONSHOT:
                api_key = st.text_input("Moonshot API Key", type="password")
            elif selected_model == const.MiniMax:
                api_key = st.text_input("MiniMax API Key", type="password")
            elif selected_model == const.COZE:
                api_key = st.text_input("Coze API Key", type="password")
                bot_id = st.text_input("Coze Bot ID")
            # 高级配置
            with st.expander("高级配置"):
                top_p = st.slider("Top P", 0.0, 1.0, 1.0)
                presence_penalty = st.slider("Presence Penalty", -2.0, 2.0, 0.0)
                frequency_penalty = st.slider("Frequency Penalty", -2.0, 2.0, 0.0)
            
            if st.form_submit_button("保存模型配置", use_container_width=True):
                # 收集模型配置
                model_config = {
                    "model": selected_model,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "top_p": top_p,
                    "presence_penalty": presence_penalty,
                    "frequency_penalty": frequency_penalty
                }
                
                # 根据不同模型添加API配置
                if selected_model in model_categories["OpenAI模型"]:
                    model_config.update({
                        "open_ai_api_key": api_key,
                        "open_ai_api_base": api_base
                    })
                elif selected_model in model_categories["Claude模型"]:
                    model_config["claude_api_key"] = api_key
                elif selected_model == const.WEN_XIN or selected_model == const.WEN_XIN_4:
                    model_config.update({
                        "baidu_wenxin_api_key": api_key,
                        "baidu_wenxin_secret_key": secret_key
                    })
                elif selected_model.startswith("glm"):
                    model_config["zhipu_ai_api_key"] = api_key
                elif selected_model.startswith("qwen"):
                    model_config["dashscope_api_key"] = api_key
                elif selected_model == const.XUNFEI:
                    model_config.update({
                        "xunfei_app_id": app_id,
                        "xunfei_api_secret": api_secret
                    })
                elif selected_model.startswith("gemini"):
                    model_config["gemini_api_key"] = api_key
                elif selected_model == const.MOONSHOT:
                    model_config["moonshot_api_key"] = api_key
                elif selected_model == const.MiniMax:
                    model_config["Minimax_api_key"] = api_key
                elif selected_model == const.COZE:
                    model_config["coze_api_key"] = api_key
                    model_config["coze_bot_id"] = bot_id
                
                # 保存配置
                if config_manager.save_config(model_config):
                    st.success("模型配置已保存")
                else:
                    st.error("保存配置失败")

        # 3, linkai配置
        st.divider()
        st.subheader("LinkAI配置")
        
        # 使用toggle开关
        use_linkai = st.toggle("启用LinkAI", value=False)
        
        # 只在启用时显示配置表单
        if use_linkai:
            with st.form("linkai_config"):
                # API配置
                col1, col2 = st.columns(2)
                with col1:
                    linkai_api_key = st.text_input("LinkAI API Key", type="password")
                with col2:
                    linkai_app_code = st.text_input("LinkAI App Code")
                
                # 高级配置
                with st.expander("高级配置"):
                    linkai_api_base = st.text_input(
                        "LinkAI API Base", 
                        value="https://api.link-ai.tech",
                        help="LinkAI服务地址，一般无需修改"
                    )
                    
                    st.markdown("""
                    ### 说明
                    - LinkAI支持国内直接访问，无需代理
                    - 支持知识库和MJ绘图等功能
                    - 可在[控制台](https://link-ai.tech/console)创建应用获取配置
                    """)
                
                if st.form_submit_button("保存LinkAI配置", use_container_width=True):
                    if not linkai_api_key:
                        st.error("必须填写API Key")
                    else:
                        # 收集LinkAI配置
                        linkai_config = {
                            "use_linkai": use_linkai,
                            "linkai_api_key": linkai_api_key,
                            "linkai_app_code": linkai_app_code,
                            "linkai_api_base": linkai_api_base
                        }
                        
                        # 保存配置
                        if config_manager.save_config(linkai_config):
                            st.success("LinkAI配置已保存")
                        else:
                            st.error("保存配置失败")

def main():
    config_manage()

if __name__ == "__main__":
    main()

