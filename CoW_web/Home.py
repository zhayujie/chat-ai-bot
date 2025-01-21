import streamlit as st
import os
from CoW_web.Chat import show_chat_info
from CoW_web.Channel import config_manage

def read_readme():
    # 获取README.md的路径 (相对于Home.py的上一级目录)
    readme_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'README.md')
    
    try:
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error reading README.md: {str(e)}"

def main():
    st.set_page_config(
        page_title="ChatGPT-on-WeChat",
        page_icon="CoW_web/chat.ico",
        layout="wide"
    )

    # 侧边栏导航
    with st.sidebar:
        st.title("导航菜单")
        selected_page = st.radio(
            "选择页面",
            options=["首页", "渠道配置", "聊天配置"],
            index=0
        )
        
        st.divider()
        st.markdown("""
        ### 快速链接
        - [项目文档](https://docs.link-ai.tech/cow/quick-start)
        - [GitHub仓库](https://github.com/JC0v0/chatgpt-on-wechat)
        - [问题反馈](https://github.com/JC0v0/chatgpt-on-wechat/issues)
        """)

    # 根据选择显示不同页面
    if selected_page == "首页":
        st.title("ChatGPT-on-WeChat")
        readme_content = read_readme()
        st.markdown(readme_content)
        
    elif selected_page == "聊天配置":
        show_chat_info()
        
    elif selected_page == "渠道配置":
        config_manage()

if __name__ == "__main__":
    main()

