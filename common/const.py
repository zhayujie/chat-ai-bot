# bot_type
OPEN_AI = "openAI"
CHATGPT = "chatGPT"
BAIDU = "baidu"  # 百度文心一言模型
XUNFEI = "xunfei"
CHATGPTONAZURE = "chatGPTOnAzure"
LINKAI = "linkai"
CLAUDEAI = "claude"  # 使用cookie的历史模型
CLAUDEAPI= "claudeAPI"  # 通过Claude api调用模型
QWEN = "qwen"  # 旧版通义模型
QWEN_DASHSCOPE = "dashscope"  # 通义新版sdk和api key
COZE = "coze" # Coze

GEMINI = "gemini"  # gemini-1.0-pro
ZHIPU_AI = "glm-4"
MOONSHOT = "moonshot"
MiniMax = "minimax"


# model
CLAUDE3 = "claude-3-opus-20240229"
GPT35 = "gpt-3.5-turbo"
GPT35_0125 = "gpt-3.5-turbo-0125"
GPT35_1106 = "gpt-3.5-turbo-1106"

GPT_4o = "gpt-4o"
GPT_4O_0806 = "gpt-4o-2024-08-06"
GPT4_TURBO = "gpt-4-turbo"
GPT4_TURBO_PREVIEW = "gpt-4-turbo-preview"
GPT4_TURBO_04_09 = "gpt-4-turbo-2024-04-09"
GPT4_TURBO_01_25 = "gpt-4-0125-preview"
GPT4_TURBO_11_06 = "gpt-4-1106-preview"
GPT4_VISION_PREVIEW = "gpt-4-vision-preview"

GPT4 = "gpt-4"
GPT_4o_MINI = "gpt-4o-mini"
GPT4_32k = "gpt-4-32k"
GPT4_06_13 = "gpt-4-0613"
GPT4_32k_06_13 = "gpt-4-32k-0613"

O1 = "o1-preview"
O1_MINI = "o1-mini"

WHISPER_1 = "whisper-1"
TTS_1 = "tts-1"
TTS_1_HD = "tts-1-hd"

WEN_XIN = "wenxin"
WEN_XIN_4 = "wenxin-4"

QWEN_TURBO = "qwen-turbo"
QWEN_PLUS = "qwen-plus"
QWEN_MAX = "qwen-max"

LINKAI_35 = "linkai-3.5"
LINKAI_4_TURBO = "linkai-4-turbo"
LINKAI_4o = "linkai-4o"

GEMINI_PRO = "gemini-1.0-pro"
GEMINI_15_flash = "gemini-1.5-flash"
GEMINI_15_PRO = "gemini-1.5-pro"
GEMINI_20_flash_exp = "gemini-2.0-flash-exp"


GLM_4 = "glm-4"
GLM_4_PLUS = "glm-4-plus"
GLM_4_flash = "glm-4-flash"
GLM_4_LONG = "glm-4-long"
GLM_4_ALLTOOLS = "glm-4-alltools"
GLM_4_0520 = "glm-4-0520"
GLM_4_AIR = "glm-4-air"
GLM_4_AIRX = "glm-4-airx"


CLAUDE_3_OPUS = "claude-3-opus-latest"
CLAUDE_3_OPUS_0229 = "claude-3-opus-20240229"

CLAUDE_35_SONNET = "claude-3-5-sonnet-latest"  # 带 latest 标签的模型名称，会不断更新指向最新发布的模型
CLAUDE_35_SONNET_1022 = "claude-3-5-sonnet-20241022"  # 带具体日期的模型名称，会固定为该日期发布的模型
CLAUDE_35_SONNET_0620 = "claude-3-5-sonnet-20240620"
CLAUDE_3_SONNET = "claude-3-sonnet-20240229"

CLAUDE_3_HAIKU = "claude-3-haiku-20240307"

GITEE_AI_MODEL_LIST = ["Yi-34B-Chat", "InternVL2-8B", "deepseek-coder-33B-instruct", "InternVL2.5-26B", "Qwen2-VL-72B", "Qwen2.5-32B-Instruct", "glm-4-9b-chat", "codegeex4-all-9b", "Qwen2.5-Coder-32B-Instruct", "Qwen2.5-72B-Instruct", "Qwen2.5-7B-Instruct", "Qwen2-72B-Instruct", "Qwen2-7B-Instruct", "code-raccoon-v1", "Qwen2.5-14B-Instruct"]

MODEL_LIST = [
              GPT35, GPT35_0125, GPT35_1106, "gpt-3.5-turbo-16k",
              O1, O1_MINI, GPT_4o, GPT_4O_0806, GPT_4o_MINI, GPT4_TURBO, GPT4_TURBO_PREVIEW, GPT4_TURBO_01_25, GPT4_TURBO_11_06, GPT4, GPT4_32k, GPT4_06_13, GPT4_32k_06_13,
              WEN_XIN, WEN_XIN_4,
              XUNFEI,
              ZHIPU_AI, GLM_4, GLM_4_PLUS, GLM_4_flash, GLM_4_LONG, GLM_4_ALLTOOLS, GLM_4_0520, GLM_4_AIR, GLM_4_AIRX,
              MOONSHOT, MiniMax,
              GEMINI, GEMINI_PRO, GEMINI_15_flash, GEMINI_15_PRO,GEMINI_20_flash_exp,
              CLAUDE_3_OPUS, CLAUDE_3_OPUS_0229, CLAUDE_35_SONNET, CLAUDE_35_SONNET_1022, CLAUDE_35_SONNET_0620, CLAUDE_3_SONNET, CLAUDE_3_HAIKU, "claude", "claude-3-haiku", "claude-3-sonnet", "claude-3-opus", "claude-3.5-sonnet",
              "moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k",
              QWEN, QWEN_TURBO, QWEN_PLUS, QWEN_MAX,
              LINKAI_35, LINKAI_4_TURBO, LINKAI_4o
            ]

MODEL_LIST = MODEL_LIST + GITEE_AI_MODEL_LIST
# channel
FEISHU = "feishu"
DINGTALK = "dingtalk"
