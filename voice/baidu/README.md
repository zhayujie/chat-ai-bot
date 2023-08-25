## 说明
### 1.百度语音识别与合成参数说明
- 百度语音依赖，经常会出现问题，可能就是缺少依赖：
pip install baidu-aip
pip install pydub
pip install pysilk
- 还有ffmpeg，不同系统安装方式不同

系统中收到的语音文件为mp3格式（wx）或者sil格式（wxy），如果要识别需要转换为pcm格式，转换后的文件为16k采样率，单声道，16bit的pcm文件
发送时又需要（wx）转换为mp3格式，转换后的文件为16k采样率，单声道，16bit的pcm文件,（wxy）转换为sil格式,还要计算声音长度，发送时需要带上声音长度
这些事情都在audio_convert.py中封装了，直接调用即可


### 2.参数说明
- 识别参数
https://ai.baidu.com/ai-doc/SPEECH/Vk38lxily
- 合成参数
https://ai.baidu.com/ai-doc/SPEECH/Gk38y8lzk

## 使用说明
分两个地方配置

1、对于def voiceToText(self, filename)函数中调用的百度语音识别API,中接口调用asr（参数）这个配置见CHATGPT-ON-WECHAT工程目录下的`config.json`文件和config.py文件。
|    参数    | 可需  |               描述               |
| :--------: | :---: | :------------------------------: |
|   app_id   | 必填  |           应用的APPID            |
|  api_key   | 必填  |           应用的APIKey           |
| secret_key | 必填  |         应用的SecretKey          |
|  dev_pid   | 必填  | 语言选择,填写语言对应的dev_pid值 |

2、对于def textToVoice(self, text)函数中调用的百度语音合成API,中接口调用synthesis（参数）在本目录下的`config.json`文件中进行配置。
| 参数  | 可需  | 描述  |
| :---: | :---: | :---: |
|tex| 必填	|合成的文本，使用UTF-8编码，请注意文本长度必须小于1024字节  |
|lan| 必填|	固定值zh。语言选择,目前只有中英文混合模式，填写固定值zh|
|ctp| 必填|	客户端类型选择，web端填写1                |
|spd| 选填|	语速，取值0-15，默认为5中语速|
|pit| 选填|	音调，取值0-15，默认为5中语调|
|vol| 选填|	音量，取值0-15，默认为5中音量（取值为0时为音量最小值，并非为无声）|
|per（基础音库）|选填|度小宇=1，度小美=0，度逍遥（基础）=3，度丫丫=4|
|per（精品音库）|选填|度逍遥（精品）=5003，度小鹿=5118，度博文=106，度小童=110，度小萌=111，度米朵=103，度小娇=5|
|aue| 选填|	3为mp3格式(默认)； 4为pcm-16k；5为pcm-8k；6为wav（内容同pcm-16k）; 注意aue=4或者6是语音识别要求的格式，但是音频内容不是语音识别要求的自然人发音，所以识别效果会受影响。|

关于per参数的说明，注意您购买的哪个音库，就填写哪个音库的参数，否则会报错。如果您购买的是基础音库，那么per参数只能填写0到4，如果您购买的是精品音库，那么per参数只能填写5003，5118，106,110,111,103,5其他的都会报错。
### 配置文件

将文件夹中`config.json.template`复制为`config.json`。

``` json
    {
    "lang": "zh",
    "ctp": 1,
    "spd": 5,
    "pit": 5,
    "vol": 5,
    "per": 0
    }
```