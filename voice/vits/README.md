## 说明
VITS是一个可以通过输入语音数据集训练以克隆声线的AI文本转语音模型，
加入对VITS的支持能够以用户自己喜欢的角色的声线来说话，增添趣味性。
需要自行搭建vits-simple-api服务器：https://github.com/Artrajz/vits-simple-api

## 参数说明
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
### 配置文件

将文件夹中`config.json.template`复制为`config.json`。

``` json
    {
    "server_url": "http://127.0.0.1:23456",
    "api_key": "api_key",
    "speaker_id": 0,
    "format": "wav",
    "lang": "auto",
    "length": 1.0,
    "noise": 0.667,
    "noisew": 0.8,
    "max": 50,
    "timeout": 60
    }
```