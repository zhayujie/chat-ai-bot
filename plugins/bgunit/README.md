## 插件说明

利用百度UNIT实现智能对话

- 1.解决问题：利用百度UNIT返回意图和词槽
- 2.如问时间：现在几点钟，今天几号
- 3.如问天气：明天广州天气怎么样，这个周末深圳会不会下雨
- 4.如问数学运算：23+45=多少，100-23=多少，35转化为二进制是多少？
- 5、操控页面：打开首页，导航到综合交通

## 使用说明

### 获取apikey

在百度UNIT官网上自己创建应用，申请百度机器人,可以把预先训练好的模型导入到自己的应用中，

see https://ai.baidu.com/unit/home#/home?track=61fe1b0d3407ce3face1d92cb5c291087095fc10c8377aaf https://console.bce.baidu.com/ai平台申请

### 配置文件

将文件夹中`config.json.template`复制为`config.json`。

在其中填写百度UNIT官网上获取应用的API Key和Secret Key

``` json
    {
    "service_id": "s...", #"机器人ID"
    "api_key": "",
    "secret_key": ""
    }
```