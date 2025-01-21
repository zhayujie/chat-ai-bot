# 渠道配置信息
channels = {
        "wx": {
            "name": "微信个人号",
            "config": {
                "hot_reload": {
                    "type": "checkbox",
                    "label": "是否开启热重载",
                    "default": False
                }
            }
        },
        "wxy": {
            "name": "微信个人号(Wechaty)",
            "config": {
                "wechaty_puppet_service_token": {
                    "type": "text",
                    "label": "Wechaty Token",
                    "default": ""
                }
            }
        },
        "wechatmp": {
            "name": "微信公众号",
            "config": {
                "wechatmp_token": {
                    "type": "text",
                    "label": "Token",
                    "default": ""
                },
                "wechatmp_port": {
                    "type": "number",
                    "label": "端口号",
                    "default": 8080
                },
                "wechatmp_app_id": {
                    "type": "text",
                    "label": "AppID",
                    "default": ""
                },
                "wechatmp_app_secret": {
                    "type": "password",
                    "label": "AppSecret",
                    "default": ""
                },
                "wechatmp_aes_key": {
                    "type": "text",
                    "label": "EncodingAESKey",
                    "default": ""
                }
            }
        },
        "wechatmp_service": {
            "name": "微信公众号(服务号)",
            "config": {
                "wechatmp_token": {
                    "type": "text",
                    "label": "Token",
                    "default": ""
                },
                "wechatmp_port": {
                    "type": "number",
                    "label": "端口号",
                    "default": 8080
                },
                "wechatmp_app_id": {
                    "type": "text",
                    "label": "AppID",
                    "default": ""
                },
                "wechatmp_app_secret": {
                    "type": "password",
                    "label": "AppSecret",
                    "default": ""
                },
                "wechatmp_aes_key": {
                    "type": "text",
                    "label": "EncodingAESKey",
                    "default": ""
                }
            }
        },
        "wechatcom_app": {
            "name": "企业微信应用",
            "config": {
                "wechatcom_corp_id": {
                    "type": "text",
                    "label": "企业ID",
                    "default": ""
                },
                "wechatcomapp_token": {
                    "type": "text",
                    "label": "Token",
                    "default": ""
                },
                "wechatcomapp_port": {
                    "type": "number",
                    "label": "端口号",
                    "default": 9898
                },
                "wechatcomapp_secret": {
                    "type": "password",
                    "label": "Secret",
                    "default": ""
                },
                "wechatcomapp_agent_id": {
                    "type": "text",
                    "label": "AgentId",
                    "default": ""
                },
                "wechatcomapp_aes_key": {
                    "type": "text",
                    "label": "AESKey",
                    "default": ""
                }
            }
        },
        "wework": {
            "name": "企业微信",
            "config": {
                "wework_smart": {
                    "type": "checkbox",
                    "label": "是否使用已登录的企业微信",
                    "default": True
                }
            }
        },
        "feishu": {
            "name": "飞书",
            "config": {
                "feishu_port": {
                    "type": "number",
                    "label": "端口号",
                    "default": 80
                },
                "feishu_app_id": {
                    "type": "text",
                    "label": "App ID",
                    "default": ""
                },
                "feishu_app_secret": {
                    "type": "password",
                    "label": "App Secret",
                    "default": ""
                },
                "feishu_token": {
                    "type": "text",
                    "label": "Verification Token",
                    "default": ""
                },
                "feishu_bot_name": {
                    "type": "text",
                    "label": "机器人名称",
                    "default": ""
                }
            }
        },
        "dingtalk": {
            "name": "钉钉",
            "config": {
                "dingtalk_client_id": {
                    "type": "text",
                    "label": "Client ID",
                    "default": ""
                },
                "dingtalk_client_secret": {
                    "type": "password",
                    "label": "Client Secret",
                    "default": ""
                },
                "dingtalk_card_enabled": {
                    "type": "checkbox",
                    "label": "是否启用卡片消息",
                    "default": False
                }
            }
        }
    }