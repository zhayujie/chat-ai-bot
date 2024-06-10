import threading
import time
import requests
from wechatpy.enterprise import WeChatClient
from config import conf

class WechatComAppClient(WeChatClient):
    def __init__(self, corp_id, secret, access_token=None, session=None, timeout=None, auto_retry=True):
        super(WechatComAppClient, self).__init__(corp_id, secret, access_token, session, timeout, auto_retry)
        self.fetch_access_token_lock = threading.Lock()

    def fetch_access_token(self):  # 重载父类方法，加锁避免多线程重复获取access_token
        with self.fetch_access_token_lock:
            access_token = self.session.get(self.access_token_key)
            if access_token:
                if not self.expires_at:
                    return access_token
                timestamp = time.time()
                if self.expires_at - timestamp > 60:
                    return access_token
            return super().fetch_access_token()

    def fetch_access_token_cs(self):
        current_time = time.time()
        if self.access_token and self.expires_at - current_time > 60:
            return self.access_token

        corpid = conf().get("wechatcom_corp_id")
        corpsecret = conf().get("wechatcomapp_secret")
        url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={corpid}&corpsecret={corpsecret}"

        response = requests.get(url).json()
        if 'access_token' in response:
            self.access_token = response['access_token']
            self.expires_at = current_time + response['expires_in'] - 60
            print(f'access_token:{self.access_token}')
            return self.access_token
        else:
            raise Exception("Failed to retrieve access token")