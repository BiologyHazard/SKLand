import asyncio
import hashlib
import hmac
import json
import re
import time
from typing import Any
from urllib import parse

from httpx import AsyncClient

from log import logger, set_level

set_level('DEBUG')


TOKEN_LENGTH = 24
APP_CODE = '4ca99fa6b56cc2ba'

send_phone_code_url = 'https://as.hypergryph.com/general/v1/send_phone_code'
token_by_phone_code_url = 'https://as.hypergryph.com/user/auth/v2/token_by_phone_code'
token_by_phone_password_url = 'https://as.hypergryph.com/user/auth/v1/token_by_phone_password'
basic_url = 'https://as.hypergryph.com/user/info/v1/basic'
get_grant_code_url = 'https://as.hypergryph.com/user/oauth2/v2/grant'
get_cred_url = 'https://zonai.skland.com/api/v1/user/auth/generate_cred_by_code'
get_binding_list_url = 'https://zonai.skland.com/api/v1/game/player/binding'
attendance_url = 'https://zonai.skland.com/api/v1/game/attendance'  # ?uid={uid}(&gameId={gameId}) 貌似可以不加gameId
player_info_url = 'https://zonai.skland.com/api/v1/game/player/info'
user_url = 'https://zonai.skland.com/api/v1/user'
cultivate_character_url = 'https://zonai.skland.com/api/v1/game/cultivate/character'  # ?characterId={characterId}
cultivate_info_url = 'https://zonai.skland.com/api/v1/game/cultivate/info'
cultivate_player_url = 'https://zonai.skland.com/api/v1/game/cultivate/player'  # ?uid={uid}
refresh_url = 'https://zonai.skland.com/api/v1/auth/refresh'

# 以下是web的接口
check_url = 'https://zonai.skland.com/web/v1/user/check'
user_url = 'https://zonai.skland.com/web/v1/user'
rts_url = 'https://zonai.skland.com/web/v1/user/rts'
game_url = 'https://zonai.skland.com/web/v1/game'
list_url = 'https://zonai.skland.com/web/v1/bulletins/list?cateId=14&gameId=1'
index_url = 'https://zonai.skland.com/web/v1/rec/index?gameId=1&pageSize=5'


class SKLandError(Exception):
    pass


login_headers: dict[str, str] = {
    # 'User-Agent': 'Skland/1.0.1 (com.hypergryph.skland; build:100001014; Android 31; ) Okhttp/4.11.0',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0',
    'Accept-Encoding': 'gzip',
    'Connection': 'close'
}

# 签名请求头一定要这个顺序，否则失败
# timestamp是必填的,其它三个随便填,不要为none即可
header_for_sign: dict[str, str] = {
    'platform': '3',
    'timestamp': '',
    'dId': 'BKj0XhcO2ttJiIPZ06YBAS8zO05UpEWKGDKhEZP+gHm6dmmV/DX34DeNQ8j8MECxbmIhOrEJ0EAxdfmw8PmlnzQ==',
    'vName': '1.0.0'
}


def generate_signature(token: str, path: str, body_or_query: str) -> tuple[str, Any]:
    """
    获得签名头
    接口地址+方法为Get请求？用query否则用body+时间戳+ 请求头的四个重要参数（dId，platform，timestamp，vName）.toJSON()
    将此字符串做HMAC加密，算法为SHA-256，密钥token为请求cred接口会返回的一个token值
    再将加密后的字符串做MD5即得到sign
    :param token: 拿cred时候的token
    :param path: 请求路径（不包括网址）
    :param body_or_query: 如果是GET，则是它的query。POST则为它的body
    :return: 计算完毕的sign
    """
    # 总是说请勿修改设备时间，怕不是yj你的服务器有问题吧，所以这里特地-2
    time_stamp = str(int(time.time()) - 2)
    header_ca = json.loads(json.dumps(header_for_sign))
    header_ca['timestamp'] = time_stamp
    header_ca_str: str = json.dumps(header_ca, separators=(',', ':'))
    s: str = path + body_or_query + time_stamp + header_ca_str
    hex_s: str = hmac.new(token.encode('utf-8'), s.encode('utf-8'), hashlib.sha256).hexdigest()
    md5: str = hashlib.md5(hex_s.encode('utf-8')).hexdigest().encode('utf-8').decode('utf-8')  # 算出签名
    return md5, header_ca


def get_sign_header(url: str,
                    method: str,
                    body,
                    old_header,
                    sign_token: str) -> dict[str, str]:
    """能跑的代码就不去动他（"""
    h = json.loads(json.dumps(old_header))
    p = parse.urlparse(url)
    if method.lower() == 'get':
        h['sign'], header_ca = generate_signature(sign_token, p.path, p.query)
    else:
        h['sign'], header_ca = generate_signature(sign_token, p.path, json.dumps(body))
    for i in header_ca:
        h[i] = header_ca[i]
    # logger.debug(f'get_sign_header(url={url!r}, method={method!r}, old_header={old_header!r}, sign_token={sign_token!r}) returns {h!r}')
    return h


class SKLand:
    def __init__(self) -> None:
        self.client = AsyncClient()
        self.attended: list[str] = []
        self.token: str
        self.grant_code: str
        self.cred: str
        self.sign_token: str

    async def fetch(self,
                    method: str,
                    url: str,
                    headers: dict[str, str],
                    data: dict[str, Any] | None,
                    sign: bool,
                    raise_error: bool = True,
                    save: bool = False) -> dict[str, Any]:
        if sign:
            headers = get_sign_header(
                url,
                method,
                data,
                headers | {'cred': self.cred},
                self.sign_token,
            )

        response = await self.client.request(
            method,
            url,
            headers=headers,
            json=data,
        )
        obj = response.json()

        if save:
            with open(f'examples/{method.upper()} {re.sub(r'[\\/:*?"<>|]', '_', url)}.json', 'w', encoding='utf-8') as fp:
                json.dump(obj, fp, ensure_ascii=False, indent=4)
        logger.debug(f'{method.upper()} {url} returns {obj!r}')

        if raise_error:
            if 'status' in obj and obj['status'] != 0 or 'code' in obj and obj['code'] != 0:
                raise SKLandError(obj['msg'])

        return obj

    async def send_phone_code(self, phone: str) -> None:
        data = {
            'phone': phone,
            'type': 2,
        }

        await self.fetch(
            'POST',
            send_phone_code_url,
            login_headers,
            data,
            sign=False,
        )

    async def token_by_phone_code(self, phone: str, code: str) -> str:
        data = {
            "phone": phone,
            "code": code,
        }

        obj = await self.fetch(
            'POST',
            token_by_phone_code_url,
            login_headers,
            data,
            sign=False,
        )

        self.token = obj['data']['token']
        return self.token

    async def token_by_phone_password(self, phone: str, password: str) -> str:
        data = {
            "phone": phone,
            "password": password,
        }

        obj = await self.fetch(
            'POST',
            token_by_phone_password_url,
            login_headers,
            data,
            sign=False,
        )

        self.token = obj['data']['token']
        return self.token

    async def basic(self) -> dict[str, Any]:
        url = f'{basic_url}?token={self.token}'
        obj = await self.fetch(
            'GET',
            url,
            login_headers,
            None,
            True,
        )
        return obj

    async def get_grant_code(self) -> str:
        data = {
            'appCode': APP_CODE,
            'token': self.token,
            'type': 0,
        }
        obj = await self.fetch(
            'POST',
            get_grant_code_url,
            login_headers,
            data,
            sign=False,
        )
        self.grant_code = obj['data']['code']
        return self.grant_code

    async def get_cred(self) -> tuple[str, str]:
        data = {
            'code': self.grant_code,
            'kind': 1
        }
        obj = await self.fetch(
            'POST',
            get_cred_url,
            login_headers,
            data,
            sign=False,
        )
        self.cred = obj['data']['cred']
        self.sign_token = obj['data']['token']
        return self.cred, self.sign_token

    async def login_by_token(self, token: str) -> tuple[str, str]:
        self.token = token
        self.grant_code = await self.get_grant_code()
        self.cred, self.sign_token = await self.get_cred()
        return self.cred, self.sign_token

    async def login_by_phone_code(self, phone: str, code: str) -> tuple[str, str]:
        token = await self.token_by_phone_code(phone, code)
        cred, sign_token = await self.login_by_token(token)
        return cred, sign_token

    async def login_by_phone_password(self, phone: str, password: str) -> tuple[str, str]:
        token = await self.token_by_phone_password(phone, password)
        cred, sign_token = await self.login_by_token(token)
        return cred, sign_token

    async def get_binding_list(self, app_code: str = 'arknights') -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        obj = await self.fetch(
            'GET',
            get_binding_list_url,
            login_headers,
            None,
            True,
        )
        for app in obj['data']['list']:
            if app['appCode'] == app_code:
                result.extend(app['bindingList'])
        return result

    async def attendance_query(self, uid: str) -> dict[str, Any]:
        url = f'{attendance_url}?uid={uid}'
        obj = await self.fetch(
            'GET',
            url,
            login_headers,
            None,
            True,
        )
        return obj

    async def attendance_single_character(self, character: dict[str, Any]) -> str:
        uid: str = character['uid']
        nickname: str = character['nickName']
        channel_master_id: str = character['channelMasterId']
        channel_name: str = character['channelName']

        data = {
            'gameId': channel_master_id,
            'uid': uid,
        }

        obj = await self.fetch(
            'POST',
            attendance_url,
            login_headers,
            data,
            True,
        )

        if obj['code'] == 0:
            award_messages: list[str] = []
            for award in obj['data']['awards']:
                award_name: str = award['resource']['name']
                award_count: int = award['count'] if 'count' in award else 1
                award_messages.append(f'{award_name} × {award_count}')
            award_message = f'获得奖励{"、".join(award_messages)}。' if award_messages else '未获得任何奖励。'
            if uid not in self.attended:
                self.attended.append(uid)
            return f'{channel_name}账号 Dr. {nickname} ({uid}) 签到成功！{award_message}'

        elif obj['code'] == 10001:
            if uid in self.attended:
                self.attended.append(uid)
            return f'{channel_name}账号 Dr. {nickname} ({uid}) 今天已经签到！'

        else:
            message: str = obj['message']
            raise SKLandError(f'{channel_name}账号 Dr. {nickname} ({uid}) 签到时出现未知错误：{message}')

    async def attendance_multi_characters(self) -> dict[str, Any]:
        try:
            binding_list: list[dict[str, Any]] = await self.get_binding_list()

            if not binding_list:
                return {
                    'code': 1,
                    'msg': '获取账号绑定角色信息失败，该账号未绑定任何角色。',
                }

            tasks = [self.attendance_single_character(character) for character in binding_list]
            result: list[str | BaseException] = await asyncio.gather(*tasks, return_exceptions=True)
            success: bool = all(isinstance(x, str) for x in result)
            message: str = '\n'.join(x if isinstance(x, str) else repr(x) for x in result)

            return {
                'code': 0 if success else 3,
                'msg': message,
            }
        except SKLandError as e:
            return {
                'code': 1,
                'msg': f'森空岛自动签到出现错误：{e!r}',
            }
        except Exception as e:
            return {
                'code': 2,
                'msg': f'森空岛自动签到出现错误：{e!r}',
            }

    async def get_player_info(self, uid) -> dict[str, Any]:
        # characters: list[dict[str, Any]] = await get_binding_list(cred, sign_token)
        # if not characters:
        #     raise SKLAssistantError('该账号未绑定任何角色。')
        # if uid is None:
        #     uid = characters[0]['uid']
        # elif not any(character['uid'] == uid for character in characters):
        #     raise SKLAssistantError('该账号未绑定该角色。')

        url: str = f'{player_info_url}?uid={uid}'
        obj = await self.fetch(
            'GET',
            url,
            login_headers,
            None,
            True,
        )
        return obj

    async def get_user_info(self):
        obj = await self.fetch(
            'GET',
            user_url,
            login_headers,
            None,
            True,
        )
        return obj

    async def cultivate_player(self, uid):
        url: str = f'{cultivate_player_url}?uid={uid}'
        obj = await self.fetch(
            'GET',
            url,
            login_headers,
            None,
            True,
        )
        return obj

    async def cultivate_character(self, character_id):
        url: str = f'{cultivate_character_url}?characterId={character_id}'
        obj = await self.fetch(
            'GET',
            url,
            login_headers,
            None,
            True,
        )
        return obj

    async def cultivate_info(self):
        obj = await self.fetch(
            'GET',
            cultivate_info_url,
            login_headers,
            None,
            True,
        )
        return obj

    async def refresh(self):
        obj = await self.fetch(
            'GET',
            refresh_url,
            login_headers,
            None,
            True,
        )
        return obj
