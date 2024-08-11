import aiohttp
apis = {
    "stage": "https://backend.yituliu.cn/stage/t3",
    "orundum": "https://backend.yituliu.cn/stage/orundum",
    "act": "https://backend.yituliu.cn/stage/act",
    "value": "https://backend.yituliu.cn/item/value",
    "perm": "https://backend.yituliu.cn/store/perm",
    "act": "https://backend.yituliu.cn/store/act",
    "pack": "https://backend.yituliu.cn/store/pack",
    "table": "https://backend.yituliu.cn/survey/operator/table",
    "result": "https://backend.yituliu.cn/survey/operator/result",
}


async def fetch_single(url):
    async with aiohttp.request('get', url) as response:
        return await response.json()
