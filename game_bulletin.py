import asyncio
import hashlib
import hmac
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib import parse

from httpx import AsyncClient

from log import logger

bulletin_list_url = "https://ak-webview.hypergryph.com/api/game/bulletinList?target=Android"
bulletin_detail_url = "https://ak-webview.hypergryph.com/api/game/bulletin"


class GameBulletin:
    def __init__(self) -> None:
        self.client = AsyncClient()

    async def fetch(self,
                    method: str,
                    url: str,
                    headers: dict[str, str],
                    data: dict[str, Any] | None,
                    raise_error: bool = True,
                    save: bool = False) -> dict[str, Any]:
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

        return obj

    async def bulletin_list(self):
        obj = await self.fetch(
            'get',
            bulletin_list_url,
            {},
            None,
        )
        return obj

    async def bulletin_detail(self, cid: str):
        url = f"{bulletin_detail_url}/{cid}"
        obj = await self.fetch(
            'get',
            url,
            {},
            None,
        )
        return obj

    async def _fetch_and_save_single(self, path: Path, cid: str):
        if (path / "bulletin" / f"{cid}.json").exists():
            return
        obj = await self.bulletin_detail(cid)
        with open(path / "bulletin" / f"{cid}.json", "w", encoding="utf-8") as fp:
            json.dump(obj, fp, ensure_ascii=False, indent=4)

    async def fetch_and_save(self, path: str | Path):
        path = Path(path)
        bulletin_list = await self.bulletin_list()
        with open(path / "bulletin_list" / f"{time.strftime("%Y-%m-%d %H-%M-%S")}.json", "w", encoding="utf-8") as fp:
            json.dump(bulletin_list, fp, ensure_ascii=False, indent=4)
        tasks = []
        for bulletin in bulletin_list["data"]["list"]:
            cid = bulletin["cid"]
            tasks.append(self._fetch_and_save_single(path, cid))
        await asyncio.gather(*tasks)
