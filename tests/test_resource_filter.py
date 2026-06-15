"""_common.is_text_resource 的资源分类契约：文本扫描应排除二进制资源。

回归：TEXT_RESOURCE_PREFIXES 的 "assets/" 前缀曾把整棵 Flutter 资源树（含字体 .otf /
图片 .png / .so 等二进制）当文本资源，导致 contacts/payment/crypto 把二进制解码后跑正则，
既错又慢（512KB .otf 让 email 正则灾难性回溯 4.6 分钟）。
"""

from __future__ import annotations

from apkscan.analyzers._common import (
    TEXT_RESOURCE_PREFIXES,
    TEXT_RESOURCE_SUFFIXES,
    is_text_resource,
)


def _itr(path: str) -> bool:
    return is_text_resource(
        path, suffixes=TEXT_RESOURCE_SUFFIXES, prefixes=TEXT_RESOURCE_PREFIXES
    )


def test_text_suffixes_and_prefixes_still_text():
    assert _itr("assets/config.json")
    assert _itr("res/raw/data.txt")
    assert _itr("res/xml/network_security_config.xml")
    assert _itr("assets/apps/__UNI__X/www/app-service.js")


def test_no_extension_under_assets_prefix_still_text():
    # 无扩展名的 assets/ 下文件仍按文本（保持既有前缀行为，不误杀）。
    assert _itr("assets/flutter_assets/AssetManifest")


def test_binary_resources_excluded_even_under_text_prefix():
    # 字体 / 图片 / 音视频 / 原生库 / 压缩包：即使落在 assets/ 前缀下也不得按文本扫描。
    for path in [
        "assets/flutter_assets/fonts/MaterialIcons-Regular.otf",
        "assets/flutter_assets/fonts/Roboto.ttf",
        "assets/fonts/icon.woff2",
        "assets/flutter_assets/assets/images/splash_image.png",
        "assets/img/logo.jpg",
        "assets/img/banner.webp",
        "assets/sound/click.mp3",
        "assets/video/intro.mp4",
        "assets/payload.so",
        "assets/data/blob.bin",
        "assets/bundle.zip",
    ]:
        assert not _itr(path), f"二进制资源应被排除：{path}"
