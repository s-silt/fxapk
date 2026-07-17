"""config-chain 数据契约：远程配置对象候选 + 下载解码后的配置制品。

两者都是 frozen dataclass（确定性、可哈希、可进 corpus 索引）。``RemoteConfigCandidate`` 由被动发现
（``discover``）产出；``ConfigArtifact`` 由授权档下载+多层解码产出（slice-1b 填充，此处先定契约）。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RemoteConfigCandidate:
    """一条**远程配置对象候选**：App 里硬编码/引用的、疑似运行时拉取的配置文件 URL。

    纯静态发现（被动、零网络）：命中对象存储/CDN host 家族，或"配置类对象后缀 + 配置类路径"双证即入选，
    ``reasons`` 记命中依据。授权档（slice-1b）据此清单下载 + 多层解码取动态域名/IP 池。
    """

    url: str
    host: str
    #: 对象存储/CDN 家族：aliyun-oss|tencent-cos|huawei-obs|aws-s3|qiniu|http（非对象存储但命中配置双证）。
    store_kind: str
    object_path: str  # URL path（去 query/fragment），用于判后缀 + 下载定位
    reasons: tuple[str, ...]  # object-storage-host|config-like-ext|config-like-path
    source_ref: str  # 命中位置（如 dex-string[123]），进证据链


@dataclass(frozen=True)
class ConfigArtifact:
    """（slice-1b）下载并多层解码后的配置制品。先定契约，下载档填充。

    ``decode_chain`` 记成功的解码步序（如 ``("base64", "aes", "json")``）；``decoded=False`` 表示下到了
    字节但未能解成结构化配置（保留原始落盘供人工）。``domains``/``ips`` 是从解出的明文配置抽出的动态池。
    """

    source_url: str
    sha256: str
    size: int
    decoded: bool
    decode_chain: tuple[str, ...]
    domains: tuple[str, ...]
    ips: tuple[str, ...]
    stored_path: str | None  # reports/<sample_sha256>/remote_config/ 落盘路径


__all__ = ["ConfigArtifact", "RemoteConfigCandidate"]
