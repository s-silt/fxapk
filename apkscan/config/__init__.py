"""config —— APK 远程配置链（config-chain）子系统。

发现 App 里硬编码/引用的**远程配置对象**（OSS/COS/CDN 上的配置文件，多为加密），（授权档）下载并多层
解码成明文配置，抽出动态域名/IP 池回灌归因——把"APK→控制面→业务基础设施"这条控制链在取证侧打通。

分层：``discover``（被动发现候选，纯离线）→ 下载+解码（授权档，复刻 pipeline 主被动硬隔离门）→
``models`` 承载 ``RemoteConfigCandidate`` / ``ConfigArtifact`` 契约。解密复用 ``core.appcrypto``、
候选进 ``LeadCategory.REMOTE_CONFIG`` 线索。
"""
