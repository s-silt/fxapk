# -*- coding: utf-8 -*-
"""误报回归网的**值级**基线：{样本: [[类别, 值, 档位代号], ...]}。

为什么是 .py 而不是 .json：基线记的是判据实际吐出的**具体值**，其中包含真实的厂商域名
（那正是夹具要验的东西——占位域名验不出边界）。JSON 放不下行内豁免注释，而这些值
需要逐条向仓库的公开面护栏说明理由，所以落成 Python 模块。

★不要手改：跑 tests/synthetic 下的生成流程重出（改判据后基线漂移是**有意**的动作，
  要在 diff 里看得见）。
"""
BASELINE: dict[str, list[list[str]]] = {
    'ethers-js-library-constants': [
    ],
    'i18n-copy-keys': [
    ],
    'oss-author-and-docs': [
        ['CONTACT', '邮箱：emn178@gmail.com', 'investigate'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
        ['DOMAIN', 'docs.soliditylang.org', 'investigate'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
        ['DOMAIN', 'eips.ethereum.org', 'investigate'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
        ['DOMAIN', 'exoplayer.dev', 'investigate'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
    ],
    'go-truncated-domains': [
        ['DOMAIN', 'go.uber.org', 'investigate'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
        ['DOMAIN', 'modernc.org', 'investigate'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
    ],
    'webgl-shader-variables': [
        ['DOMAIN', 'x09shadowcoord.xyz', 'investigate'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
        ['DOMAIN', 'x20envcolor.xyz', 'investigate'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
    ],
    'frontend-router-property-chain': [
    ],
    'flutter-framework-strings': [
        ['DOMAIN', 'api.flutter.dev', 'skip'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
        ['DOMAIN', 'dart.dev', 'skip'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
        ['DOMAIN', 'flutter.baseflow.com', 'skip'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
        ['DOMAIN', 'flutter.dev', 'skip'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
        ['DOMAIN', 'pub.dev', 'skip'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
    ],
    'unity-il2cpp-strings': [
        ['DOMAIN', 'auction.unityads.unity3d.com', 'skip'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
        ['DOMAIN', 'cdp.cloud.unity3d.com', 'skip'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
        ['DOMAIN', 'config.uca.cloud.unity3d.com', 'skip'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
    ],
    'react-native-metro-strings': [
        ['DOMAIN', 'reactnative.dev', 'skip'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
        ['IP', '10.0.2.2', 'skip'],
    ],
    'cordova-whitelist-strings': [
        ['DOMAIN', 'capacitorjs.com', 'skip'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
        ['DOMAIN', 'ionicframework.com', 'skip'],  # leak-scan: allow 值级基线条目：判据实际吐出的值，占位域名验不出边界
    ],
}
