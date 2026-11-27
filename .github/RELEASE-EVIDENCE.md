# 发布构建清单

发布预检在比对构建归档、待发布附件和 `SHA256SUMS.txt`，并生成发布说明后，写出
`release-build-manifest.json`。这是文件名到 SHA-256 的映射，包含十个归档及
`SHA256SUMS.txt` 自身，共十一项。清单是 Actions artifact，不加入 GitHub Release
附件或 PyPI 包；清单缺失或留存失败会阻断本次发布上传。

按标签对应的完整提交、发布 run ID 和实际尝试编号选取原始构建清单：

```sh
gh run download "$RUN_ID" --repo s-silt/fxapk \
  --name "release-build-manifest-${COMMIT}-${RUN_ID}-${ATTEMPT}" \
  --dir "$EVIDENCE_DIR"
```

核对 run 属于 `release.yml`、标签和提交一致，并确认所选尝试确实生成了待核对的
发布产物。清单在上传前留存，不证明发布成功；重跑可能重新构建但跳过已发布版本，
不能把最新尝试的清单直接套到旧发布。Actions artifact 会按仓库设置过期；
在到期前将原文件和 run／尝试出处保存到可信的发布证据目录。

将原清单直接传给 `tools/release_state_probe.py --inventory`，或传给
`tools/release_channel_metadata.py --inventory` 并同时指定 `--github-commit`
与实际下载的附件目录 `--downloaded`（需要证据完整时加 `--require-evidence`）。
附件目录应只含该 Release 的十一份附件，不含构建清单。旧发布没有独立清单时，
不要从待验证的附件或其元数据重建一份再当作可信输入。PyPI 的对照仍是核心包
元数据核对，不是对 PyPI 实际字节验签。
