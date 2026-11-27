# 发布构建清单

发布预检在比对构建归档、待发布附件和 `SHA256SUMS.txt`，并生成发布说明后，写出
`release-build-manifest.json`。这是文件名到 SHA-256 的映射，包含十个归档及
`SHA256SUMS.txt` 自身，共十一项。清单是 Actions artifact，不加入 GitHub Release
附件或 PyPI 包；清单缺失或留存失败会阻断本次发布上传。

按标签对应的完整提交、发布 run ID 和实际尝试编号选取原始构建清单。
令 `EVIDENCE_DIR` 指向已存在的证据根目录；每次尝试只下载到新建的子目录：

```sh
artifact="release-build-manifest-${COMMIT}-${RUN_ID}-${ATTEMPT}"
destination="$EVIDENCE_DIR/$artifact"
mkdir -- "$destination" &&
  gh run download "$RUN_ID" --repo s-silt/fxapk --name "$artifact" --dir "$destination"
```

同名目录已存在时停止，不覆盖原件；下载失败后不要采信该目录中的文件，
需要重取时改用新的证据根目录。记录 artifact 名称和下载文件的 SHA-256。

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

## 不发版的托管回读演练

「Release evidence rehearsal」用一次性构建运行真实预检，只把构建清单上传到
Actions。随后按本次上传返回的 artifact ID 下载到新目录，逐字节比对，并记录
SHA-256。可在同仓的相关 PR 上触发，也可从 Actions 手动运行；不会写入 PyPI、
GitHub Release 或标签。演练只证明 Actions 留存与回读可用，不证明某次正式发布
成功，也不能代替正式发布原始尝试的清单。
