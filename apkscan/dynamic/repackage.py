"""脱壳后重打包出「去壳」APK 并装回设备，使其能被重新动态抓包（解除加固壳对 frida/调试的阻断以便观测）。

取证用途：对取证样本自身在分析机上做运行时观测，产出端点/密钥/独特串等线索，不面向任何第三方基础设施。

工作流（MVP，见设计 spec 2026-06-22-...；务实混合路线）::

    S0 能力探测：has_apksigner / has_zipalign（硬依赖）+ has_device；缺 → status=skipped + 精确手册
    S1 输入校验：包名形态（device.is_valid_package）、原 APK 存在
    S2 收脱壳 DEX：out_dir/dump 下 rglob *.dex（自收，不依赖 unpack 回传）
    S3 DEX→classes*.dex 映射：校验 dex magic，按序映射；无 DEX/全非法 → error
    S4 zip 替换：用脱壳 DEX 覆盖原 APK 的 classes*.dex、删旧签名 META-INF/*（zipfile，不全量回编译）
    S5 zipalign → S6 apksigner 重签 + verify（每步查 returncode，失败 error）
    S7 卸原包（重签必换签名）→ 装去壳包（provision.uninstall_app + install_apk）
    S8 四联判定去壳真伪：install Success + am start + 进程存活(非秒退) + frida 可附（+best-effort logcat FATAL）
    S9 done（去壳版已就位，capture 将抓此版）；任一不过 → S10 降级

    S10 降级：重装原 APK 保证 capture 有可 spawn 目标，status=skipped（降级是预期且有用的结果）

错误处理铁律：任何失败 → 结构化 DynamicResult（status=done|skipped|error），**绝不抛**、全程 logging、
不裸 pass、不在 try 里 swallow log。外部工具（apksigner/zipalign/keytool）走 subprocess 重定向到文件
（不用 PIPE，避免 Java 孙进程持管道致超时卡死）+ timeout + stdin=DEVNULL。

★ 能力边界（如实写明，功能治不了）：VMP/dex2c/虚拟化壳（dump 出空壳）、重 native 壳、带签名/CRC
完整性自校验或反重打包的壳（重签后自杀）、app 自身反模拟器/反 frida 检测（随重打包带入）。DEX→classes
映射为启发式（frida-dexdump 命名/顺序不保证），不确定时果断降级而非强塞。重签必卸原包 → 清 app 数据/登录态。
整体真去壳成功率约 35-50%（混合样本，VMP/native 占比高则更低）——多数样本预期降级，不粉饰。
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

from apkscan.core import device, tools
from apkscan.core.models import AnalysisConfig
from apkscan.dynamic import (
    STATUS_DONE,
    STATUS_ERROR,
    STATUS_SKIPPED,
    DynamicResult,
    empty_result,
)

logger = logging.getLogger(__name__)

# 外部工具超时（秒）：apksigner/zipalign 通常秒级，给足余量。
_TOOL_TIMEOUT = 120.0
# am start 后判进程存活的宽限（秒，仿 capture._FRIDA_GRACE）。
_SPAWN_GRACE = 2.0
# subprocess 输出尾部保留多少字符记 reason/日志。
_STDOUT_TAIL = 2000
# dex 文件 magic 前缀（dex\n + 版本）。
_DEX_MAGIC = b"dex\n"
# 去壳 debug keystore 缓存位置（仓库外，复用一次生成）。
_KEYSTORE_PATH = Path.home() / ".apkscan" / "repack-debug.keystore"
_KS_PASS = "android"
_KS_ALIAS = "androiddebugkey"


def run(
    apk_path: str,
    out_dir: str = "out",
    *,
    out: str | None = None,
    serial: str | None = None,
    package_name: str | None = None,
) -> DynamicResult:
    """重打包去壳主入口（见模块 docstring）。绝不抛，返回字段齐全的 DynamicResult。

    Args:
        apk_path: 原 APK 路径（重打包以它为基底，仅替换 DEX）。
        out_dir: 产物目录；脱壳 DEX 取自 ``out_dir/dump``，去壳 APK 落 ``out_dir/repack``。
        out: ``out_dir`` 的关键字别名（CLI 以 out= 调，out 优先）。
        serial: 目标设备 serial（多设备消歧，透传 adb/frida/provision）。
        package_name: 包名（auto 可透传）；None 时内部 load_apk 自解。
    """
    if out is not None:
        out_dir = out

    skipped = _check_capabilities()
    if skipped is not None:
        return skipped

    try:
        package = package_name or _resolve_package_name(apk_path)
    except Exception as exc:  # noqa: BLE001 — load_apk 失败转 error，不抛
        logger.exception("[repack] load_apk 取包名失败：%s", apk_path)
        return empty_result(STATUS_ERROR, f"加载 APK 取包名失败：{exc}")

    if not package or not device.is_valid_package(package):
        logger.error("[repack] 包名缺失/形态非法，拒绝重打包：%r", package)
        return empty_result(STATUS_ERROR, f"包名缺失或形态非法，拒绝重打包：{package!r}")

    if not Path(apk_path).is_file():
        return empty_result(STATUS_ERROR, f"原 APK 不存在：{apk_path}")

    playbook: list[str] = []
    try:
        return _repackage_impl(apk_path, package, out_dir, serial, playbook)
    except Exception as exc:  # noqa: BLE001 — 任何意外都转 DynamicResult，绝不抛给调用方
        logger.exception("[repack] 重打包异常：%s", apk_path)
        result = empty_result(STATUS_ERROR, f"重打包执行异常：{exc}")
        result["playbook"] = playbook
        return result


def _repackage_impl(
    apk_path: str, package: str, out_dir: str, serial: str | None, playbook: list[str]
) -> DynamicResult:
    repack_dir = Path(out_dir) / "repack"
    repack_dir.mkdir(parents=True, exist_ok=True)

    # S2/S3：收脱壳 DEX + 映射 classes*.dex。
    dump_dex = _collect_dump_dex(out_dir)
    if not dump_dex:
        return _err(
            "未在 out_dir/dump 找到脱壳 DEX（请先成功 unpack）；无料可重打包。", playbook
        )
    mapping = _map_dump_to_classes(dump_dex)
    if mapping is None:
        return _err(
            f"脱壳 DEX 无法可靠重组为 classes*.dex（{len(dump_dex)} 个，疑 dump 非完整可跑/全非 DEX）。",
            playbook,
        )

    # S4：zip 替换 DEX + 删旧签名。
    base = Path(apk_path).stem
    replaced = repack_dir / f"{base}-deshelled-unsigned.apk"
    try:
        _replace_dex_in_zip(Path(apk_path), mapping, replaced)
    except Exception as exc:  # noqa: BLE001
        logger.exception("[repack] zip 替换 DEX 失败")
        return _err(f"zip 替换 DEX 失败：{exc}", playbook)

    # S5/S6：zipalign → apksigner 重签 + verify。
    aligned = repack_dir / f"{base}-deshelled-aligned.apk"
    signed = repack_dir / f"{base}-deshelled.apk"
    align_err = _zipalign(replaced, aligned, playbook)
    if align_err:
        return _err(align_err, playbook)
    sign_err = _ensure_keystore_and_sign(aligned, signed, playbook)
    if sign_err:
        return _err(sign_err, playbook)

    # S7：卸原包（签名必变）→ 装去壳包。
    logger.info("[repack] 卸原包后安装去壳包：%s", package)
    device.force_stop_app(package, serial)
    from apkscan.dynamic import provision

    provision.uninstall_app(package, serial=serial)  # best-effort，签名冲突的前置
    inst = provision.install_apk(str(signed), serial=serial)
    playbook.append(f"adb uninstall {package} && adb install -r -t -g {signed}")
    if not inst.get("ok"):
        _degrade_reinstall_original(apk_path, package, serial)
        return _err(
            f"去壳包安装失败：{inst.get('detail') or '未知'}（已尝试重装原包供 capture 兜底）", playbook
        )

    # S8：四联判定去壳真伪。
    alive, why = _verdict_app_alive(package, serial)
    if not alive:
        # S10 降级：重装原包，capture 仍跑原版。
        _degrade_reinstall_original(apk_path, package, serial)
        result = empty_result(
            STATUS_SKIPPED,
            f"去壳包装上但未通过存活判定（{why}）；已重装原包，capture 将抓原版（疑 VMP/重native/样本自我检测）。",
        )
        result["artifacts"] = [str(signed)]
        result["playbook"] = playbook
        return result

    # S9：done。
    result = empty_result(
        STATUS_DONE,
        f"去壳成功：去壳版已就位（{package}），capture 将抓此版。判定：{why}",
    )
    result["artifacts"] = [str(signed)]
    result["playbook"] = playbook
    return result


def _err(reason: str, playbook: list[str]) -> DynamicResult:
    """构造 error 结果（带 playbook）。"""
    logger.error("[repack] %s", reason)
    result = empty_result(STATUS_ERROR, reason)
    result["playbook"] = playbook
    return result


# ---------------------------------------------------------------------------
# 能力探测
# ---------------------------------------------------------------------------


def _check_capabilities() -> DynamicResult | None:
    """探测重打包所需能力。全满足返回 None；任一缺失返回 status=skipped + 精确手册。"""
    missing: list[str] = []
    if not tools.has_apksigner():
        missing.append("apksigner（Android SDK build-tools；重签名）")
    if not tools.has_zipalign():
        missing.append("zipalign（Android SDK build-tools；4 字节对齐）")
    if not device.has_device():
        missing.append("在线设备（装回去壳包并判活需要）")
    if not missing:
        return None
    reason = "缺少：" + "；".join(missing)
    logger.info("[repack] 前置条件不满足，跳过：%s", reason)
    result = empty_result(STATUS_SKIPPED, reason)
    result["playbook"] = _manual_playbook()
    return result


def _manual_playbook() -> list[str]:
    """缺工具时的精确手册（可直接复制的命令/动作）。"""
    return [
        "# 1) 装 Android SDK build-tools（含 apksigner/zipalign），并把其目录加进 PATH：",
        "#    如 <Android/Sdk>/build-tools/<版本>/  （Windows 为 apksigner.bat / zipalign.exe）",
        "apksigner --version   # 验证可用",
        "zipalign             # 验证可用",
        "# 2) 需 Java（apksigner/keytool 依赖）：java -version 应可用",
        "# 3) 连上 root 设备：adb devices 状态为 device",
        "# 4) 手动重打包（绕加固壳、改回真实 DEX）参考：",
        "#    用脱壳 DEX 覆盖原 APK 的 classes*.dex（zip 工具）→ 删 META-INF/* 旧签名 →",
        "zipalign -f 4 in.apk aligned.apk",
        "apksigner sign --ks debug.keystore --ks-pass pass:android --ks-key-alias androiddebugkey aligned.apk",
        "adb uninstall <package> && adb install -r -t -g aligned.apk",
    ]


def _resolve_package_name(apk_path: str) -> str:
    from apkscan.core.apk import load_apk

    ctx = load_apk(apk_path, AnalysisConfig(online=False))
    return ctx.package_name or ""


# ---------------------------------------------------------------------------
# DEX 收集 + 映射
# ---------------------------------------------------------------------------


def _collect_dump_dex(out_dir: str) -> list[Path]:
    """收 out_dir/dump 下所有 *.dex（递归，排序稳定）。复用 unpack 同款 rglob。"""
    dump_dir = Path(out_dir) / "dump"
    if not dump_dir.is_dir():
        return []
    return sorted(dump_dir.rglob("*.dex"))


def _is_dex(path: Path) -> bool:
    """校验 dex magic（前 4 字节 b"dex\\n"）。读失败 → False，不抛。"""
    try:
        with open(path, "rb") as f:
            return f.read(4) == _DEX_MAGIC
    except OSError:
        logger.debug("[repack] 读取 dex magic 失败：%s", path, exc_info=True)
        return False


def _map_dump_to_classes(dump_dex: list[Path]) -> dict[Path, str] | None:
    """把脱壳 DEX 映射为 classes.dex / classes2.dex ...（启发式：最大者作主 classes.dex）。

    校验 dex magic，过滤非 DEX；无有效 DEX → None（由 run 判 error，绝不强拼）。
    顺序：按文件大小降序（主 dex 通常最大）作 classes.dex / classes2.dex ...——映射错则装上即崩，
    由四联判定兜住并降级，不假成功。
    """
    valid = [p for p in dump_dex if _is_dex(p)]
    if not valid:
        return None
    try:
        valid.sort(key=lambda p: p.stat().st_size, reverse=True)
    except OSError:
        logger.debug("[repack] 按大小排序 DEX 失败，退回名称序", exc_info=True)
        valid = sorted(valid)
    mapping: dict[Path, str] = {}
    for i, p in enumerate(valid):
        mapping[p] = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
    return mapping


def _replace_dex_in_zip(base_apk: Path, mapping: dict[Path, str], out_apk: Path) -> None:
    """用映射后的脱壳 DEX 覆盖原 APK 的 classes*.dex，删旧签名 META-INF/*，其余原样保留。

    新签名由后续 apksigner 重签生成。异常上抛由调用方转 error。
    """
    new_names = set(mapping.values())
    with zipfile.ZipFile(base_apk, "r") as zin, zipfile.ZipFile(
        out_apk, "w", zipfile.ZIP_DEFLATED
    ) as zout:
        for item in zin.infolist():
            name = item.filename
            # 跳过：要替换的 classes*.dex、所有 classes*.dex（避免残留多余旧 dex）、旧签名。
            low = name.lower()
            if low in new_names or (low.startswith("classes") and low.endswith(".dex")):
                continue
            if name.startswith("META-INF/") and (
                low.endswith(".sf") or low.endswith(".rsa") or low.endswith(".dsa")
                or low.endswith(".ec") or low == "meta-inf/manifest.mf"
            ):
                continue
            zout.writestr(item, zin.read(name))
        # 写入新 DEX。
        for src, arc in mapping.items():
            zout.writestr(arc, src.read_bytes())


# ---------------------------------------------------------------------------
# zipalign / 重签
# ---------------------------------------------------------------------------


def _zipalign(src: Path, dst: Path, playbook: list[str]) -> str | None:
    """zipalign -f 4 src dst。成功返回 None；失败返回错误原因串。"""
    inv = tools.resolve_zipalign()
    if inv is None:
        return "zipalign 不可用"
    cmd, env = inv
    args = [*cmd, "-f", "4", str(src), str(dst)]
    playbook.append(f"zipalign -f 4 {src.name} {dst.name}")
    rc, tail = _run_tool(args, env)
    if rc != 0 or not dst.is_file():
        return f"zipalign 失败（rc={rc}）：{tail.strip()}"
    return None


def _ensure_keystore_and_sign(src: Path, dst: Path, playbook: list[str]) -> str | None:
    """确保 debug keystore 存在（首次 keytool 生成并缓存）→ apksigner 重签 + verify。

    成功返回 None；失败返回错误原因串。
    """
    ks_err = _ensure_debug_keystore()
    if ks_err:
        return ks_err
    shutil.copyfile(src, dst)
    sign = tools.resolve_apksigner()
    if sign is None:
        return "apksigner 不可用"
    cmd, env = sign
    sign_args = [
        *cmd, "sign", "--ks", str(_KEYSTORE_PATH), "--ks-pass", f"pass:{_KS_PASS}",
        "--ks-key-alias", _KS_ALIAS, "--key-pass", f"pass:{_KS_PASS}", str(dst),
    ]
    playbook.append(f"apksigner sign --ks <debug.keystore> {dst.name}")
    rc, tail = _run_tool(sign_args, env)
    if rc != 0:
        return f"apksigner 重签失败（rc={rc}）：{tail.strip()}"
    # verify 二次确认签名有效。
    rc2, tail2 = _run_tool([*cmd, "verify", str(dst)], env)
    if rc2 != 0:
        return f"apksigner verify 未通过（rc={rc2}）：{tail2.strip()}"
    return None


def _ensure_debug_keystore() -> str | None:
    """首次用 keytool 生成 debug keystore 并缓存到 ~/.apkscan/，之后复用。失败返回原因串。"""
    if _KEYSTORE_PATH.is_file():
        return None
    inv = tools.resolve_keytool()
    if inv is None:
        return "keytool 不可用（JDK 自带；用于首次生成 debug keystore）"
    _KEYSTORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    cmd, env = inv
    args = [
        *cmd, "-genkeypair", "-v", "-keystore", str(_KEYSTORE_PATH), "-storepass", _KS_PASS,
        "-keypass", _KS_PASS, "-alias", _KS_ALIAS, "-keyalg", "RSA", "-keysize", "2048",
        "-validity", "10000", "-dname", "CN=fxapk-repack-debug",
    ]
    rc, tail = _run_tool(args, env)
    if rc != 0 or not _KEYSTORE_PATH.is_file():
        return f"生成 debug keystore 失败（rc={rc}）：{tail.strip()}"
    return None


def _run_tool(args: list[str], extra_env: dict[str, str] | None = None) -> tuple[int, str]:
    """跑外部工具：stdout/stderr 重定向到临时文件（不用 PIPE，避免 Java 孙进程持管道卡死）+
    timeout + stdin=DEVNULL。返回 (returncode, 输出尾部)。超时/异常 → (非0, 原因)，绝不抛。
    """
    env = None
    if extra_env:
        env = {**os.environ, **extra_env}
    fd, log_path = tempfile.mkstemp(prefix="apkscan_repack_", suffix=".log")
    try:
        try:
            with open(fd, "w", encoding="utf-8", errors="replace") as log_fh:
                proc = subprocess.run(
                    args, stdout=log_fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                    env=env, timeout=_TOOL_TIMEOUT, check=False,
                )
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            logger.warning("[repack] 工具超时（%ss）：%s", _TOOL_TIMEOUT, args[0])
            return 1, f"工具超时（{_TOOL_TIMEOUT}s）"
        except OSError as exc:
            logger.warning("[repack] 工具执行失败：%s（%s）", args[0], exc)
            return 1, f"工具执行失败：{exc}"
        tail = _read_tail(log_path)
        return rc, tail
    finally:
        try:
            Path(log_path).unlink(missing_ok=True)
        except OSError:
            logger.debug("[repack] 清理工具日志失败：%s", log_path, exc_info=True)


def _read_tail(log_path: str, limit: int = _STDOUT_TAIL) -> str:
    try:
        return Path(log_path).read_text(encoding="utf-8", errors="replace")[-limit:]
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# 四联判定 + 降级
# ---------------------------------------------------------------------------


def _verdict_app_alive(package: str, serial: str | None) -> tuple[bool, str]:
    """去壳真伪四联判定：am start → 宽限后进程存活(非秒退) → frida 可附（+best-effort logcat FATAL）。

    全过 (True, 说明)；任一不过 (False, 失败关+疑因)。绝不抛（探测失败按不通过保守处理）。
    install Success 由调用方在此之前已确认。
    """
    try:
        _adb(["shell", "am", "start", "-n", f"{package}/.MainActivity"], serial)  # best-effort
        _adb(["shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"], serial)
        time.sleep(_SPAWN_GRACE)
        if not _process_alive(package, serial):
            return False, "进程未存活（秒退/未起来）"
        if _logcat_has_fatal(package, serial):
            return False, "logcat 见 FATAL/崩溃（壳入口未改回或完整性自校验自杀）"
        if not _frida_attachable(package, serial):
            return False, "frida 无法附加（反 frida / 进程已死）"
        return True, "进程存活且 frida 可附"
    except Exception:  # noqa: BLE001 — 判定层绝不抛；探测异常保守判不通过
        logger.exception("[repack] 存活判定异常，保守判不通过")
        return False, "存活判定异常"


def _adb(sub: list[str], serial: str | None) -> str:
    """跑 adb 子命令返回 stdout（best-effort，失败返空串，不抛）。"""
    from apkscan.core.tools import adb_path

    exe = adb_path()
    if not exe:
        return ""
    args = [exe]
    if serial:
        args += ["-s", serial]
    args += sub
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=15.0, check=False,
        )
        return proc.stdout or ""
    except (subprocess.TimeoutExpired, OSError):
        logger.debug("[repack] adb 子命令失败：%s", sub, exc_info=True)
        return ""


def _process_alive(package: str, serial: str | None) -> bool:
    """设备上目标进程是否存活（pidof 优先，回退 ps 匹配包名）。"""
    pid = _adb(["shell", "pidof", package], serial).strip()
    if pid:
        return True
    return package in _adb(["shell", "ps", "-A"], serial)


def _logcat_has_fatal(package: str, serial: str | None) -> bool:
    """best-effort 读 logcat 看是否有该包的 FATAL EXCEPTION / 致命崩溃迹象。"""
    out = _adb(["logcat", "-d", "-t", "200"], serial)
    if not out:
        return False
    for line in out.splitlines():
        if "FATAL EXCEPTION" in line or "E AndroidRuntime" in line:
            if package in out:  # 粗匹配：该包出现在近期 logcat 且有 FATAL
                return True
    return False


def _frida_attachable(package: str, serial: str | None) -> bool:
    """frida-ps 是否能在设备进程列表里见到该包（可附的近似判定）。"""
    inv = tools.frida_invocation("frida-ps")
    if not inv:
        return False
    args = [*inv, "-D", serial] if serial else [*inv, "-U"]
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=20.0, check=False,
        )
        return proc.returncode == 0 and package in (proc.stdout or "")
    except (subprocess.TimeoutExpired, OSError):
        logger.debug("[repack] frida-ps 探测失败", exc_info=True)
        return False


def _degrade_reinstall_original(apk_path: str, package: str, serial: str | None) -> None:
    """降级兜底：重装原 APK，保证设备上有可 spawn 目标（capture 仍跑原版）。best-effort。"""
    try:
        from apkscan.dynamic import provision

        device.force_stop_app(package, serial)
        provision.uninstall_app(package, serial=serial)
        provision.install_apk(apk_path, serial=serial)
        logger.info("[repack] 已降级重装原 APK：%s", package)
    except Exception:  # noqa: BLE001 — 降级兜底失败也不抛
        logger.exception("[repack] 降级重装原 APK 失败（capture 可能无目标）")


__all__ = ["run"]
