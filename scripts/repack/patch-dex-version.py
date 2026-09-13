#!/usr/bin/env python3
"""
patch-dex-version.py — 修复 apktool 回编降级 dex 版本导致的
IncompatibleClassChangeError 闪退(报错十八)。

背景(报错十八):
  apktool/smali 回编不按 minSdk 选择 dex 版本,一律写 035。
  原包(minSdk=27+)的 dex 是 038,内含接口 static/bridge 方法
  (如 Compose 的 DrawScope.drawRect-*$default)——该语法仅 038+
  语义合法。035 头让新 ART 按旧接口规则校验 → ICCE → 首帧闪退。
  内容级对比证实回编零差异,唯一变化就是 dex 头版本字符串。

通用策略(不依赖具体 App,对任意 minSdk/任意原包版本成立):
  1. save 模式: 解包阶段扫描原 APK,把每个 dex 的原始版本记录到
     <解包目录>/dex-versions.json(此信息回编后会丢失,必须先存);
  2. restore 模式: 回编后逐 dex 恢复 —— **只升不降**:
       target = max(原版本, minSdk 推导版本)
     - 原包 038 的 dex 恢复 038(即使 minSdk 再低也不降,保住
       desugaring 产物可能依赖的接口新语义);
     - 原包 035/无记录的 dex 补到 minSdk 推导值(防 smali 写头偏低)。
  dex 版本向后兼容(高版本读者可读低版本内容),只升不降是安全的。

CLI 契约(模块化契约: <子命令> <文件> <目录>):
  save    <输入.apk> <解包目录>      — 解包后立即记录各 dex 原始版本
  restore <回编产物.apk> <解包目录>  — 回编后恢复(同路径原地改)
"""

import sys
import zipfile
import shutil
import json
import io
import os

DEX_VERSIONS = ["035", "036", "037", "038", "039", "040"]  # 升序
_ORDER = {v: i for i, v in enumerate(DEX_VERSIONS)}


def dcc_dir():
    """dcc 内置 androguard 的路径(与 common.sh ensure_dcc 解压位置一致: <仓库根>/tools/dcc)。

    报错二十九: 本路径曾写死 <仓库根>/build/dcc/dcc;dcc 分发从 build/dcc 迁到 tools/dcc 时
    漏改此处(路径写成 os.path.join(root, "build", "dcc", "dcc"),不含连续字面量 "build/dcc",
    全仓 grep 搜不到),restore 阶段 sys.path 插入不存在的目录 → `import androguard`
    ModuleNotFoundError。改动此文件时务必与 common.sh ensure_dcc 的目标位置保持一致。
    """
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(root, "tools", "dcc")


def minsdk_to_dex_version(min_sdk: int) -> str:
    """按 minSdkVersion 推导 dex 版本下限(dex format 官方对应)。"""
    if min_sdk >= 30:
        return "039"
    if min_sdk >= 26:
        return "038"
    if min_sdk >= 24:
        return "037"
    return "035"


def read_manifest_min_sdk(apk_path: str) -> int:
    d = dcc_dir()
    # fail-fast: 路径写错时给出可诊断错误,而不是 sys.path 静默忽略不存在的目录后
    # 抛出看不懂的 ModuleNotFoundError(报错二十九的暴露形态)。
    if not os.path.isfile(os.path.join(d, "androguard", "core", "bytecodes", "apk.py")):
        raise FileNotFoundError(
            f"dcc 内置 androguard 缺失: {d};请确认 tools/dcc.zip 已解压(见 common.sh ensure_dcc)")
    sys.path.insert(0, d)
    from androguard.core.bytecodes.apk import APK
    a = APK(apk_path)
    return int(a.get_min_sdk_version() or 1)


def dex_version(data: bytes):
    """dex 头第 4~7 字节,如 b'035\\x00' → '035';非 dex/异常版本返回 None。"""
    if len(data) > 8 and data[:3] == b"dex" and data[7:8] == b"\0":
        v = data[4:7].decode("ascii", "replace")
        return v if v in _ORDER else None
    return None


def cmd_save(apk_path: str, decompiled_dir: str) -> int:
    """解包阶段: 记录原 APK 每个 dex 的真实版本。"""
    versions = {}
    with zipfile.ZipFile(apk_path) as z:
        for name in z.namelist():
            if name.endswith(".dex"):
                v = dex_version(z.read(name))
                if v:
                    versions[name] = v
    out = os.path.join(decompiled_dir, "dex-versions.json")
    with open(out, "w") as f:
        json.dump(versions, f, indent=1)
    print(f"patch-dex-version: 已记录 {len(versions)} 个 dex 的原始版本 -> {out}")
    return 0


def cmd_restore(apk_path: str, decompiled_dir: str) -> int:
    """回编后: 逐 dex 恢复 max(原始版本, minSdk 下限)。同路径原地改。"""
    rec_path = os.path.join(decompiled_dir, "dex-versions.json")
    saved = {}
    if os.path.exists(rec_path):
        with open(rec_path) as f:
            saved = json.load(f)

    minsdk = read_manifest_min_sdk(apk_path)
    floor = minsdk_to_dex_version(minsdk)  # 无记录时的兜底下限

    with open(apk_path, "rb") as f:
        src = io.BytesIO(f.read())  # 全量进内存再写,避免自读自写截断

    buf = io.BytesIO()
    patched, kept = 0, 0
    with zipfile.ZipFile(src) as zin, \
         zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename.endswith(".dex"):
                cur = dex_version(data)
                if cur:
                    orig = saved.get(item.filename)
                    # target = max(原版本, floor);原版本缺失则 floor
                    target = max(orig, floor, key=lambda v: _ORDER[v]) if orig else floor
                    if cur != target:
                        data = data[:4] + target.encode() + b"\0" + data[8:]
                        patched += 1
                        print(f"  {item.filename}: {cur} -> {target}"
                              f"  (原始={orig or '无记录'}, minSdk={minsdk})")
                    else:
                        kept += 1
            zout.writestr(item, data)

    tmp = apk_path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(buf.getvalue())
    shutil.move(tmp, apk_path)
    print(f"patch-dex-version: 回填 {patched} 个,保持 {kept} 个 (minSdk={minsdk}, 下限={floor})")
    return 0


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("save", "restore"):
        print(__doc__)
        sys.exit(2)
    mode, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
    sys.exit(cmd_save(a, b) if mode == "save" else cmd_restore(a, b))


if __name__ == "__main__":
    main()
