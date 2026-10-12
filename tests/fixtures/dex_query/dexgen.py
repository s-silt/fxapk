"""可复现的 DEX 035 生成器。

独立金标来自本文件声明的字符串池和 const-string 指令字节位置。
它不调用 ASC，也不调用 JADX。
"""

from __future__ import annotations

import hashlib
import io
import struct
import zlib
import zipfile
from dataclasses import dataclass


def _uleb(value: int) -> bytes:
    if value < 0:
        raise ValueError("uleb128 不接受负数")
    out = bytearray()
    while True:
        piece = value & 0x7F
        value >>= 7
        if value:
            out.append(piece | 0x80)
        else:
            out.append(piece)
            return bytes(out)


def _utf16_units(text: str) -> int:
    return sum(2 if ord(char) > 0xFFFF else 1 for char in text)


def mutf8(text: str) -> bytes:
    """DEX string_data_item 的 MUTF-8。BMP 与 UTF-8 相同，补充平面用 CESU-8。"""
    out = bytearray()
    for char in text:
        code = ord(char)
        if code == 0:
            out += b"\xc0\x80"
        elif code < 0x80:
            out.append(code)
        elif code < 0x800:
            out.append(0xC0 | (code >> 6))
            out.append(0x80 | (code & 0x3F))
        elif code < 0x10000:
            out.append(0xE0 | (code >> 12))
            out.append(0x80 | ((code >> 6) & 0x3F))
            out.append(0x80 | (code & 0x3F))
        else:
            code -= 0x10000
            for unit in (0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF)):
                out.append(0xE0 | (unit >> 12))
                out.append(0x80 | ((unit >> 6) & 0x3F))
                out.append(0x80 | (unit & 0x3F))
    return bytes(out)


def _align(blob: bytearray, size: int = 4) -> None:
    while len(blob) % size:
        blob.append(0)


@dataclass(frozen=True)
class DexMethodSpec:
    name: str
    params: tuple[str, ...]
    return_type: str
    string: str
    registers: int = 2


@dataclass(frozen=True)
class DexClassSpec:
    descriptor: str
    methods: tuple[DexMethodSpec, ...]
    superclass: str = "Ljava/lang/Object;"


@dataclass(frozen=True)
class ExpectedHit:
    descriptor: str
    string: str
    file_offset: int
    code_unit_offset: int


@dataclass(frozen=True)
class BuiltDex:
    data: bytes
    sha256: str
    version: str
    hits: tuple[ExpectedHit, ...]
    strings: tuple[str, ...]


def _string_item(text: str) -> bytes:
    payload = mutf8(text)
    return _uleb(_utf16_units(text)) + payload + b"\x00"


def build_dex(
    classes: tuple[DexClassSpec, ...],
    *,
    version: str = "035",
    extra_strings: tuple[str, ...] = (),
) -> BuiltDex:
    """生成一份结构合法的 DEX。version 只改魔数，041 不会被补成可查询的 035。"""
    if len(version) != 3 or not version.isdigit():
        raise ValueError("DEX 版本必须是三位数字")
    strings: list[str] = []

    def add_string(text: str) -> None:
        if text not in strings:
            strings.append(text)

    def shorty_text(return_type: str, params: tuple[str, ...]) -> str:
        def one(descriptor: str) -> str:
            while descriptor.startswith("["):
                descriptor = descriptor[1:]
            if descriptor.startswith("L"):
                return "L"
            return descriptor[:1]

        return one(return_type) + "".join(one(param) for param in params)

    for item in extra_strings:
        add_string(item)
    for clazz in classes:
        add_string(clazz.descriptor)
        add_string(clazz.superclass)
        for method in clazz.methods:
            add_string(method.name)
            add_string(method.return_type)
            add_string(shorty_text(method.return_type, method.params))
            add_string(method.string)
            for param in method.params:
                add_string(param)
    strings.sort()
    string_index = {text: index for index, text in enumerate(strings)}

    types = sorted({
        clazz.descriptor for clazz in classes
    } | {
        clazz.superclass for clazz in classes
    } | {
        method.return_type for clazz in classes for method in clazz.methods
    } | {
        param for clazz in classes for method in clazz.methods for param in method.params
    })
    type_index = {text: index for index, text in enumerate(types)}

    protos: list[tuple[str, str, tuple[str, ...]]] = []
    for clazz in classes:
        for method in clazz.methods:
            # shorty 稍后按参数重算，这里只保留唯一 (return, params)
            key = (method.return_type, method.params)
            if key not in [(item[0], item[2]) for item in protos]:
                protos.append((method.return_type, "", method.params))
    proto_index = {(item[0], item[2]): index for index, item in enumerate(protos)}

    methods: list[tuple[str, str, tuple[str, ...], str]] = []
    for clazz in classes:
        for method in clazz.methods:
            methods.append((clazz.descriptor, method.name, method.params, method.return_type))
    methods.sort(key=lambda item: (
        type_index[item[0]], string_index[item[1]], proto_index[(item[3], item[2])],
    ))

    # 先排好 ID 区大小，数据区偏移在 header 之后确定。
    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * len(strings)
    proto_ids_off = type_ids_off + 4 * len(types)
    method_ids_off = proto_ids_off + 12 * len(protos)
    class_defs_off = method_ids_off + 8 * len(methods)
    data_off = class_defs_off + 32 * len(classes)
    blob = bytearray(data_off)

    # string data 必须按 string_id 顺序紧挨着，ASC 的 locator 用下一串起点回推。
    string_data = bytearray()
    string_offs: list[int] = []
    for text in strings:
        string_offs.append(data_off + len(string_data))
        string_data += _string_item(text)
    blob += string_data
    _align(blob)

    type_list_off: dict[tuple[str, ...], int] = {}
    for _return_type, _short, params in protos:
        if not params or params in type_list_off:
            continue
        _align(blob)
        type_list_off[params] = len(blob)
        blob += struct.pack("<I", len(params))
        for param in params:
            blob += struct.pack("<H", type_index[param])
        _align(blob)

    hits: list[ExpectedHit] = []
    code_off_by_method: dict[tuple[str, str, tuple[str, ...], str], int] = {}
    for clazz in classes:
        for method in clazz.methods:
            _align(blob)
            code_off = len(blob)
            key = (clazz.descriptor, method.name, method.params, method.return_type)
            code_off_by_method[key] = code_off
            insns = bytearray()
            insns += struct.pack("<BBH", 0x1A, 0, string_index[method.string])
            insns += struct.pack("<BB", 0x11, 0)
            file_offset = code_off + 16
            params_desc = "".join(method.params)
            descriptor = (
                f"{clazz.descriptor}->{method.name}({params_desc}){method.return_type}"
            )
            hits.append(ExpectedHit(descriptor, method.string, file_offset, 0))
            blob += struct.pack(
                "<HHHHII",
                method.registers,
                len(method.params),
                0,
                0,
                0,
                len(insns) // 2,
            )
            blob += insns

    class_data_off: dict[str, int] = {}
    for clazz in classes:
        class_data_off[clazz.descriptor] = len(blob)
        direct = [
            method for method in clazz.methods
        ]
        encoded = bytearray()
        encoded += _uleb(0) + _uleb(0) + _uleb(len(direct)) + _uleb(0)
        previous = 0
        ordered = sorted(
            direct,
            key=lambda method: methods.index(
                (clazz.descriptor, method.name, method.params, method.return_type)
            ),
        )
        for method in ordered:
            index = methods.index(
                (clazz.descriptor, method.name, method.params, method.return_type)
            )
            encoded += _uleb(index - previous)
            encoded += _uleb(0x0001 | 0x0008)  # public static
            encoded += _uleb(code_off_by_method[
                (clazz.descriptor, method.name, method.params, method.return_type)
            ])
            previous = index
        blob += encoded

    _align(blob)
    map_off = len(blob)
    map_items: list[tuple[int, int, int]] = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_ids_off),
        (0x0002, len(types), type_ids_off),
        (0x0003, len(protos), proto_ids_off),
        (0x0005, len(methods), method_ids_off),
        (0x0006, len(classes), class_defs_off),
        (0x1000, 1, map_off),
        (0x2002, len(strings), string_offs[0] if string_offs else 0),
        (0x2001, len(methods), min(code_off_by_method.values()) if code_off_by_method else 0),
        (0x2000, len(classes), min(class_data_off.values()) if class_data_off else 0),
    ]
    if type_list_off:
        map_items.append((0x1001, len(type_list_off), min(type_list_off.values())))
    blob += struct.pack("<I", len(map_items))
    for item_type, size, offset in map_items:
        blob += struct.pack("<HHII", item_type, 0, size, offset)

    def put(offset: int, data: bytes) -> None:
        blob[offset:offset + len(data)] = data

    for index, text in enumerate(strings):
        put(string_ids_off + 4 * index, struct.pack("<I", string_offs[index]))
    for index, text in enumerate(types):
        put(type_ids_off + 4 * index, struct.pack("<I", string_index[text]))
    for index, (return_type, _unused, params) in enumerate(protos):
        put(proto_ids_off + 12 * index, struct.pack(
            "<III",
            string_index[shorty_text(return_type, params)],
            type_index[return_type],
            type_list_off.get(params, 0),
        ))
    for index, (class_desc, name, params, return_type) in enumerate(methods):
        put(method_ids_off + 8 * index, struct.pack(
            "<HHI",
            type_index[class_desc],
            proto_index[(return_type, params)],
            string_index[name],
        ))
    for index, clazz in enumerate(classes):
        put(class_defs_off + 32 * index, struct.pack(
            "<IIIIIIII",
            type_index[clazz.descriptor],
            0x0001,
            type_index[clazz.superclass],
            0,
            0xFFFFFFFF,
            0,
            class_data_off[clazz.descriptor],
            0,
        ))

    file_size = len(blob)
    data_size = file_size - data_off
    put(0, b"dex\n" + version.encode("ascii") + b"\x00")
    put(8, b"\x00" * 24)  # checksum + signature, filled below
    put(32, struct.pack(
        "<IIIIIIIIIIIIIIIIII",
        file_size,
        header_size,
        0x12345678,
        0,
        0,
        map_off,
        len(strings),
        string_ids_off,
        len(types),
        type_ids_off,
        len(protos),
        proto_ids_off,
        0,
        0,
        len(methods),
        method_ids_off,
        len(classes),
        class_defs_off,
    ))
    # header 从 0x20 起还有 data_size/data_off。上面的 18 个 I 正好到 0x68，缺 8 字节。
    put(0x68, struct.pack("<II", data_size, data_off))
    signature = hashlib.sha1(blob[32:]).digest()
    put(12, signature)
    put(8, struct.pack("<I", zlib.adler32(blob[12:]) & 0xFFFFFFFF))
    data = bytes(blob)
    return BuiltDex(data, hashlib.sha256(data).hexdigest(), version, tuple(hits), tuple(strings))


def sample_classes(token: str = "xref-token-example") -> tuple[DexClassSpec, ...]:
    """一个类上的两个 lookup 重载，descriptor 必须能分开。"""
    return (
        DexClassSpec(
            "Lexample/invalid/Q;",
            (
                DexMethodSpec("lookup", ("Ljava/lang/String;",), "Ljava/lang/String;", token),
                DexMethodSpec("lookup", ("I",), "Ljava/lang/String;", token),
            ),
        ),
    )


def wide_classes() -> tuple[DexClassSpec, ...]:
    token = "xref-token-\U0001F4A1"
    return (
        DexClassSpec(
            "Lexample/invalid/Wide;",
            (DexMethodSpec("read", ("Ljava/lang/String;",), "Ljava/lang/String;", token),),
        ),
    )


def zip_bytes(members: list[tuple[str, bytes]], *, compress: bool = True) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in members:
            info = zipfile.ZipInfo(name)
            info.flag_bits = 0x800
            archive.writestr(
                info,
                payload,
                compress_type=zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED,
            )
    return buffer.getvalue()


def flip_central_crc(archive: bytes) -> bytes:
    """只改中央目录 CRC，不动文件数据，也不重写原件。"""
    blob = bytearray(archive)
    if blob[-22:-18] != b"PK\x05\x06":
        raise ValueError("只处理无注释的 ZIP")
    cd_off = struct.unpack_from("<I", blob, len(blob) - 6)[0]
    if blob[cd_off:cd_off + 4] != b"PK\x01\x02":
        raise ValueError("中央目录无效")
    struct.pack_into("<I", blob, cd_off + 16, struct.unpack_from("<I", blob, cd_off + 16)[0] ^ 0xFF)
    return bytes(blob)


def declared_bomb(name: str = "classes.dex") -> bytes:
    """中央目录声明超大解压尺寸，本地数据只有几个字节。调用方必须在解压前拒绝。"""
    local_name = name.encode("utf-8")
    payload = b"dex\n035\x00"
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        0,
        0,
        0,
        0,
        zlib.crc32(payload) & 0xFFFFFFFF,
        len(payload),
        64 * 1024 * 1024,
        len(local_name),
        0,
    ) + local_name + payload
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        0,
        0,
        0,
        0,
        zlib.crc32(payload) & 0xFFFFFFFF,
        len(payload),
        64 * 1024 * 1024,
        len(local_name),
        0,
        0,
        0,
        0,
        0,
        0,
    ) + local_name
    cd_off = len(local)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), cd_off, 0)
    return local + central + eocd
