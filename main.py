import base64
import io
import sys
import magic
import pathlib
import os
import glob
import mutagen
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from mutagen.easyid3 import ID3
from wasmer import Store, Module, Instance, Uint8Array, Int32Array, engine
from wasmer_compiler_cranelift import Compiler


class XMInfo:
    def __init__(self):
        self.title = ""
        self.artist = ""
        self.album = ""
        self.tracknumber = 0
        self.size = 0
        self.header_size = 0
        self.ISRC = ""
        self.encodedby = ""
        self.encoding_technology = ""

    def iv(self):
        if self.ISRC != "":
            return bytes.fromhex(self.ISRC)
        return bytes.fromhex(self.encodedby)


def get_str(x):
    if x is None:
        return ""
    return x


def read_file(x):
    with open(x, "rb") as f:
        return f.read()


# return number of id3 bytes
def get_xm_info(data: bytes):
    # print(EasyID3(io.BytesIO(data)))
    id3 = ID3(io.BytesIO(data), v2_version=3)
    id3value = XMInfo()
    id3value.title = str(id3["TIT2"])
    id3value.album = str(id3["TALB"])
    id3value.artist = str(id3["TPE1"])
    id3value.tracknumber = int(str(id3["TRCK"]))
    id3value.ISRC = "" if id3.get("TSRC") is None else str(id3["TSRC"])
    id3value.encodedby = "" if id3.get("TENC") is None else str(id3["TENC"])
    id3value.size = int(str(id3["TSIZ"]))
    id3value.header_size = id3.size
    id3value.encoding_technology = str(id3["TSSE"])
    return id3value


def get_printable_count(x: bytes):
    i = 0
    for i, c in enumerate(x):
        # all pritable
        if c < 0x20 or c > 0x7e:
            return i
    return i


def get_printable_bytes(x: bytes):
    return x[:get_printable_count(x)]


def xm_decrypt(raw_data):
    # load xm encryptor
    # print("loading xm encryptor")
    xm_encryptor = Instance(Module(
        Store(engine.Universal(Compiler)),
        pathlib.Path("./xm_encryptor.wasm").read_bytes()
    ))
    # decode id3
    xm_info = get_xm_info(raw_data)
    # print("id3 header size: ", hex(xm_info.header_size))
    encrypted_data = raw_data[xm_info.header_size:xm_info.header_size + xm_info.size:]

    # Stage 1 aes-256-cbc
    xm_key = b"ximalayaximalayaximalayaximalaya"
    # print(f"decrypt stage 1 (aes-256-cbc):\n"
    #       f"    data length = {len(encrypted_data)},\n"
    #       f"    key = {xm_key},\n"
    #       f"    iv = {xm_info.iv().hex()}")
    cipher = AES.new(xm_key, AES.MODE_CBC, xm_info.iv())
    de_data = cipher.decrypt(pad(encrypted_data, 16))
    # print("success")
    # Stage 2 xmDecrypt
    de_data = get_printable_bytes(de_data)
    track_id = str(xm_info.tracknumber).encode()
    stack_pointer = xm_encryptor.exports.a(-16)
    assert isinstance(stack_pointer, int)
    de_data_offset = xm_encryptor.exports.c(len(de_data))
    assert isinstance(de_data_offset, int)
    track_id_offset = xm_encryptor.exports.c(len(track_id))
    assert isinstance(track_id_offset, int)
    memory_i = xm_encryptor.exports.i
    memview_unit8: Uint8Array = memory_i.uint8_view(offset=de_data_offset)
    for i, b in enumerate(de_data):
        memview_unit8[i] = b
    memview_unit8: Uint8Array = memory_i.uint8_view(offset=track_id_offset)
    for i, b in enumerate(track_id):
        memview_unit8[i] = b
    # print(bytearray(memory_i.buffer)[track_id_offset:track_id_offset + len(track_id)].decode())
    # print(f"decrypt stage 2 (xmDecrypt):\n"
    #       f"    stack_pointer = {stack_pointer},\n"
    #       f"    data_pointer = {de_data_offset}, data_length = {len(de_data)},\n"
    #       f"    track_id_pointer = {track_id_offset}, track_id_length = {len(track_id)}")
    # print("success")
    xm_encryptor.exports.g(stack_pointer, de_data_offset, len(de_data), track_id_offset, len(track_id))
    memview_int32: Int32Array = memory_i.int32_view(offset=stack_pointer // 4)
    result_pointer = memview_int32[0]
    result_length = memview_int32[1]
    assert memview_int32[2] == 0, memview_int32[3] == 0
    result_data = bytearray(memory_i.buffer)[result_pointer:result_pointer + result_length].decode()
    # Stage 3 combine
    # print(f"Stage 3 (base64)")
    decrypted_data = base64.b64decode(xm_info.encoding_technology + result_data)
    final_data = decrypted_data + raw_data[xm_info.header_size + xm_info.size::]
    # print("success")
    return xm_info, final_data


def find_ext(data):
    exts = ["m4a", "mp3", "flac", "wav"]
    value = magic.from_buffer(data).lower()
    for ext in exts:
        if ext in value:
            return ext
    raise Exception(f"unexpected format {value}")


def decrypt_xm_file(from_file, output=''):
    print(f"正在解密{from_file}")
    data = read_file(from_file)
    info, audio_data = xm_decrypt(data)
    if output == "":
        output = f"./output/{info.album}/{info.title}.{find_ext(audio_data[:0xff])}"
    if not os.path.exists(f"./output/{info.album}"):
        os.makedirs(f"./output/{info.album}")
    buffer = io.BytesIO(audio_data)
    tags = mutagen.File(buffer, easy=True)
    tags["title"] = info.title
    tags["album"] = info.album
    tags["artist"] = info.artist
    print(tags.pprint())
    tags.save(buffer)
    with open(output, "wb") as f:
        buffer.seek(0)
        f.write(buffer.read())
    print(f"解密成功，文件保存至{output}！")


if __name__ == "__main__":
    while True:
        print("欢迎使用喜马拉雅音频解密工具")
        print("本工具仅供学习交流使用，严禁用于商业用途")
        print("请选择您想要使用的功能：")
        print("1. 解密单个文件")
        print("2. 批量解密文件")
        print("3. 退出")
        choice = input()
        if choice == "1":
            while True:
                print("请输入需要解密的文件路径：")
                file_to_decrypt = input()
                if not os.path.exists(file_to_decrypt):
                    print("您输入文件不存在，请重新输入！")
                elif not os.path.isfile(file_to_decrypt):
                    print("您输入的不是一个合法的文件目录，请重新输入！")
                else:
                    decrypt_xm_file(file_to_decrypt)
                    break
        elif choice == "2":
            while True:
                print("请输入包含需要解密的文件的文件夹路径：")
                dir_to_decrypt = input()
                if not os.path.exists(dir_to_decrypt):
                    print("您输入的文件夹不存在，请重新输入！")
                elif not os.path.isdir(dir_to_decrypt):
                    print("您输入的不是一个合法的文件夹目录，请重新输入！")
                else:
                    files_to_decrypt = glob.glob(os.path.join(dir_to_decrypt, "*" + ".xm"))
                    for file_to_decrypt in files_to_decrypt:
                        decrypt_xm_file(file_to_decrypt)
                    break
        elif choice == "3":
            sys.exit()
        else:
            print("输入错误，请重新输入！")
