import os
import struct

EndLocatorMagic = 0x06054b50
ApkSignBlockMagic = "APK Sig Block 42"
ApkSignBlockV2ID = 0x7109871a
ApkSignBlockV3ID = 0xf05368c0
ApkSignBlockPaddingID = 0x42726577
PageAlignmentBytes = 4096

DebugLog = False

# cache, for speedup.
ApkFilePathCache = ''
DirectoryOffsetCache = -1
EndLocatorOffsetCache = -1
SignBlockOffsetCache = -1


def _print_log(log):
    if DebugLog:
        print(log)


def _calculation_add_pairs_length(values):
    le = len(values)
    length = 0
    for i in range(le):
        # add pair size.
        length = length + 8
        # add id size.
        length = length + 4
        # add value size.
        length += len(values[i])
    return length


def _parse_zip_central_offset(file, file_path):
    """
    struct EndLocator
    {
        ui32 signature;             // 目录结束标记（固定值 0x06054b50）。
        ui16 elDiskNumber;          // 当前磁盘编号。
        ui16 elStartDiskNumber;     // 中央目录开始位置的磁盘编号。
        ui16 elEntriesOnDisk;       // 该磁盘上所记录的核心目录数量。
        ui16 elEntriesInDirectory;  // 中央目录结构总数。
        ui32 elDirectorySize;       // 中央目录的大小。
        ui32 elDirectoryOffset;     // 中央目录开始位置相对于文件头的偏移。
        ui16 elCommentLen;          // 注释长度。
        char *elComment;            // 注释内容。
    };
    """
    file_size = os.path.getsize(file_path)
    _print_log('apk file size: %d' % file_size)
    for i in range(file_size - 4, 0, -1):
        file.seek(i)
        magic_buf = file.read(4)
        # 寻找中央目录分块。
        if int.from_bytes(magic_buf, byteorder='little',
                          signed=False) == EndLocatorMagic:
            file.seek(i)
            _1, _2, _3, _4, _5, _6, el_directory_offset, _8 = struct.unpack(
                '<IHHHHIIH', file.read(3 * 4 + 5 * 2))
            return el_directory_offset, i

    return -1, -1


def _parse_apk_sign_block_offset(file, zip_central_offset):
    """
    size of block - uint64
    length - uint64: {
    [
    {
        ID - uint32,
        value - (pair size - 4 bytes): {
            [APK Sign V2 Block]
        }
    },
    ]
    }
    size of block - uint64
    magic: "APK Sig Block 42" - (16 bytes)
    """
    for i in range(zip_central_offset - 16, 0, -1):
        file.seek(i)
        magic_buf = file.read(16)
        # find APK Sign Block。
        if magic_buf == bytes(ApkSignBlockMagic, encoding='utf8'):
            _print_log('sign block magic offset：%d' % i)
            _print_log('sign block magic hex: %s' % magic_buf.hex())

            # move block size（uint64）type size up.
            bottom_block_size_offset = i - 8
            file.seek(bottom_block_size_offset)

            block_size_buf = file.read(8)
            block_size = int.from_bytes(block_size_buf, byteorder='little',
                                        signed=False)
            _print_log('bottom sign block size：%d' % block_size)
            # 除去魔数（16 bytes）和一个分块大小（uint32）的类型大小。

            # 顶部 block size 的偏移（即 sign block offset）。
            # 向上偏移整个块大小除去 magic（16 bytes）和一个
            # bottom block size（uint64）的类型大小
            # 再向上偏移一个 top block size（uint64）的类型大小。
            top_block_size_offset = bottom_block_size_offset - (
                    block_size - 16 - 8) - 8
            return top_block_size_offset

    return -1


def _write_id_value_pair_internal(file, out_file, ids, values,
                                  sign_block_offset):
    file.seek(sign_block_offset)
    block_size_buf = file.read(8)
    block_size = int.from_bytes(block_size_buf, byteorder='little',
                                signed=False)
    _print_log('top sign block size：%d' % block_size)

    # not include 16 (two block size) and 16 (magic) type size.
    # original_pairs_size = block_size - 8 - 16

    # calculator original pairs length.
    # move [top block size] forward.
    pairs_offset = sign_block_offset + 8
    # not include 16 [two block size] and 16 [magic] type size.
    pairs_limit = pairs_offset + block_size - 8 - 16
    original_pairs_size = 0

    while pairs_offset < pairs_limit:
        file.seek(pairs_offset)
        pair_length = int.from_bytes(file.read(8), byteorder='little',
                                     signed=False)
        # move [pair length] type size forward.
        pairs_offset = pairs_offset + 8

        pair_id = int.from_bytes(file.read(4), byteorder='little',
                                 signed=False)
        _print_log('pair ID：0x%x' % pair_id)

        if pair_id == ApkSignBlockPaddingID:
            break

        # add [pair length] type size.
        original_pairs_size = original_pairs_size + pair_length + 8

        # jump to next pair.
        pairs_offset = pairs_offset + pair_length

    _print_log('original pairs length: %d' % original_pairs_size)

    # reset file position.
    pairs_offset = sign_block_offset + 8
    file.seek(pairs_offset)

    append_pairs_length = _calculation_add_pairs_length(values)
    new_block_size = original_pairs_size + append_pairs_length + 8 + 16

    # 8 is top block size.
    total_size = new_block_size + 8
    # calculator padding.
    padding = 0
    if total_size % PageAlignmentBytes != 0:
        # pair size + id size.
        padding = PageAlignmentBytes - (total_size % PageAlignmentBytes)

    new_block_size = new_block_size + padding

    _print_log('new block size: %d' % new_block_size)
    # 1. write top block size to new apk.
    _write_bytes_to_file(
        int(new_block_size).to_bytes(8, byteorder='little', signed=False),
        out_file)

    _print_log("\n====== APK Block Pairs ======\n")

    # 2. write original id-value pairs to new apk
    _write_bytes_to_file(file.read(original_pairs_size), out_file)

    # write new id-value paris to new apk.
    for i in range(len(ids)):
        # 3-2. write pair length (ID size + value size).
        _write_bytes_to_file(
            int(4 + len(values[i])).to_bytes(8, byteorder='little',
                                             signed=False), out_file)
        # 3-1. write id.
        _write_bytes_to_file(
            int(ids[i]).to_bytes(4, byteorder='little', signed=False), out_file)
        # 3-3. write value.
        _write_bytes_to_file(bytes(values[i], encoding='utf8'), out_file)

    # 3. write padding pair
    _write_bytes_to_file(int(padding - 12 + 4).to_bytes(
        8, byteorder='little', signed=False), out_file)
    _write_bytes_to_file(int(ApkSignBlockPaddingID).to_bytes(
        4, byteorder='little', signed=False), out_file)
    _write_bytes_to_file(bytes(padding - 12), out_file)

    # 4. write bottom block size to new apk.
    _write_bytes_to_file(
        int(new_block_size).to_bytes(8, byteorder='little', signed=False),
        out_file)
    # 5. write magic to new apk.
    _write_bytes_to_file(bytes(ApkSignBlockMagic, encoding='utf8'), out_file)

    # 16 (not include top block size).
    return new_block_size - block_size


def _copy_file(src_file, to_file, start, limit):
    src_file.seek(start)
    to_file.write(src_file.read(limit - start))


def _write_bytes_to_file(buffer, to_file):
    to_file.write(buffer)


def _write_zip_end_locator(src_file, src_file_size, out_file,
                           zip_end_locator_offset, el_directory_extends):
    src_file.seek(zip_end_locator_offset)
    no_el_comment_length = 3 * 4 + 5 * 2
    _1, _2, _3, _4, _5, _6, el_directory_offset, _8 = struct.unpack(
        '<IHHHHIIH', src_file.read(no_el_comment_length))

    _print_log('el_directory_offset: %d' % el_directory_offset)
    new_el_directory_offset = el_directory_offset + el_directory_extends
    _print_log('new_el_directory_offset: %d' % new_el_directory_offset)

    new_end_locator_no_el_comment = struct.pack(
        '<IHHHHIIH', _1, _2, _3, _4, _5, _6, new_el_directory_offset, _8)

    # write new_ebd_locator to new apk.
    _write_bytes_to_file(new_end_locator_no_el_comment, out_file)

    # write remain data (el_comment) to new apk.
    _copy_file(src_file, out_file,
               zip_end_locator_offset + no_el_comment_length, src_file_size)


# 1. copy original [contents of ZIP entries] to new apk.
# 2. write modified (extends) [APK Signing Block] to new apk.
# 3. write modified (if possible: zip info) [Central Directory] to new apk.
# 4. write modified (update offset info) [End of Central Directory] to new apk.
def write_id_value_pairs(file_path, out_file_path, ids, values):
    with open(file_path, 'rb') as f:
        with open(out_file_path, 'ab') as out:
            global DirectoryOffsetCache, EndLocatorOffsetCache
            global ApkFilePathCache

            # ensure the same file.
            not_same_file = ApkFilePathCache is not file_path

            if not_same_file or DirectoryOffsetCache == -1:
                DirectoryOffsetCache, EndLocatorOffsetCache = \
                    _parse_zip_central_offset(f, file_path)
                if DirectoryOffsetCache == -1:
                    raise Exception('parse zip central directory: not found')

            _print_log('zip central offset：%d\n' % DirectoryOffsetCache)

            global SignBlockOffsetCache

            if not_same_file or SignBlockOffsetCache == -1:
                SignBlockOffsetCache = _parse_apk_sign_block_offset(
                    f, DirectoryOffsetCache)
                if SignBlockOffsetCache == -1:
                    out.close()
                    os.remove(out_file_path)
                    raise Exception(
                        'parse apk sign block error: not fond block.')

            ApkFilePathCache = file_path

            _print_log('apk sign block offset：%d\n' % SignBlockOffsetCache)

            # 1. copy [contents of ZIP entries].
            _copy_file(f, out, 0, SignBlockOffsetCache)

            _print_log('write new ids: %s' % str(ids))
            _print_log('write new values: %s\n' % str(values))

            # 2. write [APK Signing Block].
            append_size = _write_id_value_pair_internal(
                f, out, ids, values, SignBlockOffsetCache)

            # 3. write [Central Directory].
            _copy_file(f, out, DirectoryOffsetCache, EndLocatorOffsetCache)

            # 4. write [End of Central Directory].
            _write_zip_end_locator(f, os.path.getsize(file_path), out,
                                   EndLocatorOffsetCache, append_size)


# test.
if __name__ == '__main__':
    # write_id_value_pairs('../../apk/htb.apk', '../../out/htb.apk',
    #                      [0xaaaa, 0x1234],
    #                      ['I am fine.', 'you are beautiful.'])
    write_id_value_pairs('../../apk/htb.apk', '../../out/htb.apk',
                         [0x71cccccc], ['i love you.'])
    _print_log('write ok.')
