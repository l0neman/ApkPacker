import struct
import os

EndLocatorMagic = 0x06054b50
ApkSignBlockMagic = "APK Sig Block 42"
ApkSignBlock42ID = 0x7109871a


def parse_zip_central_offset(file, file_path):
    """
    struct EndLocator
    {
        ui32 signature;             // 目录结束标记,(固定值0x06054b50)。
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
    print('apk file size: %d' % file_size)
    for i in range(file_size):
        file.seek(i)
        magic_buf = file.read(4)
        # 寻找中央目录分块。
        if int.from_bytes(magic_buf, byteorder='little', signed=False) == EndLocatorMagic:
            file.seek(i)
            _1, _2, _3, _4, _5, _6, el_directory_offset, _8 = struct.unpack('<IHHHHIIH', file.read(3 * 4 + 5 * 2))
            return el_directory_offset

    return -1


def parse_apk_sign_block_offset(file, zip_central_offset):
    """
    size of block - uint64
    length - uint64: [
    {
        ID - uint32,
        value - (pair size - 4 bytes): {
            [APK Sign V2 Block]
        }
    },
    ]
    size of block - uint64
    magic: "APK Sig Block 42" - (16 bytes)
    """
    for i in range(zip_central_offset - 16, 0, -1):
        file.seek(i)
        magic_buf = file.read(16)
        # 寻找 APK 分块。
        if magic_buf == bytes(ApkSignBlockMagic, encoding='utf8'):
            print('sign block magic offset：%d' % i)
            print('sign block magic hex: %s' % magic_buf.hex())

            # 向上偏移 block size（uint64）类型大小.
            bottom_block_size_offset = i - 8
            file.seek(bottom_block_size_offset)

            block_size_buf = file.read(8)
            block_size = int.from_bytes(block_size_buf, byteorder='little', signed=False)
            print('bottom sign block size：%d' % block_size)
            # 除去魔数（16 bytes）和一个分块大小（uint32）的类型大小。

            # 顶部 block size 的偏移（即 sign block offset）。
            # 向上偏移整个块大小除去 magic（16 bytes）和一个 bottom block size （uint64）的类型大小
            # 再向上偏移一个 top block size（uint64）的类型大小。
            top_block_size_offset = bottom_block_size_offset - (block_size - 16 - 8) - 8
            return top_block_size_offset

    return -1


def parse_sign_block_v2(file, sign_block_v2_offset):
    """
    [APK Sign V2 Block]:

    length - uint32: {
    signer: [
        length - uint32: {
        length - uint32: {
        signed data {
            length - uint32: {
            digests: [
                {
                    signature algorithm ID - uint32,
                    digest
                },
            ]
            },

            length - uint32: {
            certificates: [
                length - uint32: {
                certificate
                },
                ]
            },

            length - uint32: {
            additional attributes: [
                length - uint32: {
                ID - uint32,
                value - (additional attribute - 4 bytes)
                },
            ]
            }
        },

        length - uint32: {
        signatures: [
            length - uint32: {
            signature algorithm ID - uint32 [0x0101, 0x0102, 0x0103, 0x0104, 0x0201, 0x0202, 0x0301],
            length - uint32: {
                signature
            }
            },
        ]
        },

        length - uint32:{
        public key
        }
        }
        },
    ]
    }
    """
    print('sign block v2 offset: %d' % sign_block_v2_offset)
    signer_offset = sign_block_v2_offset
    file.seek(signer_offset)

    signer_queue_length = int.from_bytes(file.read(4), byteorder='little', signed=False)
    print('signer queue length: %d\n' % signer_queue_length)

    # move signer queue size (uint32) length forward。
    signer_offset = signer_offset + 4
    signer_queue_limit = sign_block_v2_offset + 4 + signer_queue_length
    signer_count = 0

    # parse signer queue:
    while signer_offset < signer_queue_limit:
        file.seek(signer_offset)

        # parse signer:
        signer_length = int.from_bytes(file.read(4), byteorder='little', signed=False)
        print('signer %d length: %d\n' % (signer_count, signer_length))

        # move signer length (uint32) forward.
        signer_offset = signer_offset + 4

        # 1. parse signed data.
        signed_data_size = int.from_bytes(file.read(4), byteorder='little', signed=False)
        print('signed data %d length: %d' % (signer_count, signed_data_size))

        # move signed data length (uint32) forward.
        signer_offset = signer_offset + 4
        # jump to signatures queue offset.
        signer_offset = signer_offset + signed_data_size

        # 1-1. parse digests.

        # 1-2. parse certificates.

        # 1-3. parse additional attributes.

        # 2. parse signatures.
        file.seek(signer_offset)

        signatures_queue_length = int.from_bytes(file.read(4), byteorder='little', signed=False)
        print('signatures queue %d length: %d\n' % (signer_count, signatures_queue_length))

        # move signatures queue length (uint32) forward.
        signer_offset = signer_offset + 4

        signature_offset = signer_offset
        signatures_queue_limit = signer_offset + signatures_queue_length
        signature_count = 0

        # parse signatures queue.
        while signature_offset < signatures_queue_limit:
            # parse signature.
            file.seek(signature_offset)

            signature_length = int.from_bytes(file.read(4), byteorder='little', signed=False)
            print('signature %d length: %d' % (signer_count, signature_length))

            # move signature length (uint32) forward.
            signature_offset = signature_offset + 4
            # jump to next signature offset.
            signature_offset = signature_offset + signature_length

            # parse signature algorithm ID.
            signature_algorithm_id = int.from_bytes(file.read(4), byteorder='little', signed=False)
            print('signature algorithm ID %d: %x' % (signature_count, signature_algorithm_id))

            signature_count = signature_count + 1

        # jump to public key offset.
        signer_offset = signer_offset + signatures_queue_length

        # move certificates queue length (uint32) forwards.

        # 3. parse public key.
        file.seek(signer_offset)

        public_key_length = int.from_bytes(file.read(4), byteorder='little', signed=False)
        print('public key %d length: %d\n' % (signer_count, public_key_length))

        # move public key length(uint32) forward.
        signer_offset = signer_offset + 4
        # jump to next signer.
        signer_offset = signer_offset + public_key_length

        # ignore parse public key content.

        signer_count = signer_count + 1


def parse_sign_block_pairs(file, sign_block_offset):
    file.seek(sign_block_offset)
    block_size_buf = file.read(8)
    block_size = int.from_bytes(block_size_buf, byteorder='little', signed=False)
    print('top sign block size：%d' % block_size)

    # 移动 top block size（uint64）类型的大小。
    pairs_offset = sign_block_offset + 8

    length = int.from_bytes(file.read(8), byteorder='little', signed=False)
    print('id-value pairs queue size：%d' % length)

    # 移动 pairs size（uint64）类型的大小。
    offset = pairs_offset + 8

    pair_count = 0

    print("\n====== APK Block Pairs ======\n")

    pairs_queue_limit = pairs_offset + length

    while offset < pairs_queue_limit:
        file.seek(offset)
        # 遍历分块 ID-value 键值对。
        print('id offset：%d' % offset)

        sig_id = int.from_bytes(file.read(4), byteorder='little', signed=False)
        print('sign ID %d：%x' % (pair_count, sig_id))

        signer_queue_length = int.from_bytes(file.read(4), byteorder='little', signed=False)
        print('signer queue length: %d\n' % signer_queue_length)

        # 偏移 ID（uint32）的类型大小。
        parse_sign_block_v2(file, offset + 4)

        if signer_queue_length == 0:
            print('not other signer value.')
            return

        # 跳到下一个 ID-value 键值对
        offset = offset + 4 + signer_queue_length
        pair_count = pair_count + 1

    return


def parse(file_path):
    with open(file_path, 'rb') as f:
        zip_central_offset = parse_zip_central_offset(f, file_path)
        if zip_central_offset == -1:
            raise Exception('parse zip central directory.')

        print('zip central offset：%d\n' % zip_central_offset)

        sign_block_offset = parse_apk_sign_block_offset(f, zip_central_offset)
        if sign_block_offset == -1:
            raise Exception('parse apk sign block error.')

        print('apk sign block offset：%d\n' % sign_block_offset)

        parse_sign_block_pairs(f, sign_block_offset)


if __name__ == '__main__':
    # parse_end_locator('../file/Tools.apk')
    parse('../file/Tools.apk')
    print('read ok.')
