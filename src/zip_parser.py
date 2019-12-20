import struct
import os

EndLocatorMagic = 0x06054b50
ApkSignBlock42 = 0x7109871a

"""
struct EndLocator
{
    ui32 signature;             //目录结束标记,(固定值0x06054b50)
    ui16 elDiskNumber;          //当前磁盘编号
    ui16 elStartDiskNumber;     //中央目录开始位置的磁盘编号
    ui16 elEntriesOnDisk;       //该磁盘上所记录的核心目录数量
    ui16 elEntriesInDirectory;  //中央目录结构总数
    ui32 elDirectorySize;       //中央目录的大小
    ui32 elDirectoryOffset;     //中央目录开始位置相对于文件头的偏移
    ui16 elCommentLen;          // 注释长度
    char *elComment;            // 注释内容
};
"""


def parse_end_locator(file_path):
    with open(file_path, 'rb') as f:
        file_size = os.path.getsize(file_path)
        print(file_size)
        for i in range(file_size):
            f.seek(i)
            int_buf = f.read(4)
            if int.from_bytes(int_buf, byteorder='little', signed=False) == EndLocatorMagic:
                f.seek(i)
                # struct EndLocator {
                signature, \
                elDiskNumber, \
                elStartDiskNumber, \
                elEntriesOnDisk, \
                elEntriesInDirectory, \
                elDirectorySize, \
                elDirectoryOffset, \
                elCommentLen = struct.unpack('<IHHHHIIH', f.read(3 * 4 + 5 * 2))
                print("中央目录偏移：%d" % elDirectoryOffset)

                for j in range(elDirectoryOffset, 0, -1):
                    f.seek(j)
                    int_buf = f.read(16)
                    # if from_bytes == ApkSignBlock42:
                    #     print("APK 签名分块 42 偏移 %d" % j)
                    #     return


if __name__ == "__main__":
    parse_end_locator('../file/SuperToolBox.apk')
    print("read ok.")
