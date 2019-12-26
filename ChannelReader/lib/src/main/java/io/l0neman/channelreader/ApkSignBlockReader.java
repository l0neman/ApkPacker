package io.l0neman.channelreader;

import android.util.Log;
import android.util.SparseArray;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by l0neman on 2019/12/24.
 */
final class ApkSignBlockReader {

  private static final String TAG = ApkSignBlockReader.class.getSimpleName();
  private static final boolean DEBUG = false;

  private static final int END_LOCATOR_MAGIC = 0x06054b50;
  private static final int APK_SIGN_BLOCK_V2_ID = 0x7109871a;
  private static final int APK_SIGN_BLOCK_V3_ID = 0xf05368c0;
  private static final String APK_SIGN_BLOCK_MAGIC = "APK Sig Block 42";
  private static final int APK_SIGN_BLOCK_PADDING_ID = 0x42726577;

  /* support custom ids */
  private static final Set<Integer> CUSTOM_ID_SET = new HashSet<>();

  static {
    CUSTOM_ID_SET.add(0x71cccccc);
  }

  private SparseArray<String> mPairs = new SparseArray<>();

  /*
    parse.
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
   */
  private int parseZipCentralOffset(FileChannel fc) throws IOException {
    for (long i = fc.size() - 4; i >= 0; i--) {
      fc.position(i);

      if (BufferUtils.readInt(fc) == END_LOCATOR_MAGIC) {
        fc.position(i);

        // signature ~ elDirectoryOffset size (3 * ui32 + 4 * ui16).
        final ByteBuffer structBuffer = ByteBuffer.allocate(3 * 4 + 4 * 2);
        structBuffer.order(ByteOrder.LITTLE_ENDIAN);
        fc.read(structBuffer);
        structBuffer.flip();
        // position to elDirectoryOffset.
        structBuffer.position(2 * 4 + 4 * 2);
        // elDirectoryOffset.
        return structBuffer.getInt();
      }
    }

    return -1;
  }

  private int parseApkSignBlockOffset(FileChannel fc, int zipCentralOffset) throws IOException {
    for (int i = zipCentralOffset - 16; i >= 0; i--) {
      fc.position(i);

      // find magic: "APK Sig Block 42".
      if (APK_SIGN_BLOCK_MAGIC.equals(BufferUtils.readString(fc, 16))) {
        //  move block size（uint64）type size up.
        int bottomBlockSizeOffset = i - 8;
        fc.position(bottomBlockSizeOffset);

        final long blockSize = BufferUtils.readInt(fc);
        // not include magic (16 bytes) + block size（uint32).
        // move magic（16 bytes）+ bottom block size (uint64) type size up.
        // top block size offset = sign block offset.
        // return topBlockSizeOffset.
        return (int) (bottomBlockSizeOffset - (blockSize - 16));
      }
    }

    return -1;
  }

  /*
    parse [Apk Sign Block] structure ID-value pairs (not include google v2, v3 sign pair).

    size of block - uint64
    [
        length - uint64: {
        ID - uint32,
        value - (pair size - 4 bytes): {
            [APK Sign V2 Block]
        }
        },
    ]
    size of block - uint64
    magic: "APK Sig Block 42" - (16 bytes)
   */
  private void parseSignBlockPairs(FileChannel fc, int signBlockOffset) throws IOException {
    fc.position(signBlockOffset);

    final long blockSize = BufferUtils.readLong(fc);

    // move top block size（uint64）type size forward.
    int pairsQueueOffset = signBlockOffset + 8;
    // not include 8 (bottom block size) and 16 (magic) type size.
    final long pairsQueueLimit = pairsQueueOffset + blockSize - 8 - 16;

    while (pairsQueueOffset < pairsQueueLimit) {
      fc.position(pairsQueueOffset);

      long pairLength = BufferUtils.readLong(fc);
      // move paris size (uint64) type size forward.
      pairsQueueOffset += 8;

      final int id = BufferUtils.readInt(fc);
      // move ID (uint32) type size forward.

      switch (id) {
      case APK_SIGN_BLOCK_V2_ID:
      case APK_SIGN_BLOCK_V3_ID:
        // ignore parse.
        break;
      case APK_SIGN_BLOCK_PADDING_ID:
        return;
      default:
        if (CUSTOM_ID_SET.contains(id)) {
          mPairs.put(id, BufferUtils.readString(fc, (int) (pairLength - 4)));
          return;
        }
      }

      // jump to next ID-value pair offset, 4 is [APK Sign V2 Block] length.
      pairsQueueOffset += pairLength;
    }
  }

  private void parsePairsInternal(FileChannel fc) throws IOException {
    int zipCentralOffset = parseZipCentralOffset(fc);
    if (zipCentralOffset == -1) {
      throw new RuntimeException("not found zip central end locator.");
    }

    int signBlockOffset = parseApkSignBlockOffset(fc, zipCentralOffset);
    if (signBlockOffset == -1) {
      throw new RuntimeException("not found apk sign block.");
    }

    parseSignBlockPairs(fc, signBlockOffset);
  }

  private void parsePairs(String apkPath) {
    FileChannel fileChannel = null;
    try {
      fileChannel = new FileInputStream(apkPath).getChannel();
      parsePairsInternal(fileChannel);
    } catch (IOException e) {
      if (DEBUG) Log.e(TAG, "e", e);
    } finally {
      if (fileChannel != null) try {
        fileChannel.close();
      } catch (IOException ignore) {}
    }
  }

  SparseArray<String> readIdValuePairs(String apkPath) {
    if (mPairs.size() != 0) {
      return mPairs;
    }

    parsePairs(apkPath);
    return mPairs;
  }
}
