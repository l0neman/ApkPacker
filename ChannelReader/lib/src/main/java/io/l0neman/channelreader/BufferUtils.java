package io.l0neman.channelreader;

import android.os.Build;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Created by l0neman on 2019/12/24.
 */
final class BufferUtils {

  // move 4 bytes forward.
  static int readInt(FileChannel fc) throws IOException {
    ByteBuffer buffer = ByteBuffer.allocate(4);
    buffer.order(ByteOrder.LITTLE_ENDIAN);
    fc.read(buffer);
    buffer.flip();

    return buffer.getInt();
  }

  // move 8 bytes forward.
  static long readLong(FileChannel fc) throws IOException {
    ByteBuffer buffer = ByteBuffer.allocate(8);
    buffer.order(ByteOrder.LITTLE_ENDIAN);
    fc.read(buffer);
    buffer.flip();

    return buffer.getLong();
  }

  static String readString(FileChannel fc, final int length) throws IOException {
    ByteBuffer buffer = ByteBuffer.allocate(length);
    buffer.order(ByteOrder.LITTLE_ENDIAN);
    fc.read(buffer);
    buffer.flip();

    // noinspection CharsetObjectCanBeUsed .
    final Charset charset = Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT ?
        StandardCharsets.UTF_8 : Charset.forName("UTF-8");
    return charset.decode(buffer).toString();

  }
}
