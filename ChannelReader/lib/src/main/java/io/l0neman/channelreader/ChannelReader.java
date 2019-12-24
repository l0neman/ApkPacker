package io.l0neman.channelreader;

import android.content.Context;

/**
 * Created by l0neman on 2019/12/24.
 */
public final class ChannelReader {

  static final int CHANNEL_ID = 0xcccc;
  private ApkSignBlockReader mBlockReader = new ApkSignBlockReader();

  private static ChannelReader sInstance = new ChannelReader();

  private String mChannel;

  public static ChannelReader getInstance() {
    return sInstance;
  }

  private static String getApkPath(Context context) {
    return context.getPackageResourcePath();
  }

  public String read(Context context) {
    if (mChannel == null) {
      mChannel = mBlockReader.readIdValuePairs(getApkPath(context)).get(CHANNEL_ID);
    }

    return mChannel;
  }
}
