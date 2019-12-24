package io.l0neman.channelreader.example;

import android.os.Bundle;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import io.l0neman.channelreader.ChannelReader;

public class MainActivity extends AppCompatActivity {

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    TextView channel = findViewById(R.id.tv_channel);
    channel.setText(ChannelReader.getInstance().read(this));
  }
}
