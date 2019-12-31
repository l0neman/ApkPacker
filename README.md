# ApkPacker

- [介绍](#介绍)
- [使用](#使用)
  - [仓库说明](#仓库说明)
  - [1. 渠道读取](#1.-渠道读取)
  - [2. 渠道打包](#2.-渠道打包)
  - [3. 测试](#3.-测试)
- [原理](#原理)
  - [原理简述](#原理简述)
  - [实现步骤简述](#实现步骤简述)
- [参考](#参考)
- [LICENSE](#license)

## 介绍

ApkPacker 是一个 Android 多渠道打包工具，打包脚本使用 Python 3.x 开发。

使用 Python 脚本，不依赖于 Android Studio 集成环境，易于使用。

ApkPacker 采用流行的的将签名写入 APK Signing Block（Apk 签名块）中的方法，避免了重新签名，所以生成渠道包效率极高，打包速度主要取决于 Apk 文件的复制速度。

## 使用

ApkPacker 的使用分为两部分，首先是使用 Python 脚本将需要用于统计的渠道写入对应的多个 Apk 副本中，得到多渠道 Apk 包，其次是 Apk 文件安装至 Android 设备后的运行时读取工作，运行时读取到 Apk 文件的对应渠道即达到多渠道打包目标。

注意：Apk 必须具有 v2 或 v3 签名，因为打包依赖于 Apk 签名分块，如果 Apk 只有 v1 签名，那么它将不具有 Apk 签名分块，无法进行打包。

### 仓库说明

首先将项目 clone 到本地，项目分为两块。

1. ChannelReader - Java 代码，用于 Android 客户端集成后读取渠道。
2. PackerTool    - Python 脚本，用于进行多渠道打包。

### 1. 渠道读取

首先需要集成渠道读取的代码，它将从 Apk 的签名分块中读取渠道。

将 `io.l0neman.channelreader` 包或包下的三个类复制到项目中合适位置。

使用如下代码即可获取渠道：

```
String channel = ChannelReader.getInstance().read(context);
```

如果应用还未进行打包（渠道还未写入 Apk），则返回 null。

### 2. 渠道打包

编译一个 Release 版本应用包，放入 `PackerTool/apk` 目录（没有则新建）下。

然后编辑渠道文件 `PackerTool/channel/channel.txt`，每行表示一个渠道，每个渠道包含一个渠道名字和渠道字符串，使用 `|` 分隔。例如：`应用宝|c1`，渠道名字用于打包时展示和命名输出文件，不会出现在 Apk 中，可为任意字符串；渠道字符串为需要读取的渠道，将会写入 Apk 文件中。

使用时将每行渠道按照上述规则修改为自己需要的渠道即可。

做完上述工作，使用 Python 执行 `PackerTool/src/apk_packer.py` 等待打印结束后即可完成多渠道打包。

例如：

```
cd src
python apk_apcker.py
```

此时在 `PackerTool/out/` 目录下将出现与渠道数量相同的渠道包，命名为 `[apk 名称无后缀]_[渠道名]_[渠道号].apk`，使用它们即可进行测试和上线工作。

例如将 `Tool.apk` 输出渠道 `应用宝|c1` 的渠道包为 `Tool_应用宝_c1.apk`。

### 3. 测试

`ChannelReader` 项目的 `app` Moduel 为渠道包 Demo，它会将渠道显示在 TextView 上，可以使用它进行渠道打包测试。

## 原理

### 原理简述

Apk 在进行 v2 或 v3 签名后，签名工具将会在 Apk 文件的中央位置插入一个 Apk Signing Block（APK 签名分块），签名工具对整个 Apk 文件计算完整性校验数据后，将关键信息（包括 Apk 文件完整性校验数据等）写入此分块，当 Apk 文件安装至设备时，Android 系统将利用签名信息对 Apk 文件进行校验。

![apk-before-after-signing.png](./arts/apk-before-after-signing.png)

[上图引用自 Android Developer 官网]

Apk 的基础文件格式为 ZIP，一个标准的 ZIP 文件结构分为 3 部分，`Contents of ZIP entries` 为 Zip 条目内容区域，记录了 ZIP 中每个文件的信息，`Central Directory` 为 ZIP 中央目标，记录了
每个文件的路径属性等信息，`End of Central Directory` 为 ZIP 中央目录结尾，记录了 ZIP 文件的结构信息，可用于找到 `Central Directory` 块，从而解析出整个 ZIP 文件。

Apk Siging Block（Apk 签名分块）将被写入 `Central Directory` 的前面，我们可以根据 `End of Central Directory` 间接的寻找到它。

签名工具在计算 Apk 文件的完整性信息时，只包括 Apk 文件的 1、3、4 数据块，而不包括 Apk Siging Block（Apk 签名分块）本身，那么我们就可以在其中写入自定义的信息（例如渠道信息），可达到避免重新签名的效果。

那么打包工具要做的工具即：将渠道写入 Apk 签名分块中，在 Apk 安装后的运行时读取渠道信息。

写入渠道首先需要了解 Apk 签名分块的结构，找到写入数据的方法。

经过查阅资料，发现 Apk 签名分块结构如下：

- `size of block in bytes` (excluding this field) (uint64)
- Sequence of uint64-length-prefixed ID-value pairs: 
  - `ID` (uint32)
  - `value` (variable-length: length of the pair - 4 bytes)
- `size of block` in bytes—same as the very first field (uint64)
- `magic` "APK Sig Block 42" (16 bytes)

翻译为中文：


- `块大小` (不包括此字段) (uint64)
- 带有 uint64 长度前缀的 ID-value 键值对序列
  - `ID` (uint32) 
  - `value` (长度：键值对 - 4 bytes)
- `块大小` 值和上面第一个字段相同。(uint64)
- `魔数` "Apk Sig Block 42" (16 bytes)

块大小和魔数都是签名分块的特征，无法携带额外信息。

其中键值对序列用于存放应用 v2 或 v3 签名信息，每一个键值对都表示一个 Apk 签名，其中 `ID` 表示签名的唯一标识，`value` 则为签名的详细信息，一般我们在对 Apk 进行 v2 签名后，`ID-value` 键值对序列中将出现一个 v2 签名的键值对，它的 `ID` 固定值为 `0x7109871a`，如果应用同时进行了 v3 签名（`ID` 为 `0xf05368c0`），那么此时键值对序列的大小将为 2。

键值对序列的设计是为了满足多签名，它不仅可以支持官方的 v2 和 v3 签名，也可以支持第三方的自定义签名，即任何人都可以对 Apk 进行签名（用于自定义的校验），例如某手机厂商自己设计了一套签名机制，必须通过它签名后的 Apk 才能按照到此厂商的系统上，Android 官方系统将忽略第三方的签名信息。

那么这里得出结论，可以向它写入自定义的签名数据，或者其他数据。最终打包工具使用了键值对进行渠道的写入，应用安装后在运行时读取 Apk 文件中的渠道数据即可。

### 实现步骤简述

1. 渠道打包

```
复制 Apk 文件 -> 根据文件结构寻找 Apk 签名分块位置 -> 解析 Apk 签名分块 -> 写入渠道
```

2. 渠道读取

```
获取 Apk 路径 -> 读取 Apk 文件 -> 根据文件结构寻找 Apk 签名分块位置 -> 读取渠道字符串
```

## 参考

- Apk 文件结构

[zip 文件格式](https://blog.csdn.net/xiaobing1994/article/details/78367035)

[The structure of a PKZip file](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html)

- Apk 签名分块结构

[APK 签名方案 v2](https://source.android.google.cn/security/apksigning/v2#apk-signature-scheme-v2-block)

- 原理博客

[Walle - 美团技术团队](https://tech.meituan.com/2017/01/13/android-apk-v2-signature-scheme.html)

- 源代码

[Meituan-Dianping/walle](https://github.com/Meituan-Dianping/walle)

## LICENSE

```
Copyright 2019 l0neman

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

