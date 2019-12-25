import datetime
import os
import sys

sys.path.append(os.path.abspath('..'))
from src.apk_sign_block import apk_sign_block_writer
from src.utils import file_util, debug_log

ChannelFilePath = '../channel/channel.txt'
OutDirPath = '../out/'
ApkFileDir = '../apk/'

ChannelId = 0x71cccccc


def get_apk_name(apk_name, channel_name, channel):
    return '%s_%s_%s' % (apk_name, channel_name, channel)


def read_channel_file_lines(callback):
    with open(ChannelFilePath, 'r', encoding='utf8') as f:
        for line in f.readlines():
            split = line.split('|')
            callback(split[0], split[1].replace('\n', ''))


def print_time():
    print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))


def start_pack_apk(apk_file_path):
    def callback(name, channel):
        debug_log.print_step_t____('读取渠道文件 [%s-%s]' % (name, channel))
        debug_log.print_step_m____('写入渠道 [%s]' % channel)
        pack_apk_name = '%s.apk' % get_apk_name(
            file_util.get_file_name(apk_file_path, has_suffix=False), name,
            channel)
        apk_sign_block_writer.write_id_value_pairs(
            apk_file_path, OutDirPath + pack_apk_name, [ChannelId], [channel])
        debug_log.print_step_b____('已写入 [%s]' % pack_apk_name)

    read_channel_file_lines(callback)


# todo 支持命令行选项执行？

if __name__ == '__main__':
    print_time()
    debug_log.print_step_t____('开始多渠道打包')
    # clean out dir.

    file_util.remove_file(OutDirPath)

    # ensure out dir.
    if not os.path.exists(OutDirPath):
        os.makedirs(OutDirPath)


    def file_callback(file_path):
        start_pack_apk(file_path)


    file_util.list_all_file(ApkFileDir, file_callback)
    debug_log.print_step_b____('多渠道打包完毕')
    print_time()
