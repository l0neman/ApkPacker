import datetime

from src import debug_log

ChannelFilePath = './channel/channel.txt'
OutDirPath = './out/'

ApkFilePath = './apk/Target.apk'


def get_apk_name(apk_name, channel_name, channel):
    return '%s_%s_%s' % (apk_name, channel_name, channel)


def read_file_lines(file_path, callback):
    with open(file_path, 'r', encoding='utf8') as f:
        for line in f.readlines():
            split = line.split('|')
            callback(split[0], split[1].replace('\n', ''))


def print_time():
    print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))


def start_pack_apk():
    def callback(name, channel):
        pass

    read_file_lines(ChannelFilePath, callback)


# todo 1. 支持静态配置文件。
# todo 2. 支持命令行选项执行。
if __name__ == '_main_':
    print_time()

    debug_log.print_step_t____('开始多渠道打包')
    start_pack_apk()
    debug_log.print_step_b____('多渠道打包完毕')

    print_time()
