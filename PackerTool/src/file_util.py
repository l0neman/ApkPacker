# coding:utf-8
# ! python3
import os


def list_all_file(path: str, callback: callable(str)) -> None:
    """遍历所有目录下所有文件，并回调子文件完整路径"""
    if callback is None:
        raise AssertionError('useless')
    if not os.path.exists(path):
        return
    for file in os.listdir(path):
        full_path = os.path.join(path, file)
        if os.path.isfile(full_path):
            callback(os.path.normpath(full_path))
        else:
            list_all_file(full_path, callback)


def get_dir_path(file_full_path: str) -> str:
    """
    从文件路径中解析出目录
    @:param file_full_path 文件或目录的全路径
    """
    file_full_path = os.path.normpath(file_full_path)
    separate = '\\'
    try:
        path_index = file_full_path.rindex(separate)
    except ValueError:
        return '.'
    end_index = len(file_full_path) - 1
    # 判断是目录
    if path_index == end_index:
        file_path = file_full_path
    else:
        file_path = file_full_path[:path_index + 1]

    return file_path
