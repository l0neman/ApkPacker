# coding:utf-8
# ! python3

"""print utils"""

StepMarkPrefix = '┣ '
ProgressMarkPrefix = '┃ '
LogLeftMark = '[ '
LogRightMark = ' ]'
Debug = True


def print_step_t____(info: str) -> None:
    """top print"""
    if not Debug:
        return
    _log("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    _log(StepMarkPrefix + info.replace('\n', '\n┃'))


def print_step_s____(info: str) -> None:
    """single print"""
    if not Debug:
        return
    _log("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    _log(ProgressMarkPrefix + info.replace('\n', '\n┃'))
    _log("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")


def print_step_m____(info: str) -> None:
    """middle print"""
    if not Debug:
        return
    _log(ProgressMarkPrefix + info.replace('\n', '\n┃'))


def print_step_b____(info: str) -> None:
    """bottom print"""
    if not Debug:
        return
    _log(StepMarkPrefix + info.replace('\n', '\n┃'))
    _log("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")


def print_log____(tag: str = '', log: str = '') -> None:
    """print as log style: [ tag ]: log"""
    if not Debug:
        return
    if tag == '':
        tag = log
    _log(ProgressMarkPrefix + LogLeftMark + tag + LogRightMark + ': ' + log)


def print_error____(error: str = '', info: str = '') -> None:
    """
    print error.

      \"[ error ] -> error info\"
    """
    if not Debug:
        return
    _log(ProgressMarkPrefix + LogLeftMark + error + LogRightMark + ' -> ' + info)


def _log(log: str) -> None:
    print(log)
