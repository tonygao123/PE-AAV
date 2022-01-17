# -*- coding: UTF-8 -*-
# !/usr/bin/python
# @Author: 人&羽
import os


def file_name(file_dir):
    filenames = []
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            filenames.append(os.path.join(root, file))
    return filenames


if __name__ == '__main__':
    L = file_name(r'D:\Users\666\PycharmProjects\data')
    print(L[0])
