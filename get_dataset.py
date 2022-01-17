import os
import keras.models as models
import keras.layers as layers
from keras.models import Sequential
from keras.layers import Dense
from keras.utils import to_categorical
from matplotlib import pyplot as plt
import numpy as np
from keras.layers import LeakyReLU

from get_feature import *
def Malicious_pe_feature(base_path):
    """
    这是对于坏的数据向量的处理
    :return: 一个包含文件特征的二维数组以及一个全为0的一维数组
    """
    #base_path = '.\Malicious'
    #base_path = '.\M'
    result = []
    # result将保存最后返回的二维数组
    for root, dirs, files in os.walk(base_path):
        for file in files:  # file就是文件名
            path = os.path.join(root, file)
            if pe_generalinfovector(path) == 0:
                continue
            else:
                Unprocessed = get_static_feature(path)
                afterTreatment = list(np.array(Unprocessed).flatten())
                #print(afterTreatment)
                result.append(afterTreatment)
    return np.array(result,dtype=int)


def Benign_pe_feature(base_path):
    """
    对好的向量的处理
    :return: 一个包含文件特征的二维数组以及一个全为1的一维数组
    """
    #base_path = '.\Benign'
    #base_path = '.\B'
    result = []
    # result将保存最后返回的二维数组
    for root, dirs, files in os.walk(base_path):
        for file in files:   # file就是文件名
            path = os.path.join(root, file)
            Unprocessed = get_static_feature(path)
            afterTreatment = list(np.array(Unprocessed).flatten())
            #print(afterTreatment)
            result.append(afterTreatment)
    return np.array(result,dtype=int)

def get_Malicious_feature_num(arr):
    """
    获取不好的数据的标签
    :param arr:
    :return:
    """
    feature_num = []
    for i in range(len(arr)):
        feature_num.append(0)
    return np.array(feature_num,dtype=int)


def get_Benign_feature_num(arr):
    """
    获取好的数据的标签
    :param arr:
    :return: 全为1的数组
    """
    feature_num = []
    for i in range(len(arr)):
        feature_num.append(1)
    return np.array(feature_num,dtype=int)
