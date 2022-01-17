import gym
import pefile
from gym import spaces
from gym.utils import seeding
import numpy as np
from keras.models import load_model
import tensorflow as tf
from get_feature import get_static_feature
import gc
import os

def file_name(file_dir):
    filenames = []
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            filenames.append(os.path.join(root, file))
    return filenames

class PEEnv(gym.Env):
    def __init__(self):
        # self.import_function = np.zeros(200)
        # self.rename_section = np.zeros(5)
        # self.add_new_section = np.zeros(10)
        # self.remove_signature = np.zeros(1)
        # self.append_some_random_bytes = np.zeros(1)
        # self.remove_debug_info = np.zeros(1)
        # self.static_feature = get_static_feature("pe文件名")
        self.seed()
        self.viewer = None
        self.state = None
        self.PElist = file_name(r'D:/python workspace/windowsPE/Malicious')
        self.number = 0
        # self.steps_beyond_done = None

        self.action_space = spaces.Discrete(5 + 1 + 1)
        self.max = np.concatenate((
            np.array([np.finfo(np.float32).max, np.finfo(np.float32).max, 1, np.finfo(np.float32).max,
                      np.finfo(np.float32).max,
                      1, 1, 1, 1, np.finfo(np.float32).max], dtype=np.float32),
            np.full(256, 65536, dtype=np.float32)))  # 观测空间的最大值
        self.min = np.zeros(266, dtype=np.float32)  # 观测空间的最小值
        self.observation_space = spaces.Box(self.min, self.max, dtype=np.float32)
        self.turn = 0
        self.PEFile = self.PElist[self.number]

    def seed(self, seed=None):
        self.np_random, seed = seeding.np_random(seed)
        return [seed]

    def step(self, action):
        assert self.action_space.contains(action), "%r (%s) invalid" % (action, type(action))
        tempFileName = r'D:/python workspace/windowsPE/Malicious/test'
        pe = pefile.PE(self.PEFile)
        # 对节区名的修改。每一个节区的修改，都是一个独立的动作。所以这包含了5个动作
        # 节区名长度是固定的
        if action == 0:
            pe.sections[0].Name = b'.mtext\x00\x00'
            pe.write(tempFileName)
        elif action == 1:
            pe.sections[1].Name = b'.mrdata\x00'
            pe.write(tempFileName)
        elif action == 2:
            pe.sections[2].Name = b'.mdata\x00\x00'
            pe.write(tempFileName)
        elif action == 3:
            if len(pe.sections) < 4:
                pass
            else:
                pe.sections[3].Name = b'.mrsrc\x00\x00'
                pe.write(tempFileName)
        elif action == 4:
            if len(pe.sections) < 5:
                pass
            else:
                pe.sections[4].Name = b'.mreloc\x00'
                pe.write(tempFileName)
        elif action == 5:  # 删除签名
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress = 0
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size = 0
            pe.write(tempFileName)
        else:  # 删除debug信息
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress = 0
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size = 0
            pe.write(tempFileName)

        del pe
        gc.collect()

        pe = pefile.PE(tempFileName)
        pe.write(self.PEFile)
        del pe
        gc.collect()


        self.state = np.array(get_static_feature(self.PEFile))
        self.afterTreatment = tf.reshape(self.state,(1,266))
        self.turn += 1
        if self.turn == 10:
            reward = 0
            done = True
        else:
            model = load_model(r'D:\python workspace\windowsPE\detectModel.h5')
            #if model.predict(self.afterTreatment)[0][0] >= 0.5:
            if model(self.afterTreatment)[0][0] >= 0.5:
                reward = 100 / self.turn
                done = True
            else:
                reward = 0
                done = False
        #print(self.PElist[self.number])
        return self.state, reward, done, {}

    def reset(self):  # 训练完成，应该找下一个pe文件开始训练
        self.number += 1
        self.PEFile = self.PElist[self.number]
        self.state = np.array(get_static_feature(self.PEFile))
        self.turn = 0
        return self.state

    def render(self, mode='human'):
        return None

    def close(self):
        if self.viewer:
            self.viewer.close()
            self.viewer = None
