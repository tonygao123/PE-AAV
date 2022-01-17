import os
import keras.models as models
import keras.layers as layers
from keras.models import Sequential
from keras.layers import Dense
from keras.utils import to_categorical
from matplotlib import pyplot as plt
import numpy as np
from keras.layers import LeakyReLU
if __name__ == '__main__':
    #goodvec = Benign_pe_feature(".\Benign")
    #goodlabel = get_Benign_feature_num(goodvec)
    #badvec = Malicious_pe_feature(".\Malicious")
    #badlabel = get_Malicious_feature_num(badvec)
    #data = np.concatenate([goodvec, badvec])
    #label = np.concatenate([goodlabel,badlabel])
    #np.save("data.npy",data)
    #np.save("label.npy", label)
    ## 构建网络
    data = np.load("data.npy")
    label = np.load("label.npy")
    model = models.Sequential()
    model.add(layers.Dense(266))
    model.add(LeakyReLU(alpha=0.2))
    model.add(layers.Dense(99))
    model.add(LeakyReLU(alpha=0.2))
    model.add(layers.Dense(99))
    model.add(LeakyReLU(alpha=0.2))
    model.add(layers.Dense(99))
    model.add(LeakyReLU(alpha=0.2))
    model.add(layers.Dense(99))
    model.add(LeakyReLU(alpha=0.2))
    model.add(layers.Dense(99))
    model.add(LeakyReLU(alpha=0.2))
    model.add(layers.Dense(99))
    model.add(LeakyReLU(alpha=0.2))
    model.add(layers.Dense(1, activation='sigmoid'))
    ##　构建优化算法和损失算法
    model.compile(optimizer='Adam',
                  loss='binary_crossentropy',
                  metrics=['accuracy'])

    ## 训练模型
    history = model.fit(data, label, epochs=17,
                        batch_size=50,
                        validation_split=0.15)

    ## 显示训练数据
    history_dict = history.history
    loss_values = history_dict['loss']
    val_loss_values = history_dict['val_loss']
    acc = history.history['accuracy']
    #val_acc = history.history['val_accuracy']
    epochs = range(1, len(loss_values) + 1)

    plt.plot(epochs, loss_values, 'bo', label='Training loss')
    plt.plot(epochs, val_loss_values, 'b', label='Validation loss')
    plt.title('Training loss and validation loss')
    plt.xlabel('Epochs')
    plt.ylabel('Loss')
    plt.legend(loc="upper right")
    plt.show()

    plt.ylim(0, 1)
    plt.xlim(-0.1,18)
    plt.plot(epochs, acc, label="Training Accuracy")
    plt.xlabel('Epochs')
    plt.ylabel('Training Accuracy')
    plt.legend(loc='lower right')
    plt.title('Training Accuracy')
    plt.show()

    #测试？
    print("准确率：",end="")
    print(acc[-1])
    save_path = r'D:\python workspace\windowsPE\saved_model.h5'
    model.save(save_path)