# Author : Ho1aAs & TonyGao
# Time : 2021-04-21
# Note : Authorized use only for Student Innovation and Entrepreneurship Projects
import pefile
import os
import numpy as np


# The general info is a vector including 10 degrees by quantifying some word description.
def pe_generalinfovector(filepath: str):
    # Load and analyze PE files by using library functions
    pefile_path = filepath
    try:
        pe = pefile.PE(pefile_path)
    except:
        print("error" + pefile_path)
        return 0
        # Get the sections and data directory area of the PE file
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    sections = pe.sections

    # get the byte size of PE file
    size = os.path.getsize(pefile_path)

    # get the virtual byte size of PE file
    vsize = pe.OPTIONAL_HEADER.SizeOfImage

    # Detect the presence of has_debug mark
    # if existed, return 1
    has_debug = 0
    if directory[6]:
        has_debug = 1

    # Get the length of EXPORT and IMPORT objects
    export_len = directory[0].Size
    import_len = directory[1].Size

    # Detect the presence of has_relocations mark
    # if existed, return 1
    has_relocations = 0
    for section in sections:
        if section.PointerToRelocations:
            has_relocations = 1
            break

    # Detect the presence of has_resources mark
    # if existed, return 1
    has_resources = 0
    if directory[2]:
        has_resources = 1

    # Detect the presence of has_signature mark
    # if existed, return 1
    has_signature = 0
    if pe.NT_HEADERS.Signature:
        has_signature = 1

    # Detect the presence of has_tls mark
    # if existed, return 1
    has_tls = 0
    if directory[9].Size:
        has_tls = 1

    # Try to get the length of symbols including IMPORT and EXPORT objects
    symbol_len = 0
    try:
        # First, Get the length of symbols of IMPORT objects by iteration if existed
        if pe.DIRECTORY_ENTRY_IMPORT:
            for i in pe.DIRECTORY_ENTRY_IMPORT:
                symbol_len += 1
    except:
        pass

    try:
        # Last, Get the length of symbols of EXPORT objects by iteration if existed
        if pe.DIRECTORY_ENTRY_EXPORT:
            for i in pe.DIRECTORY_ENTRY_EXPORT:
                symbol_len += 1

    except:
        pass

    # Return the general info vector by list format
    vector = [size, vsize, has_debug, export_len, import_len, has_relocations, has_resources, has_signature, has_tls,
              symbol_len]
    return vector


def gen_byteentropy(mypath):
    # edited from https://github.com/cphuamao/EMBER/blob/23f828f9bd95c5a8afc33371d15245c6b84cbb6e/My_Ember/ember_jsonl.py
    bytez = bytearray(open(mypath, 'rb').read())  # ??????PE???????????????????????????
    name = 'byteentropy'
    dim = 256
    window = 1024  # ????????????
    step = 256  # ????????????

    def _entropy_bin_counts(block):
        # coarse histogram, 16 bytes per bin
        # ????????????????????????????????????????????????????????????4?????????????????????????????????????????????????????????????????????0-15???16-31????????????223-255???????????????.?????????????????????????????????16?????????c
        c = np.bincount(block >> 4, minlength=16)  # 16-bin histogram
        # ???c??????????????????????????????????????????p
        p = c.astype(np.float32) / window
        # wh????????????c?????????????????????c??????i????????????0???wh????????????i
        wh = np.where(c)[0]
        # ???????????????H???????????????????????????????????????
        H = np.sum(-p[wh] * np.log2(
            p[wh])) * 2  # * x2 b.c. we reduced information by half: 256 bins (8 bits) to 16 bins (4 bits)

        Hbin = int(H * 2)  # up to 16 bins (max entropy is 8 bits)
        if Hbin == 16:  # handle entropy = 8.0 bits
            Hbin = 15

        return Hbin, c

    output = np.zeros((16, 16), dtype=np.int)  # ???????????????????????????16*16??????????????????????????????????????????????????????16*16???????????????256????????????
    a = np.frombuffer(bytez, dtype=np.uint8)  # ??????????????????????????????0-0xFF????????????????????????????????????PE??????????????????????????????
    if a.shape[0] < window:  # ????????????PE???????????????????????????????????????????????????????????????????????????
        Hbin, c = _entropy_bin_counts(a)
        output[Hbin, :] += c
    else:  # ?????????PE?????????????????????
        # strided trick from here: http://www.rigtorp.se/2011/01/01/rolling-statistics-numpy.html
        # ???????????????????????????????????????????????????
        shape = a.shape[:-1] + (a.shape[-1] - window + 1, window)
        strides = a.strides + (a.strides[-1],)
        blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::step, :]

        # from the blocks, compute histogram
        # ???????????????????????????????????????????????????
        for block in blocks:
            Hbin, c = _entropy_bin_counts(block)
            # Hbin?????????????????????0???1???2????????????15.??????????????????????????????c ??????output????????????????????????Hbin?????????
            output[Hbin, :] += c

    return output.flatten().tolist()  # ???16*16???????????????256????????????


def get_static_feature(filepath):
    '''

    :param filepath: ????????????
    :return: ????????????????????????256+10???
    '''
    return pe_generalinfovector(filepath) + gen_byteentropy(filepath)