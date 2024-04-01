import os
import socket
import random
from datetime import datetime 
import threading
import time
from ctypes import *
import ctypes
import sys
import subprocess
from bitarray import bitarray
import binascii
import shutil


try:
    rt = CDLL('librt.so')
except:
    rt = CDLL('librt.so.1')
    
shmget = rt.shmget
shmget.argtypes = [c_int, c_size_t, c_int]
shmget.restype = c_int
shmat = rt.shmat
shmat.argtypes = [c_int, POINTER(c_void_p), c_int]
shmat.restype = c_void_p

shmctl = rt.shmctl


def clean_shm(shmid):
    addr = shmat(shmid, None, 0)
    ctypes.memset(addr, 0, 64*1024)

def open_shm():
    shmid = shmget(0, 64*1024, 0o01000 | 0o02000 | 0o0600)
    os.environ["__AFL_SHM_ID"] = str(shmid)
    clean_shm(shmid)
    return shmid


def get_bitmap(shmid):
    bitmap = b''
    addr = shmat(shmid, None, 0)
    bitmap = string_at(addr, 64*1024)
    return bucketing_bitmap(bitmap)

def close_shm(shmid):
    return shmctl(shmid,0,0)

def save_interesting(in_dir, b_msg):
    now = datetime.now()
    formatted_time = now.strftime("%Y-%m-%d-%H-%M-%S")
    file = os.path.join(in_dir, f"Black-Box-{formatted_time}.raw")
    with open(file, 'w') as f:
        f.write(b_msg)

def execute(cmd):
    p = subprocess.Popen(cmd,shell=True, stdout=subprocess.PIPE)
    return p

def find_files(target_folder, suffix):
    conf_files = []  
    for root, dirs, files in os.walk(target_folder):
        for file in files:
            if file.endswith(suffix):
                conf_files.append(os.path.join(root, file))
    return conf_files

def read_in_dir(in_dir):
    in_file = find_files(in_dir, '.raw')
    msg_list = []
    for file in in_file:
        with open(file, 'rb') as f:
            content = f.read1()
            tem = ''.join('\\x{:02x}'.format(byte) for byte in content)
            msg_list.append(tem)
    return msg_list

def bucket(num):           # 将执行路径次数投入不同的bucket中进行计算
    res = b''
    
    if num == 0: res = bitarray('00000000').tobytes()
    elif num == 1: res = bitarray('00000001').tobytes()
    elif num == 2: res = bitarray('00000010').tobytes()
    elif num == 3: res = bitarray('00000100').tobytes()
    elif num in range(4,8): res = bitarray('00001000').tobytes()
    elif num in range(8,16): res = bitarray('00010000').tobytes()
    elif num in range(16,32): res = bitarray('00100000').tobytes()
    elif num in range(32,128): res = bitarray('01000000').tobytes()
    elif num in range(128,256): res = bitarray('10000000').tobytes()
        
    return res

def bucketing_bitmap(bitmap):
    new = b''
    for i in range(0,len(bitmap)):
        new = new + bucket(bitmap[i])
    return new

def bstr2bitarray(bstr):
    a = bitarray()
    a.frombytes(bstr)
    return a

def count_non_zero_bytes(mem):
    ret = 0
    # 将字节串按照4字节（32位）进行切片处理
    for i in range(0, len(mem), 4):
        v = int.from_bytes(mem[i:i+4], byteorder='little', signed=False)
        
        # 对于每个32位的块，检查是否不为0
        if v == 0:
            continue
        for n in range(4):
            # 检查每个字节是否不为0
            if (v & (0xFF << (n * 8))) != 0:
                ret += 1
    
    return ret

def count_coverage(bitmap):
    b = count_non_zero_bytes(bitmap)
    #print(b)
    coverage = round( (b / len(bitmap) ) * 100, 4 )
    return coverage

def update_sum_bitmap(bitmap, sum_bitmap, out):  
    print("Now update sum bitmap.")
    
    if len(bitmap) != len(sum_bitmap):
        print('[-] Error in [if_interesting] 1 - something wrong with length of bitmap')
        sys.exit(0)

    a = list(bitmap)
    b = list(sum_bitmap)

    for i in range(len(a)):
        if a[i] > b[i]:
            b[i] = a[i]
    sum_bitmap = bytes(b)

    #print(f"Coverage = {count_coverage(sum_bitmap)}% | No.Edge = {count_non_zero_bytes(sum_bitmap)}")
    
    if count_coverage(bitmap) > count_coverage(sum_bitmap):
        with open(out,'a') as f:
            stamp = str(int(time.time()))
            f.write(f"{stamp}|{count_coverage(sum_bitmap)}|{count_non_zero_bytes(sum_bitmap)}\n")
        print(f"Coverage = {count_coverage(sum_bitmap)}%")
        
    return sum_bitmap


def wait_for_signal(in_dir):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("",12345))
        s.listen()
        print()
        print("### Socket Start - Listening on port 12345...")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                data = conn.recv(1024)
                print()
                if data.decode('utf-8').startswith('msg'):
                    msg = data.decode('utf-8').split("|")[1]
                    b_msg = bytes(msg, 'latin-1').decode('unicode_escape').encode('latin-1')
                    now = datetime.now()
                    formatted_time = now.strftime("%Y-%m-%d-%H-%M-%S")
                    print(f"Black_Box_Fuzzing Get MSG - {formatted_time}")
                    print(f"MSG - {b_msg}")
                    print()
                    # record msg
                    file = os.path.join(in_dir, f"White-Box-{formatted_time}.raw")
                    with open(file, 'wb') as f:
                        f.write(b_msg)
                    
                elif data.decode('utf-8') == 'stop':
                    now = datetime.now()
                    formatted_time = now.strftime("%Y-%m-%d-%H-%M-%S")
                    print(f"Black_Box_Fuzzing Quit - {formatted_time}")
                    print()
                    #stop_thread = True  
                    break  







        

            