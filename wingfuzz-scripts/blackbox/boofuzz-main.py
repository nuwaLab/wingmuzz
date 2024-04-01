import os
from utils import *
import socket
import random
from datetime import datetime 
import threading
import time
from ctypes import *
import sys
import subprocess
from bitarray import bitarray
import binascii
import shutil
from boofuzz import *

# Now we are at ~/wingfuzz/wingfuzz-scripts/blackbox/
''' =============== CONFIGURATION =============== '''
WORK_DIR = "/home/dez/wingfuzz"
PROTOCOL = "dicom"
DURATION_TIME = 180     # seconds
COVR_COL_TIME = 60      # seconds
TARGET_PORT = 4289      # SUT working port
IN_DIR = f"../../{str(PROTOCOL)}/in/"
RECORD_PATH = f"../../{str(PROTOCOL)}/out/record/"
sum_bitmap = b''


# Fuzz in specific duration time
def test_for_duration(session, duration):
    start_time = time.time()
    while time.time() - start_time < duration:
        session.fuzz()

# TODO: Seems not working...
# Callback after each test case execution
def post_test_case_callback(target, fuzz_data_logger, session, sock, *args, **kwargs):
    global sum_bitmap
    
    bitmap = get_bitmap(shmid)
    clean_shm(shmid)
    
    if sum_bitmap == b'':
        sum_bitmap = bitmap
    else:
        formatted_time = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
        record_file = os.path.join(RECORD_PATH,f"{formatted_time}.txt")
        sum_bitmap = update_sum_bitmap(bitmap, sum_bitmap, record_file)

# Record message from grey-box
def record_msg(b_msg):
    now = datetime.now()
    formatted_time = now.strftime("%Y-%m-%d-%H-%M-%S")
    print(f"Black_Box_Fuzzing Get MSG - {formatted_time}")
    print(f"MSG - {b_msg}")
    file = os.path.join(IN_DIR, f"Grey-Box-{formatted_time}.raw")
    with open(file, 'wb') as f:
        f.write(b_msg)
        time.sleep(2)  # need some time to write


# Begin to roll
program_close = "sudo pkill -9 -f dicom/repo/storescp"
shmid = open_shm()
p = execute(program_close)

program_boot = f"sudo __AFL_SHM_ID={str(shmid)} {str(WORK_DIR)}/{str(PROTOCOL)}/repo/storescp_v3.6.7 4289 &"
p = execute(program_boot)
time.sleep(1)

msg_list = read_in_dir(IN_DIR)
#print(msg_list)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("",12345))
    s.listen()
    print(f"### __AFL_SHM_ID={str(shmid)}")
    print("### Socket Start - Listening on port 12345...")

    # Set 10 rounds, about 10 hours
    for index in range(0, 10):
        session = Session(
            target = Target(
                # connection=UDPSocketConnection("127.0.0.1",123,send_timeout=0.2)
                connection=TCPSocketConnection("127.0.0.1", TARGET_PORT, send_timeout=0.2)
            ),
            post_test_case_callbacks = [post_test_case_callback],
            web_port = None
        )
    
        for i in range(0, len(msg_list)):
            s_initialize(name = f"Round-{index+1}-Orig:id{i}" )
            s_random(msg_list[i],min_length=47, max_length=47)
            session.connect(s_get(f"Round-{index+1}-Orig:id{i}"))

        # run for 55 mins, greybox runs 60 mins per round.
        test_for_duration(session, DURATION_TIME)
        #session.fuzz()

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            flag = conn.recv(4)
            while True:
                # Sticky Packets and Packet Splitting
                if flag.decode('utf-8') == 'mesg':
                    flag = bytes()  # set as null
                    test = conn.recv(8).decode('utf-8')
                    msg_len = test.split('.')[0]
                    part_msg = test.split('.')[1]
                    res_data_len = int(msg_len) - 7 + len(msg_len)
                    recv_data = b''
                    while len(recv_data) < res_data_len:
                        data = conn.recv(res_data_len - len(recv_data))
                        if not data:
                            break
                        recv_data += data
                    msg = part_msg + recv_data.decode('utf-8')
                    b_msg = bytes(msg, 'latin-1').decode('unicode_escape').encode('latin-1')
                    record_msg(b_msg)
                    # read another flag
                    flag = conn.recv(4)
                elif flag.decode('utf-8') == 'stop' or flag == bytes():
                    now = datetime.now()
                    formatted_time = now.strftime("%Y-%m-%d-%H-%M-%S")
                    print(f"Black_Box_Fuzzing Quit - {formatted_time}")
                    #stop_thread = True  
                    break
        
        #wait_for_signal(in_dir)
        msg_list = read_in_dir(IN_DIR)
        #print(msg_list)

p = execute(program_close)
close_shm(shmid)
