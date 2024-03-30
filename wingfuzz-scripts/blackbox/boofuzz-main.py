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

''' =========== CONFIGURATION =========== '''
WORK_DIR = "/home/dez/wingfuzz"
PROTOCOL = "dicom"

# Fuzz in specific duration time
def test_for_duration(session, duration):
    start_time = time.time()
    while time.time() - start_time < duration:
        session.fuzz()

# Callback after each test case execution
def post_test_case_callback(target, fuzz_data_logger, session, sock, *args, **kwargs):
    global sum_bitmap
    
    bitmap = get_bitmap(shmid)
    clean_shm(shmid)
    
    if sum_bitmap == b'':
        sum_bitmap = bitmap
    else:
        formatted_time = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
        record_file = os.path.join(record_dir,f"{formatted_time}.txt")
        sum_bitmap = update_sum_bitmap(bitmap, sum_bitmap, record_file)
    

program_close = "sudo pkill -9 -f dicom/repo/storescp"
# Now we are at ~/wingfuzz/wingfuzz-scripts/blackbox/
in_dir = f"../../{str(PROTOCOL)}/in/"
record_dir = f"../{str(PROTOCOL)}/out/record/"

sum_bitmap = b''

# s_initialize("NTP Packet")
# s_binary("\\x1b")  # LI, VN, Mode
# s_random("\\x00" * 47, min_length=47, max_length=47) 
# session.connect(s_get("NTP Packet"))


shmid = open_shm()
p = execute(program_close)

program_boot = f"sudo __AFL_SHM_ID={str(shmid)} {str(WORK_DIR)}/{str(PROTOCOL)}/repo/storescp_v3.6.8 4288 &"

p = execute(program_boot)
time.sleep(1)

msg_list = read_in_dir(in_dir)
#print(msg_list)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("",12345))
    s.listen()
    print()
    print("### Socket Start - Listening on port 12345...")

    # Set 10 rounds, about 10 hours
    for index in range(0, 10):
        session = Session(
            target = Target(
                # connection=UDPSocketConnection("127.0.0.1",123,send_timeout=0.2)
                connection=TCPSocketConnection("127.0.0.1", 4288, send_timeout=0.2)
            ),
            post_test_case_callbacks = [post_test_case_callback],
            web_port = None
        )
    
        for i in range(0,len(msg_list)):
            s_initialize(name = f"Round-{index+1}-Orig:id{i}" )
            s_random(msg_list[i],min_length=47, max_length=47)
            session.connect(s_get(f"Round-{index+1}-Orig:id{i}"))

        test_for_duration(session, 3000)
        #session.fuzz()

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
        
        #wait_for_signal(in_dir)
        msg_list = read_in_dir(in_dir)
        #print(msg_list)


p = execute(program_close)
close_shm(shmid)

