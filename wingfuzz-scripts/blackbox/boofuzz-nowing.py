import os
import gc
import time
import socket
from utils import *
from datetime import datetime 
from ctypes import *
from bitarray import bitarray
from boofuzz import *

# Now we are at ~/wingfuzz/wingfuzz-scripts/blackbox/
''' =============== CONFIGURATION =============== '''
WORK_DIR = "~/wingfuzz"
PROTOCOL = "ftp"
DURATION_TIME = 3600     # seconds
TARGET_PORT = 21      # SUT working port
BINARY = "proftpd_v1.3.8"
IN_DIR = f"../../{PROTOCOL}/init_in/"
RECORD_PATH = f"../../{PROTOCOL}/out/record/"
sum_bitmap = b''


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
program_close = f"sudo pkill -9 -f {PROTOCOL}/repo/{BINARY}"
shmid = open_shm()
p = execute(program_close)

program_boot = f"sudo __AFL_SHM_ID={str(shmid)} {WORK_DIR}/{PROTOCOL}/repo/{BINARY} -c ~/proftpd-v1.3.8/etc/proftpd.conf &"
p = execute(program_boot)
time.sleep(1)

msg_list = read_in_dir(IN_DIR)
#print(msg_list)

print(f"### __AFL_SHM_ID={str(shmid)}")

# Set 10 rounds, about 10 hours
for index in range(0, 10):
    # Prevent OOM
    gc.collect()
    # Start boofuzz
    session = Session(
        target = Target(
            # connection=UDPSocketConnection("127.0.0.1",123,send_timeout=0.2)
            connection=TCPSocketConnection("127.0.0.1", TARGET_PORT, send_timeout=0.2)
        ),
        post_test_case_callbacks = [post_test_case_callback],
        web_port = None
    )
    
    for i in range(0, len(msg_list)):
        s_initialize(name = f"Round-1-Orig:id{i}" )
        s_random(msg_list[i], min_length=47, max_length=47)
        session.connect(s_get(f"Round-1-Orig:id{i}"))

    # run for 60 mins, and run 10 rounds
    test_for_duration(session, DURATION_TIME)


p = execute(program_close)
close_shm(shmid)
