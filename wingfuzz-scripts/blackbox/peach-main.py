import os
import gc
import errno
import socket
import threading
from utils import *
from peautils import *

''' ------------< PEACH AND TARGET CONFIGURATION >------------ '''
# ===== Network Params =====
PROXY_IP = '127.0.0.1'
PROXY_PORT = 12345
TARGET_IP = '127.0.0.1' # local/remote machine
TARGET_PORT = 5300
# ===== Target Params =====
PROTOCOL = "dns"
WORK_DIR = "~/wingfuzz"
BINARY = "dnsmasq_2.71"
SUM_BITMAP = b''
IN_DIR = f"../../{PROTOCOL}/in/"
# ===== Peach Params =====
PITS_DIR = '~/wingfuzz/dns/conf'
DURATION_TIME = 3600
# Running PIT files using the peach binary 
BIN = '~/peach-3.1.124/peach'
'''----------------------------------------------------------- '''

files_run = []
msg_list = read_peach_indir(IN_DIR)


def handle_greybox_connection(msg_list):
    global SUM_BITMAP

    for i in range(0, len(msg_list)):
        request = msg_list[i]
        peachGreyCaseSend(BIN, request)

        bitmap = get_bitmap(shmid)
        clean_shm(shmid)
        if SUM_BITMAP == b'':
            SUM_BITMAP = bitmap
        else:
            record_path = './record.txt'
            SUM_BITMAP = update_sum_bitmap(bitmap, SUM_BITMAP, record_path)


def run_peach():
    flist = os.listdir(PITS_DIR)
    for file in sorted(flist):
        name = file.split('.')
        if file.endswith(".xml"):
            newfile = PITS_DIR + '/' + file
            print(f"[INFO] Fuzzing {TARGET_IP}:{TARGET_PORT} Using {file}")
            files_run.append(name[0])
            os.system(f'{BIN} {newfile} >peach_log 2>&1')


def cov_log_duration(duration):
    global SUM_BITMAP

    start_time = time.time()

    if len(msg_list) != 0:
        handle_greybox_connection(msg_list)

    while time.time() - start_time < duration:
        bitmap = get_bitmap(shmid)
        clean_shm(shmid)

        if SUM_BITMAP == b'':
            SUM_BITMAP = bitmap
        else:
            record_path = './record.txt'
            SUM_BITMAP = update_sum_bitmap(bitmap, SUM_BITMAP, record_path)


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


if __name__ == "__main__":
    print("========================== [PEACH MANUAL] ==========================")
    os.system(f'{BIN} -h')
    # Create SHM to record Coverage
    shmid = open_shm()
    program_close = f"sudo pkill -9 -f /repo/{BINARY}"
    program_boot = f"sudo __AFL_SHM_ID={str(shmid)} {WORK_DIR}/{PROTOCOL}/repo/{BINARY} -p 5300 &"
    p = execute(program_boot)
    time.sleep(1)

    # Create Proxy Binding
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((PROXY_IP, PROXY_PORT))
        server.listen(5)
        print(f'[INFO] __AFL_SHM_ID={str(shmid)}')
        print(f'[INFO] Spike Proxy Listening on {PROXY_IP}:{PROXY_PORT}')

        for idx in range(0, 10):
            # Prevent OOM
            gc.collect()

            cov_log_duration(DURATION_TIME)

            conn, addr = server.accept()
            with conn:
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
            
            msg_list = read_peach_indir(IN_DIR)
    
    p = execute(program_close)
    close_shm(shmid)