import os
import threading
from utils import *
from spiutils import *

''' ------------< PEACH AND TARGET CONFIGURATION >------------ '''
# ===== Network Params =====
TARGET_IP = '127.0.0.1' # local/remote machine
TARGET_PORT = 5300
# ===== Target Params =====
PROTOCOL = "dns"
WORK_DIR = "~/wingfuzz"
BINARY = "dnsmasq_2.71"
SUM_BITMAP = b''
# ===== Peach Params =====
PITS_DIR = '/home/dez/wingfuzz/dns/conf'
# Running PIT files using the peach binary 
BIN = '~/peach-3.1.124/peach'
'''----------------------------------------------------------- '''

files_run = []

def run_peach():
    flist = os.listdir(PITS_DIR)
    for file in sorted(flist):
        name = file.split('.')
        if file.endswith(".xml"):
            newfile = PITS_DIR + '/' + file
            print(f"[INFO] Fuzzing {TARGET_IP}:{TARGET_PORT} Using {file}")
            files_run.append(name[0])
            os.system(f'{BIN} {newfile} >peach_log 2>&1')


# Peach-nowing, just blackbox fuzzing
if __name__ == "__main__":
    print("========================== [PEACH MANUAL] ==========================")
    os.system(f'{BIN} -h')
    # Create SHM to record Coverage
    shmid = open_shm()
    program_close = f"sudo pkill -9 -f /repo/{BINARY}"
    program_boot = f"sudo __AFL_SHM_ID={str(shmid)} {WORK_DIR}/{PROTOCOL}/repo/{BINARY} -p 5300 &"
    p = execute(program_boot)
    time.sleep(1)

    print(f'[INFO] __AFL_SHM_ID={str(shmid)}')

    client_handler = threading.Thread(target=run_peach(), args=())
    client_handler.start()

    try:
        while True:
            bitmap = get_bitmap(shmid)
            clean_shm(shmid)

            if SUM_BITMAP == b'':
                SUM_BITMAP = bitmap
            else:
                record_path = './record.txt'
                SUM_BITMAP = update_sum_bitmap(bitmap, SUM_BITMAP, record_path)
    finally:
        p = execute(program_close)
        close_shm(shmid)