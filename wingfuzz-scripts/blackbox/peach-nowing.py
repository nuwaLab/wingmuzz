import os
import sys
import errno
import getopt
import socket
import threading
from utils import *
from spiutils import *

''' ------------< PEACH AND TARGET CONFIGURATION >------------ '''
# ===== Network Params =====
TARGET_IP = '0.0.0.0' # local/remote machine
TARGET_PORT = 123
# ===== Target Params =====
PROTOCOL = "ntp"
WORK_DIR = "~/wingfuzz"
BINARY = "ntpd_4.2.8p10"
SUM_BITMAP = b''
# ===== Peach Params =====
#exclude = ['TRUN','STATS','TIME','SRUN','HELP','EXIT','GDOG']
EXCLUDE = []
SKIPSTR = 0
SKIPVAR = 0
PITS_DIR = '/home/dez/wingfuzz/ntp/conf'
# Running PIT files using the peach binary 
BIN = '~/peach-3.1.124/peach'
'''----------------------------------------------------------- '''

files_run = []

def run_spike():
    #if there are no excluded spikes, grab all spk files in the provided spks_dir and run spike
    if len(EXCLUDE) == 0:
        flist = os.listdir(PITS_DIR)
        for file in sorted(flist):
            name = file.split('.')
            if file.endswith(".spk"):
                newfile = PITS_DIR + '/' + file
                print(f"[INFO] Fuzzing {TARGET_IP}:{TARGET_PORT} Using {file}")
                files_run.append(name[0])
                os.system(f'{BIN} {TARGET_IP} {TARGET_PORT} {newfile} {SKIPSTR} {SKIPVAR} >log 2>&1')

    # if there are exclusions, grab all spk files that dont contain the exclusion and run spike
    else:
        flist = os.listdir(PITS_DIR)
        for file in sorted(flist):
            name = file.split('.')
            if file.endswith(".spk") and name[0] not in EXCLUDE:
                newfile = PITS_DIR + '/' + file
                print(f"[INFO] Fuzzing {TARGET_IP}:{TARGET_PORT} Using {file}")
                files_run.append(name[0])
                os.system(f'{BIN} {TARGET_IP} {TARGET_PORT} {newfile} {SKIPSTR} {SKIPVAR} >log 2>&1')



# Peach-nowing, just blackbox fuzzing
if __name__ == "__main__":
    print("========================== [PEACH MANUAL] ==========================")
    os.system(f'{BIN} -h')
    # Create SHM to record Coverage
    shmid = open_shm()
    program_close = f"sudo pkill -9 -f /repo/{BINARY}"
    program_boot = f"sudo __AFL_SHM_ID={str(shmid)} {WORK_DIR}/{PROTOCOL}/repo/{BINARY} &"
    p = execute(program_boot)
    time.sleep(1)

    print(f'[INFO] __AFL_SHM_ID={str(shmid)}')

    client_handler = threading.Thread(target=run_spike(), args=())
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