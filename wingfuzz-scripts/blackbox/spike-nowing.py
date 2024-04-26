import os
import getopt
import threading
from utils import *
from spiutils import *

''' ------------< SPIKE AND TARGET CONFIGURATION >------------ '''
# ===== Network Params =====
TARGET_IP = '127.0.0.1' # local/remote machine
TARGET_PORT = 5060
# ===== Target Params =====
PROTOCOL = "sip"
WORK_DIR = "~/wingfuzz"
BINARY = "opensips_3.1.6"
SUM_BITMAP = b''
# ===== Spike Params =====
#exclude = ['TRUN','STATS','TIME','SRUN','HELP','EXIT','GDOG']
EXCLUDE = []
SKIPSTR = 0
SKIPVAR = 0
SPKS_DIR = '/home/dez/wingfuzz/sip/conf'
TCP_OR_UDP = 0  # TCP = 1; UDP = 0; Configure it
UDP_TOTAL_SEND = 100000000    # UDP send number of cases
# Running spike scripts using the TCP/UDP script interpreter 
# spike-fuzzer-generic-send_tcp / spike-fuzzer-generic-send_udp
# BIN = '~/Spike-Fuzzer/usr/bin/spike-fuzzer-generic-send_tcp'
BIN = '~/Spike-Fuzzer/usr/bin/spike-fuzzer-generic-send_udp'
'''----------------------------------------------------------- '''

files_run = []

def run_spike():
    #if there are no excluded spikes, grab all spk files in the provided spks_dir and run spike
    if len(EXCLUDE) == 0:
        flist = os.listdir(SPKS_DIR)
        for file in sorted(flist):
            name = file.split('.')
            if file.endswith(".spk"):
                newfile = SPKS_DIR + '/' + file
                print(f"[INFO] Fuzzing {TARGET_IP}:{TARGET_PORT} Using {file}")
                files_run.append(name[0])
                if TCP_OR_UDP == 1:
                    os.system(f'{BIN} {TARGET_IP} {TARGET_PORT} {newfile} {SKIPSTR} {SKIPVAR} >log 2>&1')
                else: 
                    os.system(f'{BIN} {TARGET_IP} {TARGET_PORT} {newfile} {SKIPSTR} {SKIPVAR} {UDP_TOTAL_SEND} >log 2>&1')

    # if there are exclusions, grab all spk files that dont contain the exclusion and run spike
    else:
        flist = os.listdir(SPKS_DIR)
        for file in sorted(flist):
            name = file.split('.')
            if file.endswith(".spk") and name[0] not in EXCLUDE:
                newfile = SPKS_DIR + '/' + file
                print(f"[INFO] Fuzzing {TARGET_IP}:{TARGET_PORT} Using {file}")
                files_run.append(name[0])
                if TCP_OR_UDP == 1:
                    os.system(f'{BIN} {TARGET_IP} {TARGET_PORT} {newfile} {SKIPSTR} {SKIPVAR} >log 2>&1')
                else: 
                    os.system(f'{BIN} {TARGET_IP} {TARGET_PORT} {newfile} {SKIPSTR} {SKIPVAR} {UDP_TOTAL_SEND} >log 2>&1')


def spike_cmd_boot():
    global TARGET_IP, TARGET_PORT, SPKS_DIR
    
    if not len (sys.argv[1:]):
        usage()

    try:
        opts,args= getopt.getopt(sys.argv[1:],"hl:t:d:e:b", ["help","local","target","dir","exclude","bad"])
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for o,a in opts:
        if o in ("-h","--help"):
            usage()
        elif o in ("-t","--local"):
            try:
                d = a.split(':')
                TARGET_IP = d[0]
                TARGET_PORT = int(d[1])
            except:
                usage()
                sys.exit(0)
        elif o in ("-d","--dir"):
            try:
                SPKS_DIR = a
            except:
                usage()
                sys.exit(0)
        elif o in ("-e", "--exclude"):
            if ',' in a:
                ex = a.split(',')
                for e in ex:
                    EXCLUDE.append(e)
            else:
                EXCLUDE.append(a)

    print("\n[INFO] Starting Spike-Nowing")


# Spike-nowing, just blackbox fuzzing
if __name__ == "__main__":
    
    spike_cmd_boot()

    # Create SHM to record Coverage
    shmid = open_shm()
    program_close = f"sudo pkill -9 -f /repo/{BINARY}"
    program_boot = f"sudo __AFL_SHM_ID={str(shmid)} {WORK_DIR}/{PROTOCOL}/repo/{BINARY} &"
    p = execute(program_boot)
    time.sleep(1)

    print(f'[INFO] __AFL_SHM_ID={str(shmid)}')

    client_handler = threading.Thread(target=run_spike(), args=())
    client_handler.start()

    # heart_beat = threading.Thread(target=heartbeat(TARGET_IP, TARGET_PORT), args=())
    # heart_beat.start()

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