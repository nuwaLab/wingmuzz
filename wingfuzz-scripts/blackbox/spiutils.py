import sys

def usage():
    print("Spike Fuzzing Proxy \nUsage: spike-proxy.py -l proxy_ip:port -t target_ip:port -d spikefiles_directory -e excludes \n\
    -l --local               -Set up local proxy on this ip:port \n\
    -t --target              -Target computer:port to fuzz \n\
    -d --dir                 -Directory where spike files reside \n\
    -e --exclude             -File names to exclude - common seperated \n\
    -h --help                -Help \nExamples: \n\
    spikeproxy.py -l 127.0.0.1:9999 -t 192.168.1.105:9999 -d /root/Downloads/spike -e TRUN.spk,GMON.spk \n\
    spikeproxy.py -h")
    sys.exit(0)

