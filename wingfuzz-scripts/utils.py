import os
import sys
import time
import subprocess
import socket

''' 
    utils.py file defines two main classes. 
'''
class wingman:
    
    name = ""
    boot = ""
    close = ""
    afl = ""
    
    cur_cali_res_list = [] # 协作列表
    cur_distance = 0
    
    def __init__(self):
        self.name = ""
        self.boot = ""
        self.close = ""
        self.afl = ""
        self.cur_cali_res_list = []
        self.cur_distance = 0
        
    # 必须初始化 name boot close afl
    def isInited(self):
        if self.name != "" and self.boot != "" and self.close != "" and self.afl != "":
            return True
        return False
    
    def display_cur_res(self):
        if self.cur_cali_res_list == []:
            print(f"Please Test {self.name} First ---")
            return 0
        print("==== Wingman ====")
        print(f"Current Calibrite Responses: ")
        for res in self.cur_cali_res_list:
            print(f"{res}")
        print("=================")
        return 0
        
    
    def display(self):
        if self.isInited():
            print(f"Please Init {self.name} First ---")
            return 0
        print("==== Wingman ====")
        print(f"Name: {self.name}")
        print(f"Boot: {self.boot}")
        print(f"Close: {self.close}")
        print(f"AFLNET_Command: {self.afl}")
        print("=================")
        return 0
        
        
    def start(self):
        try:
            subprocess.check_call(self.boot, shell=True)  # boot 其实就是启动命令
            print(f"{self.name} start ---")
        except subprocess.CalledProcessError as e:
            print(f"{self.name} boot error : {e}")
    
    # stop the protocol server
    def shutdown(self):
        try:
            subprocess.check_call(self.close, shell=True)
            print(f"{self.name} close ---")
        except subprocess.CalledProcessError as e:
            print(f"{self.name} close msg : {e}")
            
# message sequence? actually seed corpus?
class msg_sq:

    msg = b""
    response_list = []
    target_name = ""
    
    
    def __init__(self):
        self.msg = b""
        response_list = []
        target_name = ""
        
    def isInited(self):
        if self.msg != b"":
            return True
        return False
    
    def display_response(self, target_name):
        # if self.target_name == "" or response_list == []:
        if self.target_name == "" or self.response_list == []:
            print(f"Please Send The Message First ---")
            return 0
        print("==== Response ====")
        print(f"Current Target Name: {target_name}")
        print("Response:")
        for res in self.response_list:
            print(f"{res}")
        print("=================")
        #return 0
    
    def display(self):
        if not self.isInited():
            print(f"Please Init The Message First ---")
            return 0
        print("==== Message ====")
        print("Content:")
        print(f"{self.msg}")
        print("=================")
        #return 0
    
    # 
    def send(self, target_info, target_name, timeout=0.2):
        info, ip, port = target_info
        response_list = []
        
        self.target_name = target_name
        
        if info == "udp" or info == "UDP":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                try:
                    s.settimeout(timeout)
                    msg_list = self.msg.split(b"\r\n")
                    for msg in msg_list:
                        s.sendto(msg, (ip, port))
                        data, server = s.recvfrom(1024)
                        response_list.append(data)
                except socket.error as e:
                    data = b"timeout"
                    response_list.append(data)
        elif info == "tcp" or info == "TCP":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.settimeout(timeout)
                    # s.connect((host, port))
                    s.connect((ip, port))
                    msg_list = self.msg.split(b"\r\n")
                    for msg in msg_list:
                        s.sendall(msg)
                        data = s.recv(1024)
                        response_list.append(data)
                except socket.error as e:
                    data = b"timeout"
                    response_list.append(data)
        else:
            print(f"Message Info Error - {info}")
            sys.exit(0)
        
        self.response_list = response_list
        
        response = b""
        
        if len(response_list) > 1:
            response = b"|".join(response_list)
        else:
            response = response_list[0]
        
        #for res in response_list:
        #    response = response + res + b"|"
        
        return response
    
